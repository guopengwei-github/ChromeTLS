#include "thread_local_storage.h"

#include <atomic>
#include <mutex>

#include <atltrace.h>

#ifdef _WIN64

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:p_thread_callback_base")

#else  // _WIN64

#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_p_thread_callback_base")

#endif  // _WIN64

// Static callback function to call with each thread termination.
void NTAPI OnThreadExit(PVOID module, DWORD reason, PVOID reserved) {
  // On XP SP0 & SP1, the DLL_PROCESS_ATTACH is never seen. It is sent on SP2+
  // and on W2K and W2K3. So don't assume it is sent.
  if (DLL_THREAD_DETACH == reason || DLL_PROCESS_DETACH == reason)
    PlatformThreadLocalStorage::OnThreadExit();
}

// .CRT$XLA to .CRT$XLZ is an array of PIMAGE_TLS_CALLBACK pointers that are
// called automatically by the OS loader code (not the CRT) when the module is
// loaded and on thread creation. They are NOT called if the module has been
// loaded by a LoadLibrary() call. It must have implicitly been loaded at
// process startup.
// By implicitly loaded, I mean that it is directly referenced by the main EXE
// or by one of its dependent DLLs. Delay-loaded DLL doesn't count as being
// implicitly loaded.
//
// See VC\crt\src\tlssup.c for reference.

// extern "C" suppresses C++ name mangling so we know the symbol name for the
// linker /INCLUDE:symbol pragma above.
extern "C" {
// The linker must not discard p_thread_callback_base.  (We force a reference
// to this variable with a linker /INCLUDE:symbol pragma to ensure that.) If
// this variable is discarded, the OnThreadExit function will never be called.
#ifdef _WIN64

// .CRT section is merged with .rdata on x64 so it must be constant data.
#pragma const_seg(".CRT$XLB")
// When defining a const variable, it must have external linkage to be sure the
// linker doesn't discard it.
extern const PIMAGE_TLS_CALLBACK p_thread_callback_base;
const PIMAGE_TLS_CALLBACK p_thread_callback_base = OnThreadExit;

// Reset the default section.
#pragma const_seg()

#else  // _WIN64

#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback_base = OnThreadExit;

// Reset the default section.
#pragma data_seg()

#endif  // _WIN64

}  // extern "C"


bool PlatformThreadLocalStorage::AllocTLS(TLSKey* key) {
  TLSKey value = TlsAlloc();
  if (value != TLS_OUT_OF_INDEXES) {
    *key = value;
    return true;
  }

  return false;
}

void PlatformThreadLocalStorage::FreeTLS(TLSKey key) {
  TlsFree(key);
}

void PlatformThreadLocalStorage::SetTLSValue(TLSKey key, void* value) {
  TlsSetValue(key, value);
}

void* PlatformThreadLocalStorage::GetTLSValue(TLSKey key) {
  return TlsGetValue(key);
}

namespace {
std::atomic<PlatformThreadLocalStorage::TLSKey> g_native_tls_key{
    PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES};

enum class TlsVectorState {
  kUninitialized = 0,

  // In the process of destroying the entries in the vector.
  kDestroying,

  // All of the entries and the vector has been destroyed.
  kDestroyed,

  // The vector has been initialized and is in use.
  kInUse,

  kMaxValue = kInUse
};

// Bit-mask used to store TlsVectorState.
constexpr uintptr_t kVectorStateBitMask = 3;
static_assert(static_cast<int>(TlsVectorState::kMaxValue) <=
                  kVectorStateBitMask,
              "number of states must fit in header");
static_assert(static_cast<int>(TlsVectorState::kUninitialized) == 0,
              "kUninitialized must be null");

// The maximum number of slots in our thread local storage stack.
constexpr int kThreadLocalStorageSize = 256;

enum TlsStatus {
  FREE,
  IN_USE,
};

struct TlsMetadata {
  TlsStatus status;
  ThreadLocalStorage::TLSDestructorFunc destructor;
  // Incremented every time a slot is reused. Used to detect reuse of slots.
  uint32_t version;
};

struct TlsVectorEntry {
  // `data` is not a raw_ptr<...> for performance reasons (based on analysis of
  // sampling profiler data and tab_search:top100:2020).
  void* data;

  uint32_t version;
};

// This lock isn't needed until after we've constructed the per-thread TLS
// vector, so it's safe to use.
std::mutex* GetTLSMetadataLock() {
  static auto* lock = new std::mutex();
  return lock;
}
TlsMetadata g_tls_metadata[kThreadLocalStorageSize];
size_t g_last_assigned_slot = 0;

// The maximum number of times to try to clear slots by calling destructors.
// Use pthread naming convention for clarity.
constexpr int kMaxDestructorIterations = kThreadLocalStorageSize;

void SetTlsVectorValue(PlatformThreadLocalStorage::TLSKey key,
                       TlsVectorEntry* tls_data,
                       TlsVectorState state) {
  // DCHECK(tls_data || (state == TlsVectorState::kUninitialized) ||
  //       (state == TlsVectorState::kDestroyed));
  PlatformThreadLocalStorage::SetTLSValue(
      key, reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(tls_data) |
                                   static_cast<uintptr_t>(state)));
}

// Returns the tls vector and current state from the raw tls value.
TlsVectorState GetTlsVectorStateAndValue(void* tls_value,
                                         TlsVectorEntry** entry = nullptr) {
  if (entry) {
    *entry = reinterpret_cast<TlsVectorEntry*>(
        reinterpret_cast<uintptr_t>(tls_value) & ~kVectorStateBitMask);
  }
  return static_cast<TlsVectorState>(reinterpret_cast<uintptr_t>(tls_value) &
                                     kVectorStateBitMask);
}

// Returns the tls vector and state using the tls key.
TlsVectorState GetTlsVectorStateAndValue(PlatformThreadLocalStorage::TLSKey key,
                                         TlsVectorEntry** entry = nullptr) {
  return GetTlsVectorStateAndValue(PlatformThreadLocalStorage::GetTLSValue(key),
                                   entry);
}

// This function is called to initialize our entire Chromium TLS system.
// It may be called very early, and we need to complete most all of the setup
// (initialization) before calling *any* memory allocator functions, which may
// recursively depend on this initialization.
// As a result, we use Atomics, and avoid anything (like a singleton) that might
// require memory allocations.
TlsVectorEntry* ConstructTlsVector() {
  PlatformThreadLocalStorage::TLSKey key =
      g_native_tls_key.load(std::memory_order_relaxed);
  if (key == PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES) {
    PlatformThreadLocalStorage::AllocTLS(&key);

    // The TLS_KEY_OUT_OF_INDEXES is used to find out whether the key is set or
    // not in NoBarrier_CompareAndSwap, but Posix doesn't have invalid key, we
    // define an almost impossible value be it.
    // If we really get TLS_KEY_OUT_OF_INDEXES as value of key, just alloc
    // another TLS slot.
    if (key == PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES) {
      PlatformThreadLocalStorage::TLSKey tmp = key;
      (PlatformThreadLocalStorage::AllocTLS(&key) &&
       key != PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES);
      PlatformThreadLocalStorage::FreeTLS(tmp);
    }
    // Atomically test-and-set the tls_key. If the key is
    // TLS_KEY_OUT_OF_INDEXES, go ahead and set it. Otherwise, do nothing, as
    // another thread already did our dirty work.
    PlatformThreadLocalStorage::TLSKey old_key =
        PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES;
    if (!g_native_tls_key.compare_exchange_strong(old_key, key,
                                                  std::memory_order_relaxed,
                                                  std::memory_order_relaxed)) {
      // We've been shortcut. Another thread replaced g_native_tls_key first so
      // we need to destroy our index and use the one the other thread got
      // first.
      PlatformThreadLocalStorage::FreeTLS(key);
      key = g_native_tls_key.load(std::memory_order_relaxed);
    }
  }
  (GetTlsVectorStateAndValue(key), TlsVectorState::kUninitialized);

  // Some allocators, such as TCMalloc, make use of thread local storage. As a
  // result, any attempt to call new (or malloc) will lazily cause such a system
  // to initialize, which will include registering for a TLS key. If we are not
  // careful here, then that request to create a key will call new back, and
  // we'll have an infinite loop. We avoid that as follows: Use a stack
  // allocated vector, so that we don't have dependence on our allocator until
  // our service is in place. (i.e., don't even call new until after we're
  // setup)
  TlsVectorEntry stack_allocated_tls_data[kThreadLocalStorageSize];
  memset(stack_allocated_tls_data, 0, sizeof(stack_allocated_tls_data));
  // Ensure that any rentrant calls change the temp version.
  SetTlsVectorValue(key, stack_allocated_tls_data, TlsVectorState::kInUse);

  // Allocate an array to store our data.
  TlsVectorEntry* tls_data = new TlsVectorEntry[kThreadLocalStorageSize];
  memcpy(tls_data, stack_allocated_tls_data, sizeof(stack_allocated_tls_data));
  SetTlsVectorValue(key, tls_data, TlsVectorState::kInUse);
  return tls_data;
}

void OnThreadExitInternal(TlsVectorEntry* tls_data) {
  // Some allocators, such as TCMalloc, use TLS. As a result, when a thread
  // terminates, one of the destructor calls we make may be to shut down an
  // allocator. We have to be careful that after we've shutdown all of the known
  // destructors (perchance including an allocator), that we don't call the
  // allocator and cause it to resurrect itself (with no possibly destructor
  // call to follow). We handle this problem as follows: Switch to using a stack
  // allocated vector, so that we don't have dependence on our allocator after
  // we have called all g_tls_metadata destructors. (i.e., don't even call
  // delete[] after we're done with destructors.)
  TlsVectorEntry stack_allocated_tls_data[kThreadLocalStorageSize];
  memcpy(stack_allocated_tls_data, tls_data, sizeof(stack_allocated_tls_data));
  // Ensure that any re-entrant calls change the temp version.
  PlatformThreadLocalStorage::TLSKey key =
      g_native_tls_key.load(std::memory_order_relaxed);
  SetTlsVectorValue(key, stack_allocated_tls_data, TlsVectorState::kDestroying);
  delete[] tls_data;  // Our last dependence on an allocator.

  // Snapshot the TLS Metadata so we don't have to lock on every access.
  TlsMetadata tls_metadata[kThreadLocalStorageSize];
  {
    std::unique_lock<std::mutex> auto_lock(*GetTLSMetadataLock());
    memcpy(tls_metadata, g_tls_metadata, sizeof(g_tls_metadata));
  }

  int remaining_attempts = kMaxDestructorIterations;
  bool need_to_scan_destructors = true;
  while (need_to_scan_destructors) {
    need_to_scan_destructors = false;
    // Try to destroy the first-created-slot (which is slot 1) in our last
    // destructor call. That user was able to function, and define a slot with
    // no other services running, so perhaps it is a basic service (like an
    // allocator) and should also be destroyed last. If we get the order wrong,
    // then we'll iterate several more times, so it is really not that critical
    // (but it might help).
    for (int slot = 0; slot < kThreadLocalStorageSize; ++slot) {
      void* tls_value = stack_allocated_tls_data[slot].data;
      if (!tls_value || tls_metadata[slot].status == TlsStatus::FREE ||
          stack_allocated_tls_data[slot].version != tls_metadata[slot].version)
        continue;

      ThreadLocalStorage::TLSDestructorFunc destructor =
          tls_metadata[slot].destructor;
      if (!destructor)
        continue;
      stack_allocated_tls_data[slot].data = nullptr;  // pre-clear the slot.
      destructor(tls_value);
      // Any destructor might have called a different service, which then set a
      // different slot to a non-null value. Hence we need to check the whole
      // vector again. This is a pthread standard.
      need_to_scan_destructors = true;
    }
    if (--remaining_attempts <= 0) {
      break;
    }
  }

  // Remove our stack allocated vector.
  SetTlsVectorValue(key, nullptr, TlsVectorState::kDestroyed);
}

}  // namespace

void PlatformThreadLocalStorage::OnThreadExit() {
  PlatformThreadLocalStorage::TLSKey key =
      g_native_tls_key.load(std::memory_order_relaxed);
  if (key == PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES)
    return;
  TlsVectorEntry* tls_vector = nullptr;
  const TlsVectorState state = GetTlsVectorStateAndValue(key, &tls_vector);

  // On Windows, thread destruction callbacks are only invoked once per module,
  // so there should be no way that this could be invoked twice.
  // DCHECK_NE(state, TlsVectorState::kDestroyed);

  // Maybe we have never initialized TLS for this thread.
  if (state == TlsVectorState::kUninitialized)
    return;
  OnThreadExitInternal(tls_vector);
}

// static
bool ThreadLocalStorage::HasBeenDestroyed() {
  PlatformThreadLocalStorage::TLSKey key =
      g_native_tls_key.load(std::memory_order_relaxed);
  if (key == PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES)
    return false;
  const TlsVectorState state = GetTlsVectorStateAndValue(key);
  return state == TlsVectorState::kDestroying ||
         state == TlsVectorState::kDestroyed;
}

void ThreadLocalStorage::Slot::Initialize(TLSDestructorFunc destructor) {
  PlatformThreadLocalStorage::TLSKey key =
      g_native_tls_key.load(std::memory_order_relaxed);
  if (key == PlatformThreadLocalStorage::TLS_KEY_OUT_OF_INDEXES ||
      GetTlsVectorStateAndValue(key) == TlsVectorState::kUninitialized) {
    ConstructTlsVector();
  }

  // Grab a new slot.
  {
    std::unique_lock<std::mutex> auto_lock(*GetTLSMetadataLock());
    for (int i = 0; i < kThreadLocalStorageSize; ++i) {
      // Tracking the last assigned slot is an attempt to find the next
      // available slot within one iteration. Under normal usage, slots remain
      // in use for the lifetime of the process (otherwise before we reclaimed
      // slots, we would have run out of slots). This makes it highly likely the
      // next slot is going to be a free slot.
      size_t slot_candidate =
          (g_last_assigned_slot + 1 + i) % kThreadLocalStorageSize;
      if (g_tls_metadata[slot_candidate].status == TlsStatus::FREE) {
        g_tls_metadata[slot_candidate].status = TlsStatus::IN_USE;
        g_tls_metadata[slot_candidate].destructor = destructor;
        g_last_assigned_slot = slot_candidate;
        // DCHECK_EQ(kInvalidSlotValue, slot_);
        slot_ = slot_candidate;
        version_ = g_tls_metadata[slot_candidate].version;
        break;
      }
    }
  }
  // CHECK_NE(slot_, kInvalidSlotValue);
  // CHECK_LT(slot_, kThreadLocalStorageSize);
}

void ThreadLocalStorage::Slot::Free() {
  // DCHECK_NE(slot_, kInvalidSlotValue);
  // DCHECK_LT(slot_, kThreadLocalStorageSize);
  {
    std::unique_lock<std::mutex> auto_lock(*GetTLSMetadataLock());
    g_tls_metadata[slot_].status = TlsStatus::FREE;
    g_tls_metadata[slot_].destructor = nullptr;
    ++(g_tls_metadata[slot_].version);
  }
  slot_ = kInvalidSlotValue;
}

void* ThreadLocalStorage::Slot::Get() const {
  TlsVectorEntry* tls_data = nullptr;
  const TlsVectorState state = GetTlsVectorStateAndValue(
      g_native_tls_key.load(std::memory_order_relaxed), &tls_data);
  // DCHECK_NE(state, TlsVectorState::kDestroyed);
  if (!tls_data)
    return nullptr;
  // DCHECK_NE(slot_, kInvalidSlotValue);
  // DCHECK_LT(slot_, kThreadLocalStorageSize);
  // Version mismatches means this slot was previously freed.
  if (tls_data[slot_].version != version_)
    return nullptr;
  return tls_data[slot_].data;
}

void ThreadLocalStorage::Slot::Set(void* value) {
  TlsVectorEntry* tls_data = nullptr;
  const TlsVectorState state = GetTlsVectorStateAndValue(
      g_native_tls_key.load(std::memory_order_relaxed), &tls_data);
  // DCHECK_NE(state, TlsVectorState::kDestroyed);
  if (!tls_data) {
    if (!value)
      return;
    tls_data = ConstructTlsVector();
  }
  // DCHECK_NE(slot_, kInvalidSlotValue);
  // DCHECK_LT(slot_, kThreadLocalStorageSize);
  tls_data[slot_].data = value;
  tls_data[slot_].version = version_;
}

ThreadLocalStorage::Slot::Slot(TLSDestructorFunc destructor) {
  Initialize(destructor);
}

ThreadLocalStorage::Slot::~Slot() {
  Free();
}
