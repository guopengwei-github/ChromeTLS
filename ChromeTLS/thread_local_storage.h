#ifndef THREAD_LOCAL_STORAGE_H_
#define THREAD_LOCAL_STORAGE_H_

#include <stdint.h>

#include <Windows.h>


class PlatformThreadLocalStorage {
 public:
  typedef unsigned long TLSKey;
  enum : unsigned { TLS_KEY_OUT_OF_INDEXES = TLS_OUT_OF_INDEXES };
  static bool AllocTLS(TLSKey* key);
  static void FreeTLS(TLSKey key);

  static void SetTLSValue(TLSKey key, void* value);
  static void* GetTLSValue(TLSKey key);
  static void OnThreadExit();
};


class ThreadLocalStorage {
 public:
  typedef void (*TLSDestructorFunc)(void* value);

  // A key representing one value stored in TLS. Use as a class member or a
  // local variable. If you need a static storage duration variable, use the
  // following pattern with a NoDestructor<Slot>:
  // void MyDestructorFunc(void* value);
  // ThreadLocalStorage::Slot& ImportantContentTLS() {
  //   static NoDestructor<ThreadLocalStorage::Slot> important_content_tls(
  //       &MyDestructorFunc);
  //   return *important_content_tls;
  // }
  class Slot final {
   public:
    // |destructor| is a pointer to a function to perform per-thread cleanup of
    // this object.  If set to nullptr, no cleanup is done for this TLS slot.
    explicit Slot(TLSDestructorFunc destructor = nullptr);

    Slot(const Slot&) = delete;
    Slot& operator=(const Slot&) = delete;

    // If a destructor was set for this slot, removes the destructor so that
    // remaining threads exiting will not free data.
    ~Slot();

    // Get the thread-local value stored in slot 'slot'.
    // Values are guaranteed to initially be zero.
    void* Get() const;

    // Set the thread-local value stored in slot 'slot' to
    // value 'value'.
    void Set(void* value);

   private:
    void Initialize(TLSDestructorFunc destructor);
    void Free();

    static constexpr int kInvalidSlotValue = -1;
    int slot_ = kInvalidSlotValue;
    uint32_t version_ = 0;
  };

  ThreadLocalStorage(const ThreadLocalStorage&) = delete;
  ThreadLocalStorage& operator=(const ThreadLocalStorage&) = delete;

 private:
  // In most cases, most callers should not need access to HasBeenDestroyed().
  // If you are working in code that runs during thread destruction, contact the
  // base OWNERs for advice and then make a friend request.
  //
  // Returns |true| if Chrome's implementation of TLS is being or has been
  // destroyed during thread destruction. Attempting to call Slot::Get() during
  // destruction is disallowed and will hit a DCHECK. Any code that relies on
  // TLS during thread destruction must first check this method before calling
  // Slot::Get().
  static bool HasBeenDestroyed();
};

#endif  // !THREAD_LOCAL_STORAGE_H_