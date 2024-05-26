

#include <chrono>
#include <iostream>
#include <thread>

#include "thread_local_storage.h"

struct ThreadData {
  int counter;
};

ThreadLocalStorage::Slot tls_slot([](void* data) {
  delete static_cast<ThreadData*>(data);
});

ThreadLocalStorage::Slot tls_slot2([](void* data) {
  delete static_cast<ThreadData*>(data);
});

void IncrementCounter() {
  // 从TLS槽获取当前线程的数据
  ThreadData* data = static_cast<ThreadData*>(tls_slot.Get());
  // 如果当前线程没有数据，则初始化
  if (!data) {
    data = new ThreadData();
    data->counter = 0;
    tls_slot.Set(data);
  }

  // 增加计数器
  data->counter++;
  std::cout << "Thread " << std::this_thread::get_id()
            << " counter: " << data->counter << std::endl;

  ThreadData* data2 = static_cast<ThreadData*>(tls_slot2.Get());
  // 如果当前线程没有数据，则初始化
  if (!data2) {
    data2 = new ThreadData();
    data2->counter = 0;
    tls_slot2.Set(data2);
  }
  data2->counter++;
  std::cout << "Thread " << std::this_thread::get_id()
            << " counter2: " << data->counter << std::endl;
}

void ThreadFunction() {
  for (int i = 0; i < 5; ++i) {
    IncrementCounter();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
}

int main() {
  std::thread thread_1(ThreadFunction);

  std::thread thread_2(ThreadFunction);

  std::thread thread_3(ThreadFunction);
  thread_1.join();
  thread_2.join();
  thread_3.join();

  return 0;
}
