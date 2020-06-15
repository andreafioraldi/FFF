#pragma once

#include <atomic>

namespace FFF {

struct RWSpinlock {

  void read_lock() {
    int old, d;
    while(true) {
      old = flag.load();
      if(old >= 0) {
        d = old +1;
        if(flag.compare_exchange_weak(old, d))
          break;
      }
    }
    std::atomic_thread_fence(std::memory_order_acquire);
  }

  void read_unlock() {
    int old, d;
    while(true) {
      old = flag.load();
      if(old > 0) {
        d = old -1;
        std::atomic_thread_fence(std::memory_order_acquire);
        if(flag.compare_exchange_weak(old, d))
          break;
      }
    }
  }

  void write_lock() {
    int old, d;
    while(true) {
      old = flag.load();
      if(old == 0) {
        d = -1;
        if(flag.compare_exchange_weak(old, d))
          break;
      }
    }
    std::atomic_thread_fence(std::memory_order_acquire);
  }
  
  void write_unlock() {
    int old, d;
    while(true) {
      old = flag.load();
      if(old == -1) {
        d = 0;
        std::atomic_thread_fence(std::memory_order_acquire);
        if(flag.compare_exchange_weak(old, d))
          break;
      }
    }
  }

protected:
  std::atomic<int> flag = 0;

};

}
