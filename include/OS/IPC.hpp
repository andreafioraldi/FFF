#pragma once

#include <atomic>
#include <stdlib.h>

namespace FFF {

struct VirtualRW {

  virtual size_t write(const void *buf, size_t count) = 0;
  virtual size_t read(void *buf, size_t count) = 0;

};

struct Pipe : public VirtualRW {

  Pipe();
  virtual ~Pipe();
  
  size_t write(const void *buf, size_t count);
  size_t read(void *buf, size_t count);

protected:
  void* handle;

};

void* createAnonSharedMem(size_t size);

struct SharedMemSequence {

  SharedMemSequence(int num_sequences) {
    mem = (std::atomic<int>*)createAnonSharedMem(sizeof(int));
    *mem = 0;
    this->num_sequences = num_sequences;
  }

  void wait(int idx) {
    auto old = idx;
    auto inc = (idx+1) % num_sequences;
    while (!mem->compare_exchange_weak(old, inc))
      old = idx;
    std::atomic_thread_fence(std::memory_order_acquire);
  }

protected:
  std::atomic<int>* mem;
  int num_sequences;

};

};
