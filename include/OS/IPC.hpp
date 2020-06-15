#pragma once

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

};
