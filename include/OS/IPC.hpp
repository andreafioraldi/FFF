#pragma once

#include <stdlib.h>

namespace FFF {

/*
struct VirtualRW {

  virtual size_t write(const void *buf, size_t count);
  virtual size_t read(const void *buf, size_t count);

};

struct Pipe : public VirtualRW {

  virtual void dupForTarget();
  
  virtual ~Pipe();

};
*/

void* createAnonSharedMem(size_t size);

};
