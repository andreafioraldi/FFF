#include "OS/IPC.hpp"

#include <unistd.h>
#include <sys/mman.h>

#include <stdexcept>

using namespace FFF;

namespace FFF {

void* createAnonSharedMem(size_t size) {

  void* mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (!mem)
    throw std::runtime_error("createSharedMem: mmap() failed");
  return mem;

}

}
