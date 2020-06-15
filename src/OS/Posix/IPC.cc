#include "OS/IPC.hpp"

#include <unistd.h>
#include <sys/mman.h>

#include <stdexcept>

using namespace FFF;

namespace FFF {

Pipe::Pipe() {
  int* fds = new int[2];
  if (pipe(fds) < 0)
    throw std::runtime_error("pipe() failed");
  handle = (void*)fds;
}

size_t Pipe::write(const void *buf, size_t count) {
  int* fds = (int*)handle;
  return ::write(fds[1], buf, count);
}

size_t Pipe::read(void *buf, size_t count) {
  int* fds = (int*)handle;
  return ::read(fds[0], buf, count);
}

Pipe::~Pipe() {
  int* fds = (int*)handle;
  close(fds[0]);
  close(fds[1]);
  delete fds;
}

void* createAnonSharedMem(size_t size) {

  void* mem = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (!mem)
    throw std::runtime_error("createSharedMem: mmap() failed");
  return mem;

}

}
