#pragma once

#include "Executor/Executor.hpp"
#include "Input/RawInput.hpp"
#include "OS/IPC.hpp"
#include "OS/Process.hpp"

#include "Config.h"

#include <cstring>
#include <stdexcept>

namespace FFF {

struct InMemoryExternalExecutor : public Executor {

  InMemoryExternalExecutor(HarnessFunctionType func) {
    harness = func;
    shared_input = (uint8_t*)createAnonSharedMem(max_file_size);
  }

  virtual void start() {}

  void runTarget() {
    int status = 0;
    if (auto raw = dynamic_cast<RawInput*>(current_input)) {
      runTargetAux(raw->getBytes());
    } else {
      Bytes bytes = current_input->serialize();
      runTargetAux(bytes);
    }
  }

protected:
  void runTargetAux(const Bytes& bytes) {
    memcpy(shared_input, bytes.data(), bytes.size());
    child.resume();
    ExitType e = child.wait(true);
    switch(e) {
      case ExitType::STOP:
        return;
      case ExitType::NORMAL:
        break;
      default:
        dumpCrashToFile(e, bytes);
    }
    start();
  }
  
  void childRun() {
    Process* cur = Process::current();
    int status = 0;
    while (true) {
      cur->suspend();
      harness(shared_input, shared_input_size);
    }
  }

  Process child;
  HarnessFunctionType harness;
  uint8_t* shared_input;
  size_t shared_input_size;

};

struct InMemoryForkExecutor : public InMemoryExternalExecutor {

  InMemoryForkExecutor(HarnessFunctionType func) : InMemoryExternalExecutor(func) {
    start();
  }

  void start() {
    switch (child.fork()) {
      case ForkResult::FAILED:
        throw std::runtime_error("fork() failed");
      case ForkResult::CHILD:
        childRun();
      case ForkResult::PARENT:
        return;
    }
  }

};

}
