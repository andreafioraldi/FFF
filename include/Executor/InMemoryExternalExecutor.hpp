#pragma once

#include "Executor/Executor.hpp"
#include "Input/RawInput.hpp"
#include "OS/IPC.hpp"
#include "OS/Crash.hpp"
#include "OS/Process.hpp"

#include "Config.h"

#include "Logger.hpp"

#include <cstring>
#include <stdexcept>

namespace FFF {

struct InMemoryExternalExecutor : public Executor {

  static InMemoryExternalExecutor* current_executor;

  InMemoryExternalExecutor(HarnessFunctionType func) : seq(4) {
    harness = func;
    shared_input = (uint8_t*)createAnonSharedMem(max_file_size);
  }

  virtual void start() {}

  void runTarget() {
    if (auto raw = dynamic_cast<RawInput*>(current_input)) {
      runTargetAux(raw->getBytes());
    } else {
      Bytes bytes = current_input->serialize();
      runTargetAux(bytes);
    }
  }
  
  void writeSharedExitType(ExitType exit_type) {
    ;
  }

protected:
  void runTargetAux(const Bytes& bytes) {
    ExitType status = ExitType::NORMAL;
    memcpy(shared_input, bytes.data(), bytes.size());
    seq.wait(0);
    seq.wait(3);
    if (status == ExitType::NORMAL)
      return;
    child.wait();
    dumpCrashToFile(status, bytes);
    start();
  }
  
  void childRun() {
    current_executor = this;
    installCrashHandlers(&fillSharedCrashReport);
    ExitType status = ExitType::NORMAL;
    while (true) {
      seq.wait(1);
      harness(shared_input, shared_input_size);
      seq.wait(2);
    }
  }

  Process child;
  SharedMemSequence seq;
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
