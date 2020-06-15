#pragma once

#include "Executor/Executor.hpp"
#include "Input/RawInput.hpp"

namespace FFF {

struct InMemoryExecutor;
extern InMemoryExecutor* current_executor;

struct InMemoryExecutor : public Executor {

  InMemoryExecutor(HarnessFunctionType func) {
    harness = func;
  }

  void runTarget() {
    current_executor = this;
    if (auto raw = dynamic_cast<RawInput*>(current_input)) {
      harness((const uint8_t*)raw->getBytes().data(), raw->getBytes().size());
    } else {
      Bytes bytes = current_input->serialize();
      harness((const uint8_t*)bytes.data(), bytes.size());
    }
    current_executor = nullptr;
  }

protected:
  HarnessFunctionType harness;

};

}
