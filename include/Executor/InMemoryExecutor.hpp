#pragma once

#include "Executor/Executor.hpp"
#include "Input/RawInput.hpp"

namespace FFF {

struct InMemoryExecutor;
extern InMemoryExecutor* current_executor;

struct InMemoryExecutor : public Executor {

  InMemoryExecutor(HarnessFunctionType func) {
    this->harnessFunction = func;
  }

  void runTarget() {
    current_executor = this;
    if (auto raw = std::dynamic_pointer_cast<RawInput>(currentInput)) {
      harnessFunction((const uint8_t*)raw->getBytes().data(), raw->getBytes().size());
    } else {
      Bytes bytes = currentInput->serialize();
      harnessFunction((const uint8_t*)bytes.data(), bytes.size());
    }
    current_executor = nullptr;
  }

protected:
  HarnessFunctionType harnessFunction;

};

}
