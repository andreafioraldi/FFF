#pragma once

#include "Executor/Executor.hpp"

namespace FFF {

typedef int (*HarnessFunctionType)(const uint8_t* data, size_t size);

struct InMemoryExecutor;
extern InMemoryExecutor* current_executor;

struct InMemoryExecutor : public Executor {

  InMemoryExecutor(HarnessFunctionType func) {
    this->harnessFunction = func;
  }

  void runTarget() {
    current_executor = this;
    if (currentInput->alreadySerialized()) {
      harnessFunction((const uint8_t*)currentInput->raw().data(), currentInput->raw().size());
    } else {
      Bytes bytes = currentInput->serialize();
      harnessFunction((const uint8_t*)bytes.data(), bytes.size());
    }
    current_executor = nullptr;
  }

private:
  HarnessFunctionType harnessFunction;

};

}
