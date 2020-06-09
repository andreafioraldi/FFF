#pragma once

#include "VirtualInput.hpp"
#include "Executor.hpp"

namespace FFF {

typedef int (*HarnessFunctionType)(const uint8_t* data, size_t size);

struct InMemoryExecutor : Executor {

  InMemoryExecutor(HarnessFunctionType func) {
    this->harnessFunction = func;
  }

  void runTarget() {
    if (currentInput->alreadySerialized()) {
      harnessFunction(currentInput->raw().data(), currentInput->raw().size());
    } else {
      Bytes bytes = currentInput->serialize();
      harnessFunction(bytes.data(), bytes.size());
    }
  }

private:
  HarnessFunctionType harnessFunction;

};

}
