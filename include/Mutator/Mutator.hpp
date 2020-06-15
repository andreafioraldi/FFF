#pragma once

#include "Input/VirtualInput.hpp"
#include "Object.hpp"

namespace FFF {

struct FuzzingStage;

struct Mutator : public Object {

  Mutator(FuzzingStage* stage) {
    this->stage = stage;
  }

  virtual void mutate(VirtualInput* input, size_t stage_idx) = 0;

  FuzzingStage* getStage() {
    return stage;
  }

protected:
  FuzzingStage* stage;

};

}
