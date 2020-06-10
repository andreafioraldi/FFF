#pragma once

#include "Input/VirtualInput.hpp"

#include <vector>

namespace FFF {

struct Engine;
struct Mutator;

struct Stage {

  Stage(Engine* engine) {
    this->engine = engine;
  }

  virtual void perform(VirtualInput* input) = 0;

protected:
  Engine* engine;

};

}
