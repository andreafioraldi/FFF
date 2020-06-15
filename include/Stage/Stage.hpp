#pragma once

#include "Input/VirtualInput.hpp"
#include "Object.hpp"

#include <vector>

namespace FFF {

struct Engine;

struct Stage : public Object {

  Stage(Engine* engine) {
    this->engine = engine;
  }

  virtual void perform(VirtualInput* input, VirtualInput* original) = 0;

protected:
  Engine* engine;

};

}
