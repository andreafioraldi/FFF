#pragma once

#include "Input/VirtualInput.hpp"

namespace FFF {

struct Mutator {

  virtual void mutate(VirtualInput* input, size_t stage_idx) = 0;

};

}
