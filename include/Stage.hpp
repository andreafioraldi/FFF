#pragma once

#include "VirtualInput.hpp"
#include "Random.hpp"

#include <vector>

namespace FFF {

struct Engine;
struct Mutator;

struct Stage {

  Stage(Engine* engine) {
    this->engine = engine;
  }

  virtual size_t iterations() {
    return 42;
  }

  void perform(VirtualInput* input);

  void addMutator(Mutator* mutator) {
    mutators.push_back(mutator);
  }

protected:
  Engine* engine;
  std::vector<Mutator*> mutators;

};

}
