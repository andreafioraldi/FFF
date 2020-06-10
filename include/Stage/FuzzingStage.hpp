#pragma once

#include "Stage/Stage.hpp"
#include "Random.hpp"

#include <vector>

namespace FFF {

struct Mutator;

struct FuzzingStage : Stage {

  using Stage::Stage;

  virtual size_t iterations() {
    return Random::below(128);
  }

  void perform(VirtualInput* input);

  void addMutator(Mutator* mutator) {
    mutators.push_back(mutator);
  }

protected:
  std::vector<Mutator*> mutators;

};

}
