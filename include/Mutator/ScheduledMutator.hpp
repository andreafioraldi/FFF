#pragma once

#include "Mutator/Mutator.hpp"
#include "Random.hpp"

#include <vector>

namespace FFF {

typedef void (*MutationFunctionType)(Mutator*, VirtualInput*);

struct ScheduledMutator : public Mutator {

  using Mutator::Mutator;

  int iterations() {
    return 1 << (1 + Random::below(7));
  }

  int schedule() {
    return Random::below(mutations.size());
  }
  
  void mutate(VirtualInput* input, size_t stage_idx) {
    int num = iterations();
    for (int i = 0; i < num; ++i) {
      mutations[schedule()](this, input);
    }
  }

  void addMutation(MutationFunctionType func) {
    mutations.push_back(func);
  }

protected:
  std::vector<MutationFunctionType> mutations;

};

void addHavocMutations(ScheduledMutator* mut);

struct HavocMutator : public ScheduledMutator {

  HavocMutator(FuzzingStage* stage) : ScheduledMutator(stage) {
    addHavocMutations(this);
  }

};

}
