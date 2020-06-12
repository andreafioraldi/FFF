#pragma once

#include "Stage/Stage.hpp"
#include "Random.hpp"

#include <vector>

namespace FFF {

struct Mutator;

struct FuzzingStage : public Stage {

  using Stage::Stage;

  virtual size_t iterations() {
    return Random::below(128);
  }

  void perform(std::shared_ptr<VirtualInput> input);

  void addMutator(Mutator* mutator) {
    mutators.push_back(mutator);
  }
  template <class T, typename...Ts>
  T* createMutator(Ts... args) {
    T* obj = new T(this, args...);
    addMutator(static_cast<Mutator*>(obj));
    return obj;
  }

protected:
  std::vector<Mutator*> mutators;

};

}
