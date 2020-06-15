#include "Stage/FuzzingStage.hpp"
#include "Mutator/Mutator.hpp"
#include "Engine.hpp"

using namespace FFF;

void FuzzingStage::perform(VirtualInput* input, VirtualInput* original) {

  size_t num = iterations();

  for(size_t i = 0; i < num; ++i) {
    for (auto mut : mutators)
      mut->mutate(input, i);
    engine->execute(input);
    if (original)
      input->restore(original);
  }

}
