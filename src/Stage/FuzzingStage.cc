#include "Stage/Stage.hpp"
#include "Mutator/Mutator.hpp"
#include "Engine.hpp"

using namespace FFF;

void FuzzingStage::perform(VirtualInput* input) {

  size_t num = iterations();
  if (!input->hasClone())
      input->saveClone();

  for(size_t i = 0; i < num; ++i) {
    for (auto mut : mutators)
      mut->mutate(input, i);
    engine->execute(input);
    input->resetClone();
  }

}
