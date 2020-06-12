#include "Stage/FuzzingStage.hpp"
#include "Mutator/Mutator.hpp"
#include "Engine.hpp"

using namespace FFF;

void FuzzingStage::perform(std::shared_ptr<VirtualInput> input) {

  size_t num = iterations();
  if (!input->hasBackup())
      input->createBackup();

  for(size_t i = 0; i < num; ++i) {
    for (auto mut : mutators)
      mut->mutate(input, i);
    engine->execute(input);
    input->resetBackup();
  }

}
