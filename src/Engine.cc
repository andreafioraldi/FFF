#include "FuzzOne/FuzzOne.hpp"
#include "Input/RawInput.hpp"
#include "Engine.hpp"
#include "Logger.hpp"

#include <filesystem>

using namespace FFF;

void Engine::execute(VirtualInput* input) {
  executor->resetObservationChannels();
  executor->placeInput(input);
  executor->runTarget();
  for (auto obs : executor->getObservationChannels())
    obs->postExec(executor);
  
  bool add_to_queue = false;
  for(auto feedback : feedbacks)
    add_to_queue = add_to_queue || feedback->isInteresting(executor);
  if (add_to_queue)
    queue->add(new QueueEntry(input->copy(), queue));
}

void Engine::loop() {
  while (true)
    fuzz_one->perform();
}

void Engine::loadZeroTestcase(size_t size) {
  RawInput raw(Bytes(size, 0));
  execute(&raw);
}
