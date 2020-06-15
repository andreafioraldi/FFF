#include "FuzzOne/FuzzOne.hpp"
#include "Input/RawInput.hpp"
#include "Engine.hpp"
#include "Monitor.hpp"

#include <filesystem>

#define IS_POW2(x) (x && (!(x&(x-1))))

using namespace FFF;

void Engine::execute(VirtualInput* input) {
  executor->resetObservationChannels();
  executor->placeInput(input);
  
  if (start_time == 0)
    start_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  
  executor->runTarget();

  if (IS_POW2(executions))
    Monitor::event(this, "EXECS");
  ++executions;

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
