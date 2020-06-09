#pragma once

#include "VirtualInput.hpp"
#include "Feedback.hpp"
#include "FuzzOne.hpp"
#include "Random.hpp"

#include <vector>
#include <map>

namespace FFF {

struct Engine {

  void setFuzzOne(FuzzOne* fuzz_one) {
    this->fuzz_one = fuzz_one;
  }
  void setQueue(GlobalQueue* queue) {
    this->queue = queue;
  }
  void setExecutor(Executor* executor) {
    this->executor = executor;
  }
  void addFeedback(Feedback* feedback) {
    feedbacks.push_back(feedback);
  }

  void execute(VirtualInput* input) {
    executor->resetObservers();
    executor->placeInput(input);
    executor->runTarget();
    for (auto obs : executor->getObservers())
      obs->postExec(executor);
    
    bool add_to_queue = false;
    for(auto feedback : feedbacks)
      add_to_queue = add_to_queue || feedback->isInteresting(executor);
    if (add_to_queue)
      queue->add(new QueueEntry(input, true));
  }

  void loop() {
    while (true)
      fuzz_one->perform();
  }
  
  void loadTestcasesFromDir(const std::string& path) {
    //TODO
  }
  void loadZeroTestcase(size_t size) {
    RawInput* zero = new RawInput(Bytes(size, 0));
    execute(zero);
  }

protected:
  FuzzOne* fuzz_one;
  GlobalQueue* queue;
  Executor* executor;
  std::vector<Feedback*> feedbacks;

};

}
