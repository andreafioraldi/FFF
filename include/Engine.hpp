#pragma once

#include "Input/VirtualInput.hpp"
#include "Feedback/Feedback.hpp"
#include "FuzzOne/FuzzOne.hpp"
#include "Queue/GlobalQueue.hpp"
#include "FuzzOne/FuzzOne.hpp"
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

  void execute(VirtualInput* input);
  void loop() {
    while (true)
      fuzz_one->perform();
  }
  
  void loadTestcasesFromDir(const std::string& path);
  void loadZeroTestcase(size_t size);

protected:
  FuzzOne* fuzz_one;
  GlobalQueue* queue;
  Executor* executor;
  std::vector<Feedback*> feedbacks;

};

}
