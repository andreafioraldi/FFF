#pragma once

#include "Input/VirtualInput.hpp"
#include "Feedback/Feedback.hpp"
#include "Queue/GlobalQueue.hpp"
#include "Random.hpp"

#include <vector>
#include <map>

namespace FFF {

struct FuzzOne;

struct Engine {

  Engine(Executor* executor, GlobalQueue* queue) {
    this->executor = executor;
    this->queue = queue;
  }

  GlobalQueue* getQueue() {
    return queue;
  }

  void setFuzzOne(FuzzOne* fuzz_one) {
    this->fuzz_one = fuzz_one;
  }
  FuzzOne* getFuzzOne() {
    return fuzz_one;
  }
  template <class T, typename...Ts>
  T* createFuzzOne(Ts... args) {
    T* obj = new T(this, args...);
    setFuzzOne(static_cast<FuzzOne*>(obj));
    return obj;
  }

  void addFeedback(Feedback* feedback) {
    feedbacks.push_back(feedback);
  }
  template <class T, typename...Ts>
  T* createFeedback(Ts... args) {
    T* obj = new T(args...);
    addFeedback(static_cast<Feedback*>(obj));
    return obj;
  }

  void execute(const std::shared_ptr<VirtualInput>& input);
  void loop();
  
  void loadTestcasesFromDir(const std::string& path);
  void loadZeroTestcase(size_t size);

protected:
  FuzzOne* fuzz_one;
  GlobalQueue* queue;
  Executor* executor;
  std::vector<Feedback*> feedbacks;

};

}
