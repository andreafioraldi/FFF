#pragma once

#include "Input/VirtualInput.hpp"
#include "Feedback/Feedback.hpp"
#include "Queue/GlobalQueue.hpp"
#include "Random.hpp"

#include <filesystem>
#include <atomic>
#include <vector>
#include <chrono>
#include <map>

namespace FFF {

struct FuzzOne;

struct Engine : public Object {

  Engine(Executor* executor, GlobalQueue* queue, int id = 0) {
    this->executor = executor;
    this->queue = queue;
    this->id = id;
  }

  std::string getObjectName() {
    return "Engine #" + std::to_string(id);
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

  void execute(VirtualInput* input);
  void loop();
  
  template<class InputClass>
  void loadTestcasesFromDir(const std::string& path) {
    for (const auto & entry : std::filesystem::directory_iterator(path)) {
      if (!entry.is_regular_file())
        Logger::log("LOADING: Skipping ", entry, " because is not a regular file\n");
      else {
        auto input = new InputClass();
        input->loadFromFile(entry.path());
        Logger::log("LOADING: Executing ", entry, "\n");
        execute(input);
      }
    }
  }

  void loadZeroTestcase(size_t size);
  
  void incrementExecs() {
    executions++;
  }
  size_t getExecs() {
    return executions.load();
  }
  uint64_t getStartTime() {
    return start_time;
  }

protected:
  FuzzOne* fuzz_one;
  GlobalQueue* queue;
  Executor* executor;
  std::vector<Feedback*> feedbacks;

  std::atomic<size_t> executions = 0;
  uint64_t start_time = 0;
  int id;

};

}
