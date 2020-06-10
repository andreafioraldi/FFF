#pragma once

#include "Input/VirtualInput.hpp"
#include "Stage/FuzzingStage.hpp"
#include "Queue/BaseQueue.hpp"
#include "Random.hpp"

#include <vector>

namespace FFF {

struct Engine;

struct FuzzOne {

  virtual void perform() = 0;

};

struct MutationalFuzzOne : FuzzOne {

  MutationalFuzzOne(Engine* engine, BaseQueue* queue) {
    this->engine = engine;
    this->queue = queue;
  }

  void perform() {
  
    QueueEntry* q = queue->getNext(engine);
    if (!q) return;

    VirtualInput* input = q->getInput();
    
    for(auto stage : stages)
      stage->perform(input);

  }
  
  void addStage(Stage* stage) {
    stages.push_back(stage);
  }

protected:
  Engine* engine;
  BaseQueue* queue;
  std::vector<Stage*> stages;

};

}
