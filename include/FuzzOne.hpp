#pragma once

#include "VirtualInput.hpp"
#include "Stage.hpp"
#include "Engine.hpp"
#include "Queue.hpp"
#include "Random.hpp"

#include <vector>

namespace FFF {

struct FuzzOne {

  virtual void perform() = 0;

};

struct MutationalFuzzOne : FuzzOne {

  MutationalFuzzOne(Engine* engine, AbstractQueue* queue) {
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
  AbstractQueue* queue;
  std::vector<Stage*> stages;

};

}
