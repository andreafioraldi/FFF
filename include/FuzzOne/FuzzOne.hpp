#pragma once

#include "Input/VirtualInput.hpp"
#include "Stage/FuzzingStage.hpp"
#include "Queue/BaseQueue.hpp"
#include "Object.hpp"
#include "Engine.hpp"
#include "Random.hpp"

#include <vector>

namespace FFF {

struct Engine;

struct FuzzOne : public Object {

  FuzzOne(Engine* engine) {
    this->engine = engine;
  }

  virtual void perform() = 0;

protected:
  Engine* engine;

};

struct StagedFuzzOne : public FuzzOne {

  using FuzzOne::FuzzOne;

  void perform() {
  
    QueueEntry* q = engine->getQueue()->getNext(engine);
    if (!q) return;

    VirtualInput* input = q->getInput();
    
    for(auto stage : stages)
      stage->perform(input);

  }
  
  void addStage(Stage* stage) {
    stages.push_back(stage);
  }
  template <class T, typename...Ts>
  T* createStage(Ts... args) {
    T* obj = new T(engine, args...);
    addStage(static_cast<Stage*>(obj));
    return obj;
  }

protected:
  std::vector<Stage*> stages;

};

}
