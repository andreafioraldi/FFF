#pragma once

#include "Input/VirtualInput.hpp"
#include "Observation/ObservationChannel.hpp"

#include <vector>

namespace FFF {

struct Executor {

  virtual void runTarget() = 0;
  virtual void placeInput(VirtualInput* input) {
    currentInput = input;
  }

  void resetObservers() {
    for (auto obv : observers)
      obv->reset();
  }

  std::vector<ObservationChannel*>& getObservers() {
    return observers;
  }
  void addObserver(ObservationChannel* obs) {
    observers.push_back(obs);
  }
  VirtualInput* getCurrentInput() {
    return currentInput;
  }

protected:
  std::vector<ObservationChannel*> observers;
  VirtualInput* currentInput;

};

}
