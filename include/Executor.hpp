#pragma once

#include "VirtualInput.hpp"
#include "ObservationChannel.hpp"

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

  std::vector<ObvservationChannel*>& getObservers() {
    return observers;
  }
  void addObserver(ObvservationChannel* obs) {
    observers.push_back(obs);
  }
  VirtualInput* getCurrentInput() {
    return currentInput;
  }

protected:
  std::vector<ObvservationChannel*> observers;
  VirtualInput* currentInput;

};

}
