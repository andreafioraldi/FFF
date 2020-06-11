#pragma once

#include "Input/VirtualInput.hpp"
#include "Observation/ObservationChannel.hpp"
#include "Object.hpp"

#include <vector>

namespace FFF {

struct Executor : public Object {

  virtual void runTarget() = 0;
  virtual void placeInput(VirtualInput* input) {
    currentInput = input;
  }

  void resetObservationChannels() {
    for (auto obv : observers)
      obv->reset();
  }

  std::vector<ObservationChannel*>& getObservationChannels() {
    return observers;
  }
  void addObservationChannel(ObservationChannel* obs) {
    observers.push_back(obs);
  }
  template <class T, typename...Ts>
  T* createObservationChannel(Ts... args) {
    T* obj = new T(args...);
    addObservationChannel(static_cast<ObservationChannel*>(obj));
    return obj;
  }
  
  VirtualInput* getCurrentInput() {
    return currentInput;
  }

protected:
  std::vector<ObservationChannel*> observers;
  VirtualInput* currentInput;

};

}
