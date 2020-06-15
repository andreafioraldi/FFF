#pragma once

#include "Input/VirtualInput.hpp"
#include "Observation/ObservationChannel.hpp"
#include "Object.hpp"

#include <vector>

namespace FFF {

typedef int (*HarnessFunctionType)(const uint8_t* data, size_t size);

struct Executor : public Object {

  virtual void runTarget() = 0;
  virtual void placeInput(VirtualInput* input) {
    current_input = input;
  }

  void resetObservationChannels() {
    for (auto obv : channels)
      obv->reset();
  }

  std::vector<ObservationChannel*>& getObservationChannels() {
    return channels;
  }
  void addObservationChannel(ObservationChannel* obs) {
    channels.push_back(obs);
  }
  template <class T, typename...Ts>
  T* createObservationChannel(Ts... args) {
    T* obj = new T(args...);
    addObservationChannel(static_cast<ObservationChannel*>(obj));
    return obj;
  }
  
  VirtualInput* getCurrentInput() {
    return current_input;
  }

protected:
  std::vector<ObservationChannel*> channels;
  VirtualInput* current_input;

};

}
