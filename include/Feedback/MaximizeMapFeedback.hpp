#pragma once

#include "Feedback/Feedback.hpp"
#include "Observation/MapObservationChannel.hpp"

#include <type_traits>

namespace FFF {

template<class BaseType, class ObserverType>
struct MaximizeMapFeedback : Feedback {

  MaximizeMapFeedback(size_t size) {
    // static_assert(std::is_base_of<MapObservationChannel, ObserverType>::value, "ObserverType must derive from MapObservationChannel");
    this->size = size;
    virginBits = new BaseType[size]();
  }

  virtual ~MaximizeMapFeedback() {
    delete virginBits;
  }

  bool isInteresting(Executor* executor) {
  
    bool found = false;

    for (auto ob : executor->getObservers()) {
      if (auto hmob = dynamic_cast<ObserverType*>(ob)) {
      
        if (size != hmob->getSize()) continue;
      
        for (size_t i = 0; i < size; ++i) {
          BaseType e = hmob->getTraceBits()[i];
          if (e > virginBits[i]) {
            virginBits[i] = e;
            found = true;
          }
        }
      
      }
    }
    
    if (feedbackQueue) {
      if (found)
        feedbackQueue->add(new QueueEntry(executor->getCurrentInput(), false));
      
      return false; // never use GlobalQueue
    }
    
    return found;
  
  }

private:
  BaseType* virginBits;
  size_t size;

};

}
