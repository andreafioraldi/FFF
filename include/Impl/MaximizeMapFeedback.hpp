#pragma once

#include "Feedback.hpp"
#include "HitcountsMapObvservationChannel.hpp"

namespace FFF {

template<class BaseType>
struct MaximizeMapFeedback : Feedback {

  MaximizeMapFeedback(size_t size) {
    this->size = size;
    virginBits = new BaseType[size]();
  }

  virtual ~MaximizeMapFeedback() {
    delete virginBits;
  }

  bool isInteresting(Executor* executor) {
  
    bool found = false;

    for (auto ob : executor->getObservers()) {
      if (auto hmob = dynamic_cast<HitcountsMapObvservationChannel*>(ob)) {
      
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
