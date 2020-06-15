#pragma once

#include "Feedback/Feedback.hpp"
#include "Observation/MapObservationChannel.hpp"

#include <type_traits>
#include <atomic>

namespace FFF {

template<class BaseTy, class ObvervationChannelTy>
struct MaximizeMapFeedback : public Feedback {

  MaximizeMapFeedback(size_t size) {
    static_assert(std::is_base_of<MapObservationChannel<BaseTy>, ObvervationChannelTy>::value, "ObvervationChannelTy must derive from MapObservationChannel");
    this->size = size;
    virgin_bits = new std::atomic<BaseTy>[size]();
  }

  virtual ~MaximizeMapFeedback() {
    delete virgin_bits;
  }

  bool isInteresting(Executor* executor) {
  
    bool found = false;

    for (auto ob : executor->getObservationChannels()) {
      if (auto hmob = dynamic_cast<ObvervationChannelTy*>(ob)) {
      
        if (size != hmob->getSize()) continue;
      
        for (size_t i = 0; i < size; ++i) {
          // TODO save new bits
          BaseTy e = hmob->getTraceBits()[i];
          auto old = virgin_bits[i].load();
          while (old < e) {
            bool changed = virgin_bits[i].compare_exchange_weak(old, e);
            if (!changed)
              old = virgin_bits[i].load();
            else {
              found = true;
              break;
            }
          }
        }
      
      }
    }
    
    if (feedback_queue) {
      if (found)
        feedback_queue->add(new QueueEntry(executor->getCurrentInput(), feedback_queue));
      
      return false; // never use GlobalQueue
    }
    
    return found;
  
  }

private:
  std::atomic<BaseTy>* virgin_bits;
  size_t size;

};

}
