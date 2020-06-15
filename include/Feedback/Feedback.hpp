#pragma once

#include "Executor/Executor.hpp"
#include "Queue/FeedbackQueue.hpp"
#include "Object.hpp"

namespace FFF {

struct Feedback : public Object {

  virtual bool isInteresting(Executor* executor) = 0;

  void setFeedbackQueue(FeedbackQueue* feedback_queue) {
    this->feedback_queue = feedback_queue;
  }
  FeedbackQueue* getFeedbackQueue() {
    return feedback_queue;
  }

protected:
  FeedbackQueue* feedback_queue = nullptr;
  
};

struct FeedbackMetadata {

  Feedback* getFeedback() {
    return feedback;
  }

protected:
  Feedback* feedback;

};

}
