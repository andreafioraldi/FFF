#pragma once

#include "Executor/Executor.hpp"
#include "Queue/FeedbackQueue.hpp"
#include "Object.hpp"

namespace FFF {

struct Feedback : public Object {

  virtual bool isInteresting(Executor* executor) = 0;

  void setFeedbackQueue(FeedbackQueue* feedbackQueue) {
    this->feedbackQueue = feedbackQueue;
  }
  FeedbackQueue* getFeedbackQueue() {
    return feedbackQueue;
  }

protected:
  FeedbackQueue* feedbackQueue = nullptr;
  
};

struct FeedbackMetadata {

  Feedback* getFeedback() {
    return feedback;
  }

protected:
  Feedback* feedback;

};

}
