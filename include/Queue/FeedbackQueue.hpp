#pragma once

#include "Queue/BaseQueue.hpp"

namespace FFF {

struct FeedbackQueue : public BaseQueue {

  virtual std::string getObjectName() {
    return name;
  }

  FeedbackQueue(Feedback* feedback) {
    this->feedback = feedback;
  }
  FeedbackQueue(Feedback* feedback, const char* name) {
    this->feedback = feedback;
    this->name = name;
  }
  
protected:
  Feedback* feedback;
  const char* name = "FeedbackQueue";

};

}
