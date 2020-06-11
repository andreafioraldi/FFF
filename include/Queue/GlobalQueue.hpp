#pragma once

#include "Queue/BaseQueue.hpp"
#include "Queue/FeedbackQueue.hpp"

namespace FFF {

struct GlobalQueue : public BaseQueue {

  virtual std::string getObjectName() {
    return "GlobalQueue";
  }

  QueueEntry* get(Engine* engine) {
    if (currentsQueues[engine] != nullptr)
      return currentsQueues[engine]->get(engine);
    return BaseQueue::get(engine);
  }
  QueueEntry* getNext(Engine* engine) {
    int choice = schedule();
    if (choice < 0 || feedbackQueues[choice]->getSize() == 0) {
      currentsQueues[engine] = nullptr;
      return BaseQueue::getNext(engine);
    } else {
      currentsQueues[engine] = feedbackQueues[choice];
      return currentsQueues[engine]->getNext(engine);
    }
  }

  int schedule() { // Random naive schedule

    if (feedbackQueues.size() == 0 || Random::below(2))
      return -1; // Schedule Global
    return Random::below(feedbackQueues.size());

  }

  void addFeedbackQueue(FeedbackQueue* queue) {
    feedbackQueues.push_back(queue);
  }

protected:
  std::vector<FeedbackQueue*> feedbackQueues;
  std::map<Engine*, FeedbackQueue*> currentsQueues;

};

}
