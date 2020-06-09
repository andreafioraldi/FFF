#pragma once

#include "VirtualInput.hpp"
#include "Random.hpp"
#include "Logger.hpp"

#include <vector>
#include <map>
#include <string>

namespace FFF {

struct Engine;
struct Feedback;
struct FeedbackMetadata;

struct QueueEntry {

  friend class AbstractQueue;

  QueueEntry(VirtualInput* input) {
    this->input = input;
  }
  QueueEntry(VirtualInput* input, bool isGlobal) {
    this->input = input;
    this->isGlobalFlag = isGlobal;
  }
  
  VirtualInput* getInput() {
    return input;
  }
  FeedbackMetadata* getMeta() {
    return meta;
  }
  void setMeta(FeedbackMetadata* meta) {
    this->meta = meta;
  }
  bool isGlobal() {
    return isGlobalFlag;
  }
  
  QueueEntry* getNext() {
    return next;
  }
  QueueEntry* getPrev() {
    return prev;
  }
  QueueEntry* getParent() {
    return parent;
  }
  QueueEntry* getChild(size_t index) {
    return children.at(index);
  }

protected:
  VirtualInput* input;
  FeedbackMetadata* meta = nullptr;
  bool isGlobalFlag = true;

  QueueEntry* next = nullptr;
  QueueEntry* prev = nullptr;
  QueueEntry* parent = nullptr;
  std::vector<QueueEntry*> children;

};

struct AbstractQueue {

  virtual const char* getQueueName() {
    return "AbstractQueue";
  }

  virtual void add(QueueEntry* entry) {
    entry->next = base;
    if (base) base->prev = entry;
    base = entry;
    size++;
    // TODO proper logging
    std::cerr << getQueueName() << " ADD: size = " << size << "\n";
  }
  virtual void remove(QueueEntry* entry) {
    // TODO
  }
  virtual QueueEntry* get(Engine* engine) {
    size--;
    return currents[engine];
  }
  virtual QueueEntry* getNext(Engine* engine) {
    QueueEntry* q = currents[engine];
    if (q == nullptr)
      q = base;
    currents[engine] = q->next;
    return q;
  }
  QueueEntry* getBase() {
    return base;
  }
  size_t getSize() {
    return size;
  }

protected:
  QueueEntry* base = nullptr;
  size_t size = 0;
  std::map<Engine*, QueueEntry*> currents;

};

struct FeedbackQueue : public AbstractQueue {

  virtual const char* getQueueName() {
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

struct GlobalQueue : public AbstractQueue {

  virtual const char* getQueueName() {
    return "GlobalQueue";
  }

  QueueEntry* get(Engine* engine) {
    if (currentsQueues[engine] != nullptr)
      return currentsQueues[engine]->get(engine);
    return AbstractQueue::get(engine);
  }
  QueueEntry* getNext(Engine* engine) {
    int choice = schedule();
    if (choice < 0 || feedbackQueues[choice]->getSize() == 0) {
      currentsQueues[engine] = nullptr;
      return AbstractQueue::getNext(engine);
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
