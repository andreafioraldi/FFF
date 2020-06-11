#pragma once

#include "Input/VirtualInput.hpp"
#include "Random.hpp"
#include "Logger.hpp"

#include <vector>
#include <map>
#include <string>

namespace FFF {

struct Engine;
struct Feedback;
struct FeedbackMetadata;

struct QueueEntry : public Object {

  friend class BaseQueue;

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

struct BaseQueue : public Object {

  virtual std::string getObjectName() {
    return "BaseQueue";
  }

  virtual void add(QueueEntry* entry) {
    entry->next = base;
    if (base) base->prev = entry;
    base = entry;
    size++;
    Logger::log(getObjectName(), " ADD: size = ", size, "\n");
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

}
