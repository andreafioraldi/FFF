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
struct BaseQueue;

struct QueueEntry : public Object {

  friend class BaseQueue;

  QueueEntry(const std::shared_ptr<VirtualInput>& input, BaseQueue* queue);
  
  std::shared_ptr<VirtualInput>& getInput() {
    if (input->isEmpty())
      input->loadFromFile(filename);
    return input;
  }
  FeedbackMetadata* getMeta() {
    return meta;
  }
  void setMeta(FeedbackMetadata* meta) {
    this->meta = meta;
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
  std::shared_ptr<VirtualInput> input;
  std::string filename;
  FeedbackMetadata* meta = nullptr;
  BaseQueue* queue;

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

  void setDirectory(std::string path) {
    dirpath = path;
    save_to_files = true;
  }
  std::string getDirectory() {
    return dirpath;
  }
  void unsetDirectory() {
    dirpath = "";
    save_to_files = false;
  }
  bool getSaveToFiles() {
    return save_to_files;
  }
  size_t& getNamesID() {
    return names_id;
  }

protected:
  QueueEntry* base = nullptr;
  size_t size = 0;
  std::map<Engine*, QueueEntry*> currents;
  std::string dirpath;
  size_t names_id = 0;
  bool save_to_files = false;

};

}
