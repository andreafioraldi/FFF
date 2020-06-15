#pragma once

#include "Input/VirtualInput.hpp"
#include "Random.hpp"
#include "Monitor.hpp"

#include <vector>
#include <map>
#include <string>
#include <shared_mutex>
#include <stdexcept>

namespace FFF {

struct Engine;
struct Feedback;
struct FeedbackMetadata;
struct BaseQueue;

struct QueueEntry : public Object {

  friend class BaseQueue;

  QueueEntry(VirtualInput* input, BaseQueue* queue);
  
  VirtualInput* getInput() {
    if (on_disk) {
      VirtualInput* load = input->empty();
      load->loadFromFile(filename);
      return load;
    }
    return input;
  }
  bool isOnDisk() {
    return on_disk;
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
  VirtualInput* input;
  bool on_disk;
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
    queue_mutex.lock();
    if (base) base->prev = entry;
    base = entry;
    size++;
    queue_mutex.unlock();
    Monitor::event(this, "ADD");
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
    if (q == nullptr)
      throw std::runtime_error(getObjectName() + " is empty");
    queue_mutex.lock_shared();
    currents[engine] = q->next;
    queue_mutex.unlock_shared();
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
  std::shared_mutex queue_mutex;
  std::map<Engine*, QueueEntry*> currents;

  std::string dirpath;
  size_t names_id = 0;
  bool save_to_files = false;

};

}
