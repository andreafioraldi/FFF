#include "Queue/BaseQueue.hpp"

using namespace FFF;

QueueEntry::QueueEntry(VirtualInput* input, BaseQueue* queue) {
  this->queue = queue;
  if (queue->getSaveToFiles()) {
    filename = queue->getDirectory() + "/testcase-" + std::to_string(queue->getNamesID()++);
    input->saveToFile(filename);
    this->input = input->empty();
    on_disk = true;
  } else {
    this->input = input->copy();
    on_disk = false;
  }
}
