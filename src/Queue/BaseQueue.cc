#include "Queue/BaseQueue.hpp"

using namespace FFF;

QueueEntry::QueueEntry(const std::shared_ptr<VirtualInput>& input, BaseQueue* queue) {
  this->input = input;
  this->queue = queue;
  if (queue->getSaveToFiles()) {
    filename = queue->getDirectory() + "/testcase-" + std::to_string(queue->getNamesID()++);
    input->saveToFile(filename);
    input->clear();
  }
}
