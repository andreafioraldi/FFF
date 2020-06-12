#pragma once

#include "Input/VirtualInput.hpp"

namespace FFF {

struct RawInput : public VirtualInput {

  RawInput() {}
  RawInput(const Bytes& bytes) {
    this->bytes = bytes;
  }
  
  void deserialize(const Bytes& bytes) {
    this->bytes = bytes;
  }
  Bytes serialize() {
    return bytes;
  }
  
  void createBackup() {
    backup = bytes;
  }
  void resetBackup() {
    bytes = backup;
  }

  std::shared_ptr<VirtualInput> copy();
  
  Bytes& getBytes() {
    return bytes;
  }
  
protected:
  Bytes bytes;
  Bytes backup;

};

}
