#pragma once

#include "Input/VirtualInput.hpp"

namespace FFF {

struct RawInput : VirtualInput {

  RawInput() {}
  RawInput(const Bytes& bytes) {
    this->bytes = bytes;
  }
  
  virtual void deserialize(const Bytes& bytes) {
    this->bytes = bytes;
  }
  Bytes serialize() {
    return bytes;
  }
  bool alreadySerialized() {
    return true;
  }
  Bytes& raw() {
    return bytes;
  }
  
  void saveClone() {
    clone = bytes;
    hasCloneFlag = true;
  }
  void cleanClone() {
    clone.clear();
    hasCloneFlag = false;
  }
  void resetClone() {
    bytes = clone;
  }
  
protected:
  Bytes bytes;
  Bytes clone;

};

}
