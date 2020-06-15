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
  
  VirtualInput* copy();
  VirtualInput* empty();
  void restore(VirtualInput* input) {
    RawInput* raw = static_cast<RawInput*>(input); // TODO dynamic check
    bytes = raw->bytes;
  }
  
  void loadFromFile(std::string path);
  void saveToFile(std::string path);
  void clear() {
    bytes.clear();
  }
  
  Bytes& getBytes() {
    return bytes;
  }
  
protected:
  Bytes bytes;

};

}
