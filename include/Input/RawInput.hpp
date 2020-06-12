#pragma once

#include "Input/VirtualInput.hpp"

namespace FFF {

struct RawInput : public VirtualInput {

  RawInput() {
    is_empty = true;
  }
  RawInput(const Bytes& bytes) {
    this->bytes = bytes;
    is_empty = false;
  }
  
  void deserialize(const Bytes& bytes) {
    this->bytes = bytes;
    is_empty = false;
  }
  Bytes serialize() {
    return bytes;
  }
  
  void createBackup() {
    backup = bytes;
  }
  void resetBackup() {
    bytes = backup;
    is_empty = false;
  }

  std::shared_ptr<VirtualInput> copy(); //TODO handle is_empty
  
  void loadFromFile(std::string path);
  void saveToFile(std::string path);
  void clear() {
    bytes.clear();
    is_empty = true;
  }
  bool isEmpty() {
    return is_empty;
  }
  
  Bytes& getBytes() {
    return bytes;
  }
  
protected:
  Bytes bytes;
  Bytes backup;
  bool is_empty;

};

}
