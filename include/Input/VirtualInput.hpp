#pragma once

#include "Bytes.hpp"
#include "Object.hpp"

namespace FFF {

struct VirtualInput : public Object {

  virtual void deserialize(const Bytes& bytes) = 0;
  virtual Bytes serialize() = 0;
  virtual bool alreadySerialized() = 0;
  virtual Bytes& raw() = 0;

  virtual void saveClone() = 0;
  virtual void cleanClone() = 0;
  virtual void resetClone() = 0;
  bool hasClone() {
    return hasCloneFlag;
  }

protected:
  bool hasCloneFlag = false;

};

struct RawInput : public VirtualInput {

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
