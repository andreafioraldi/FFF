#pragma once

#include "Bytes.hpp"
#include "Object.hpp"

#include <memory>

namespace FFF {

struct VirtualInput : public Object {

  virtual ~VirtualInput() = default;

  virtual void deserialize(const Bytes& bytes) = 0;
  virtual Bytes serialize() = 0;

  virtual VirtualInput* copy() = 0;
  virtual VirtualInput* empty() = 0;
  virtual void restore(VirtualInput* input) = 0;
  
  virtual void loadFromFile(std::string path) = 0;
  virtual void saveToFile(std::string path) = 0;
  virtual void clear() = 0;

};

}
