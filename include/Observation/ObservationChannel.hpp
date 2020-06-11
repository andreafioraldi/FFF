#pragma once

#include "Object.hpp"

namespace FFF {

struct Executor;

struct ObservationChannel : public Object {

  void flush() {};
  virtual void reset() = 0;
  
  virtual void postExec(Executor* executor) {}

};

}
