#pragma once

namespace FFF {

struct Executor;

struct ObvservationChannel {

  void flush() {};
  virtual void reset() = 0;
  
  virtual void postExec(Executor* executor) {}

};

}
