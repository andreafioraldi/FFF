#pragma once

namespace FFF {

struct Executor;

struct ObservationChannel {

  void flush() {};
  virtual void reset() = 0;
  
  virtual void postExec(Executor* executor) {}

};

}
