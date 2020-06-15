#pragma once

#include "OS/Crash.hpp"

#include <stdlib.h>

namespace FFF {

enum class ForkResult {
  FAILED,
  CHILD,
  PARENT
};

struct Process {

  static Process* current();
  
  ForkResult fork();
  void suspend();
  void resume();
  ExitType wait(bool untraced = false);
  
protected:
  void* handle;

};

};
