#pragma once

#include <iostream>
#include <ostream>

namespace FFF {

struct Logger {

  static void setOutstream(std::ostream* s) {
    outstream = s;
  }

  template <typename T, typename...Ts>
  static void log(T &&first, Ts&&... rest) {
    if (outstream) {
      *outstream << std::forward<T>(first);
      log(std::forward<Ts>(rest)...);
    }
  }
  
  static inline void log() {}

private:
  static std::ostream* outstream;

};

};
