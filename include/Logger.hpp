#pragma once

#include <iostream>
#include <ostream>

namespace FFF {

struct Logger {

  static void setOutstream(std::ostream* s) {
    outstream = s;
  }

  template <typename T, typename...Ts>
  static inline void logAux(T &&first, Ts&&... rest) {
    *outstream << std::forward<T>(first);
    logAux(std::forward<Ts>(rest)...);
  }
  static inline void logAux() {}

  template <typename T, typename...Ts>
  static void log(T &&first, Ts&&... rest) {
    if (outstream) {
      *outstream << header << std::forward<T>(first);
      logAux(std::forward<Ts>(rest)...);
    }
  }
  
private:
  static std::ostream* outstream;
  static std::string header;

};

};
