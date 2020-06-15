#pragma once

#include <iostream>
#include <ostream>
#include <sstream>

namespace FFF {

typedef void (*LogHeaderFunctionType)(std::stringstream& ss);

struct Logger {

  static void setOutstream(std::ostream* s) {
    outstream = s;
  }
  static void setHeaderFunction(LogHeaderFunctionType func) {
    log_header = func;
  }

  template <typename T, typename...Ts>
  static void log(T &&first, Ts&&... rest) {
    if (outstream) {
      std::stringstream ss;
      if (log_header) log_header(ss);
      ss << std::forward<T>(first);
      logAux(ss, std::forward<Ts>(rest)...);
      *outstream << ss.str();
    }
  }
  
  template <typename...Ts>
  static void logLine(Ts&&... rest) {
    log(std::forward<Ts>(rest)..., "\n");
  }
  
private:
  template <typename T, typename...Ts>
  static inline void logAux(std::stringstream& ss, T &&first, Ts&&... rest) {
    ss << std::forward<T>(first);
    logAux(ss, std::forward<Ts>(rest)...);
  }
  static inline void logAux(std::stringstream& ss) {}

  static std::ostream* outstream;
  static LogHeaderFunctionType log_header;

};

void defaultLogHeader(std::stringstream& ss);

}
