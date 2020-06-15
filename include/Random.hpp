#pragma once

#include <cstdlib>
#include <ctime>

#include "Logger.hpp"

namespace FFF {

struct Random {

  static void init() {
    init(time(NULL));
  }
  static void init(int seed) {
    srand(seed);
    Logger::logLine("INIT: ", "seed = ", seed);
  }
  
  static int below(int max) {
    return rand() % max;
  }

};

};
