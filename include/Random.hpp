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
    state = seed;
    Logger::logLine("INIT: ", "seed = ", seed);
  }
  
  static uint64_t random() {
    uint64_t x = state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    state = x;
    return x;
  }
  
  static uint64_t below(int max) {
    return random() % max;
  }

  static uint64_t state;

};

};
