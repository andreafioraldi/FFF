#pragma once

#include <cstdlib>
#include <ctime>

namespace FFF {

struct Random {

  static void init() {
    srand(time(NULL));
  }
  static void init(int seed) {
    srand(seed);
  }
  
  static int below(int max) {
    return rand() % max;
  }

};

};
