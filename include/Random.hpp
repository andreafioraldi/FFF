#pragma once

#include <cstdlib>
#include <ctime>

namespace FFF {

struct Random {

  static void init(int seed) {
    if (seed) srand(seed);
    else srand(time(NULL));
  }
  
  static int below(int max) {
    return rand() % max;
  }

};

};
