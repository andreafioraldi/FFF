#pragma once

#include "ObservationChannel.hpp"
#include <cstring>

namespace FFF {

struct HitcountsMapObvservationChannel : ObvservationChannel {

  HitcountsMapObvservationChannel(uint8_t* traceBits, size_t size) {
    this->traceBits = traceBits;
    this->size = size;
  }

  void reset() {
    memset(traceBits, 0, size);
  };

  void postExec(Executor* executor) {
    static constexpr uint8_t countClassLookup[256] = {

      [0]           = 0,
      [1]           = 1,
      [2]           = 2,
      [3]           = 4,
      [4 ... 7]     = 8,
      [8 ... 15]    = 16,
      [16 ... 31]   = 32,
      [32 ... 127]  = 64,
      [128 ... 255] = 128

    };
    
    for (size_t i = 0; i < size; ++i) {
      traceBits[i] = countClassLookup[traceBits[i]];
    }
  }
  
  uint8_t* getTraceBits() {
    return traceBits;
  }
  size_t getSize() {
    return size;
  }

protected:
  uint8_t* traceBits;
  size_t size;

};

}
