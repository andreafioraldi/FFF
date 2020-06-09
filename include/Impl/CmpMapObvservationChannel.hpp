#pragma once

#include "ObservationChannel.hpp"
#include <cstring>

namespace FFF {

struct CmpMapObvservationChannel : ObvservationChannel {

  CmpMapObvservationChannel(uint8_t* traceBits, size_t size) {
    this->traceBits = traceBits;
    this->size = size;
  }

  void reset() {
    memset(traceBits, 0, size);
  };

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


