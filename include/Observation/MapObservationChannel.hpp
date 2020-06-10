#pragma once

#include "Observation/ObservationChannel.hpp"
#include <cstring>

namespace FFF {

template<typename BaseType>
struct MapObservationChannel : ObservationChannel {

  MapObservationChannel(BaseType* traceBits, size_t size) {
    this->traceBits = traceBits;
    this->size = size;
  }

  void reset() {
    memset(traceBits, 0, size * sizeof(BaseType));
  };

  BaseType* getTraceBits() {
    return traceBits;
  }
  size_t getSize() {
    return size;
  }

protected:
  BaseType* traceBits;
  size_t size;

};

struct HitcountsMapObservationChannel : MapObservationChannel<uint8_t> {

  using MapObservationChannel<uint8_t>::MapObservationChannel;

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

};

struct CmpMapObservationChannel : MapObservationChannel<uint8_t> {

  using MapObservationChannel<uint8_t>::MapObservationChannel;

};

}
