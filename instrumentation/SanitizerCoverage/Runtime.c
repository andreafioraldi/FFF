#include "Config.h"

#include <stdint.h>

uint8_t __fff_edges_map[MAP_SIZE];
uint8_t __fff_cmp_map[MAP_SIZE];

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __fff_edges_map[*guard]++;
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {
 
  static uint32_t cnt;

  if (start == stop || *start) return;

  *(start++) = ++cnt;

  while (start < stop) {
    *start = ++cnt;
    start++;
  }

}

#define MAX(a,b) \
 ({ __typeof__ (a) _a = (a); \
     __typeof__ (b) _b = (b); \
   _a > _b ? _a : _b; })

#if defined(__APPLE__)
  #pragma weak __sanitizer_cov_trace_const_cmp1 = __sanitizer_cov_trace_cmp1
  #pragma weak __sanitizer_cov_trace_const_cmp2 = __sanitizer_cov_trace_cmp2
  #pragma weak __sanitizer_cov_trace_const_cmp4 = __sanitizer_cov_trace_cmp4
  #pragma weak __sanitizer_cov_trace_const_cmp8 = __sanitizer_cov_trace_cmp8
#else
void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp1")));
void __sanitizer_cov_trace_const_cmp2(uint16_t arg1, uint16_t arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp2")));
void __sanitizer_cov_trace_const_cmp4(uint32_t arg1, uint32_t arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp4")));
void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2)
    __attribute__((alias("__sanitizer_cov_trace_cmp8")));
#endif

void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2) {
  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __fff_cmp_map[k] = MAX(__fff_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));
}

void __sanitizer_cov_trace_cmp2(uint16_t arg1, uint16_t arg2) {
  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __fff_cmp_map[k] = MAX(__fff_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));
}

void __sanitizer_cov_trace_cmp4(uint32_t arg1, uint32_t arg2) {
  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __fff_cmp_map[k] = MAX(__fff_cmp_map[k], (__builtin_popcount(~(arg1 ^ arg2))));
}

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {
  uintptr_t k = (uintptr_t)__builtin_return_address(0);
  k = (k >> 4) ^ (k << 8);
  k &= MAP_SIZE - 1;
  __fff_cmp_map[k] = MAX(__fff_cmp_map[k], (__builtin_popcountll(~(arg1 ^ arg2))));
}
