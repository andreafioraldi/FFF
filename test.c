#include <stdio.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  printf(">> (%ld) %s\n", Size, Data);
  return 0;
}
