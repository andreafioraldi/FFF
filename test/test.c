#include <stdio.h>
#include <stdint.h>
#include <assert.h>

int target_func(char* buf, int size){
    
    switch (buf[0])
    {
    case 1:
        if(buf[1]=='\x44'){
            volatile char* p;
            p = 0;
            p[0] = 1;
        }
        break;
    case '\xfe':
        // assert(0);
        if(buf[4]=='\xf0'){
            return 8;
        }
        break;
    case 0xff:
        if(buf[2]=='\xff'){
            if(buf[1]=='\x44'){
                *(char*)(0xdeadbeef) = 1;
            }else{
                return 7;
            }
        }
        break;
    default:
        break;
    }

    return 1;
}


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  //printf(">> %s\n", Data);
  target_func(Data, Size);
  return 0;
}
