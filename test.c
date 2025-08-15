#define DIGEST_IMPLEMENTATION
#include "digest.h"

int main(int argc, char **argv)
{
  uint64_t hash[8];
  uint64_t expected[8] = {
    0xddaf35a193617aba, 0xcc417349ae204131,
    0x12e6fa4e89a97ea2, 0x0a9eeee64b55d39a,
    0x2192992a274fc1a8, 0x36ba3c23a3feebbd,
    0x454d4423643ce80e, 0x2a9ac94fa54ca49f
  };
  unsigned short i;

  if (digest_sha512("abc", 3, hash) != 0) {
    return 1;
  }
  for (i = 0; i < 8; i++) {
    if(hash[i] != expected[i]) {
      return 1;
    }
  }

  printf("PASSED!\n");
  return 0;
}
