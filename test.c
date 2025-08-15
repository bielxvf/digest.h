#define DIGEST_IMPLEMENTATION
#include "digest.h"

#include <stdio.h>

int main(int argc, char **argv)
{
  unsigned short i;

  uint64_t sha512_hash[8];
  uint32_t sha256_hash[8];
  uint64_t sha512_expected[8] = {
    0xddaf35a193617aba, 0xcc417349ae204131,
    0x12e6fa4e89a97ea2, 0x0a9eeee64b55d39a,
    0x2192992a274fc1a8, 0x36ba3c23a3feebbd,
    0x454d4423643ce80e, 0x2a9ac94fa54ca49f
  };
  uint32_t sha256_expected[8] = {
    0xba7816bf, 0x8f01cfea,
    0x414140de, 0x5dae2223,
    0xb00361a3, 0x96177a9c,
    0xb410ff61, 0xf20015ad
  };

  if (digest_sha512("abc", 3, sha512_hash) != 0) {
    return 1;
  }
  for (i = 0; i < 8; i++) {
    if (sha512_hash[i] != sha512_expected[i]) {
      return 1;
    }
  }
  printf("digest_sha512 PASSED!\n");

  if (digest_sha256("abc", 3, sha256_hash) != 0) {
    return 1;
  }
  for (i = 0; i < 8; i++) {
    if (sha512_hash[i] != sha512_expected[i]) {
      return 1;
    }
  }
  printf("digest_sha256 PASSED!\n");

  return 0;
}
