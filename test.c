#define DIGEST_IMPLEMENTATION
#include "digest.h"

#include <stdio.h>

uint64_t sha512_hash[8];
uint64_t sha512_expected[8] = {
  0xddaf35a193617aba, 0xcc417349ae204131,
  0x12e6fa4e89a97ea2, 0x0a9eeee64b55d39a,
  0x2192992a274fc1a8, 0x36ba3c23a3feebbd,
  0x454d4423643ce80e, 0x2a9ac94fa54ca49f
};

uint64_t sha384_hash[6];
uint64_t sha384_expected[6] = {
  0xcb00753f45a35e8b, 0xb5a03d699ac65007,
  0x272c32ab0eded163, 0x1a8b605a43ff5bed,
  0x8086072ba1e7cc23, 0x58baeca134c825a7
};

uint32_t sha256_hash[8];
uint32_t sha256_expected[8] = {
  0xba7816bf, 0x8f01cfea,
  0x414140de, 0x5dae2223,
  0xb00361a3, 0x96177a9c,
  0xb410ff61, 0xf20015ad
};

/* TODO: Fix this mess */

int main(int argc, char **argv)
{
  unsigned short i;

  if (digest_sha512("abc", 3, sha512_hash) != 0) {
    fprintf(stderr, "digest_sha512 returned non-zero\n");
    return 1;
  }
  for (i = 0; i < 8; i++) {
    if (sha512_hash[i] != sha512_expected[i]) {
      return 1;
    }
  }
  printf("digest_sha512 PASSED!\n");

  if (digest_sha384("abc", 3, sha384_hash) != 0) {
    fprintf(stderr, "digest_sha384 returned non-zero\n");
    return 1;
  }

  for (i = 0; i < 6; i++) {
    if (sha384_hash[i] != sha384_expected[i]) {
      return 1;
    }
  }
  printf("digest_sha384 PASSED!\n");

  if (digest_sha256("abc", 3, sha256_hash) != 0) {
    fprintf(stderr, "digest_sha256 returned non-zero\n");
    return 1;
  }
  for (i = 0; i < 8; i++) {
    if (sha256_hash[i] != sha256_expected[i]) {
      return 1;
    }
  }
  printf("digest_sha256 PASSED!\n");

  return 0;
}
