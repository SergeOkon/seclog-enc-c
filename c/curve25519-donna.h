#include <stdint.h>

// a header created for curve25519_donna function.

extern void curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);
