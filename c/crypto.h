#include <stdint.h>
#include <stdlib.h>

// Randomness functions

// AES wrappers
extern size_t aes_state_size();
// aes_state should be pre-allocated
extern void aes_init(void* aes_state, const uint8_t* key, const uint8_t* ivs);
// buffer - n*16 bytes, key - 32 bytes, ivs - 16 bytes
extern void aes_encrypt(void* aes_state, uint8_t* buffer, const size_t size);
extern void aes_decrypt(void* aes_state, uint8_t* buffer, const size_t size);

// Curve25519 wrappers
// rng_bytes - 32 bytes, public_key - 32 bytes, private key - 32 bytes, shared secret - 32 bytes
extern void ec25519_donna_conv_rng_bytes_to_private_key(uint8_t* rng_bytes);
extern void ec25519_donna_public_key_given_private_key(const uint8_t* public_key_out, const uint8_t* private_key);
extern void ec25519_donna_make_shared_secret(uint8_t* shared_secret_out, const uint8_t* private_key, const uint8_t* public_key);
