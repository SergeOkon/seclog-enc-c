#include <stddef.h>
#include <stdint.h>
#include "curve25519-donna.h"
#include "aes.h"

// AES

size_t aes_state_size() {
    return sizeof(struct AES_ctx);
}

void aes_init(void* aes_state, const uint8_t* key, const uint8_t* ivs) {
    AES_init_ctx_iv(aes_state, key, ivs);
}

void aes_encrypt(void* aes_state, uint8_t* buffer, const size_t size) {
    AES_CBC_encrypt_buffer(aes_state, buffer, size);
}

void aes_decrypt(void* aes_state, uint8_t* buffer, const size_t size) {
    AES_CBC_decrypt_buffer(aes_state, buffer, size);
}


// Curve 25519

static const uint8_t basepoint[32] = { 9, 0, 0, 0, 0, 0, 0, 0,  
                                       0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0 };

void ec25519_donna_conv_rng_bytes_to_private_key(uint8_t* rng_bytes)
{
    rng_bytes[0]  &= 248;
    rng_bytes[31] &= 127;
    rng_bytes[31] |= 64;
}

void ec25519_donna_public_key_given_private_key(uint8_t* public_key_out, const uint8_t* private_key)
{
    curve25519_donna(public_key_out, private_key, basepoint);
}

void ec25519_donna_make_shared_secret(uint8_t* shared_secret_out, const uint8_t* private_key, const uint8_t* public_key) 
{
    curve25519_donna(shared_secret_out, private_key, public_key);
}
