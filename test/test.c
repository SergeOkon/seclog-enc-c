#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../c/crypto.h"
#include "../c/util.h"

const char* aes_key_1   = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const char* aes_ivs_1   = "000102030405060708090A0B0C0D0E0F";
const char* aes_plain_1 = "6bc1bee22e409f96e93d7e117393172a";
const char* aes_enc_1   = "f58c4c04d6e5f1ba779eabfb5f7bfbd6";
const char* aes_key_2   = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const char* aes_ivs_2   = "F58C4C04D6E5F1BA779EABFB5F7BFBD6";
const char* aes_plain_2 = "ae2d8a571e03ac9c9eb76fac45af8e51";
const char* aes_enc_2   = "9cfc4e967edb808d679f777bc6702c7d";
const char* aes_key_3   = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const char* aes_ivs_3   = "9CFC4E967EDB808D679F777BC6702C7D";
const char* aes_plain_3 = "30c81c46a35ce411e5fbc1191a0a52ef";
const char* aes_enc_3   = "39f23369a9d9bacfa530e26304231461";
const char* aes_key_4   = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const char* aes_ivs_4   = "39F23369A9D9BACFA530E26304231461";
const char* aes_plain_4 = "f69f2445df4f9b17ad2b417be66c3710";
const char* aes_enc_4   = "b2eb05e2c39be9fcda6c19078c6a9d1b";

const char* secret_a = "70076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C6A";
const char* secret_b = "58AB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E06B";
const char* shared_s = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";


void test_aes(size_t number, const char* aes_key_in, const char* aes_ivs_in, const char* aes_plain_in, const char* aes_enc_in) {
    uint8_t aes_key[32], aes_ivs[16], aes_plain[16], aes_enc[16], buffer[16];
    memset(aes_key, 0, sizeof(aes_key)); memset(aes_ivs,   0, sizeof(aes_ivs));
    memset(aes_enc, 0, sizeof(aes_enc)); memset(aes_plain, 0, sizeof(aes_plain));
    memset(buffer, 0, sizeof(buffer));
    hex_to_bytes(aes_key, aes_key_in);     hex_to_bytes(aes_ivs, aes_ivs_in);
    hex_to_bytes(aes_plain, aes_plain_in); hex_to_bytes(aes_enc, aes_enc_in);

    // Set-up
    u_int8_t aes_state[aes_state_size()];
    printf("aes key   %zu : ", number); output_in_hex(stdout, aes_key, sizeof aes_key); printf("\n");
    printf("aes iv    %zu : ", number); output_in_hex(stdout, aes_ivs, sizeof aes_ivs); printf("\n");

    // AES Decryption test
    aes_init(aes_state, aes_key, aes_ivs);
    memcpy(buffer, aes_enc, sizeof aes_enc);
    aes_decrypt(aes_state, buffer, sizeof buffer);
    printf("aes plain %zu : ", number); output_in_hex(stdout, buffer, sizeof buffer); printf("\n");
   

    // AES Encryption test
    aes_init(aes_state, aes_key, aes_ivs);
    memcpy(buffer, aes_plain, sizeof aes_plain);
    aes_encrypt(aes_state, buffer, sizeof buffer);
    printf("aes enc   %zu : ", number); output_in_hex(stdout, buffer, sizeof buffer); printf("\n");

}

void test_curve() {
    uint8_t sa[32], sb[32], pa[32], pb[32], ss[32];
    memset(pa, 0, sizeof(pa));
    memset(sb, 0, sizeof(sb)); memset(pb, 0, sizeof(pb));
    memset(ss, 0, sizeof(ss));

    hex_to_bytes(sa, secret_a);
    printf("secret A : "); output_in_hex(stdout, sa, sizeof sa); printf("\n");
    ec25519_donna_public_key_given_private_key(pa, sa);
    printf("public A : "); output_in_hex(stdout, pa, sizeof pa); printf("\n");
    hex_to_bytes(sb, secret_b);
    printf("secret B : "); output_in_hex(stdout, sb, sizeof sb); printf("\n");
    ec25519_donna_public_key_given_private_key(pb, sb);
    printf("public B : "); output_in_hex(stdout, pb, sizeof pb); printf("\n");

    memset(ss, 0, sizeof(ss));
    ec25519_donna_make_shared_secret(ss, sa, pb);
    printf("shared 1 : "); output_in_hex(stdout, ss, sizeof ss); printf("\n");

    memset(ss, 0, sizeof(ss));
    ec25519_donna_make_shared_secret(ss, sb, pa);
    printf("shared 2 : "); output_in_hex(stdout, ss, sizeof ss); printf("\n");
}

int main() {
  
    // aims to generate the same output as expected.txt

    printf("AES-256 TESTS\n");
    test_aes(1, aes_key_1, aes_ivs_1, aes_plain_1, aes_enc_1);
    test_aes(2, aes_key_2, aes_ivs_2, aes_plain_2, aes_enc_2);
    test_aes(3, aes_key_3, aes_ivs_3, aes_plain_3, aes_enc_3);
    test_aes(4, aes_key_4, aes_ivs_4, aes_plain_4, aes_enc_4);

    printf("\nCURVE25519 TESTS\n");
    test_curve();
}