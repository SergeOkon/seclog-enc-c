#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "util.h"

typedef char bool;
#define true 1
#define false 0


void print_usage() {
    fprintf(stderr, "AES functions:\n");
    fprintf(stderr, "  crypto aes encrypt <plaintext> <key> <ivs>\n");
    fprintf(stderr, "  crypto aes decrypt <ciphertxt> <key> <ivs>\n");
    fprintf(stderr, "Curve 25519 functions:\n");
    fprintf(stderr, "  crypto curve genpair\n");
    fprintf(stderr, "  crypto curve public <private_key>\n");
    fprintf(stderr, "  crypto curve secret <private_key> <public_key>\n");
}

void error_and_exit(const char* message) {
    fprintf(stderr, "%s", message);
    exit(1);
}

int main(int argc, char **argv) {

    // Algo and commands
    bool aes = false, encrypt = false, decrypt = false;
    bool curve = false, gen_pair = false, get_public = false, get_secret = false;

    // Data params
    uint8_t *data1 = NULL, *data2 = NULL, *data3 = NULL;
    size_t  data1size = 0, data2size = 0, data3size = 0;

    for (int i = 1; i < argc; i++) {
        if (i == 1) {
            // Which Algorithm
            const char* algo = argv[i];
            if      (strcmp(algo, "aes") == 0) aes = true;
            else if (strcmp(algo, "curve") == 0) curve = true;
            else error_and_exit("Unknown algo in param 1");
        } else if (i == 2) {
            // Which Command
            const char* command = argv[i];
            if (aes) {
                if      (strcmp(command, "enc") == 0 || strcmp(command, "encrypt") == 0) encrypt = true;
                else if (strcmp(command, "dec") == 0 || strcmp(command, "decrypt") == 0) decrypt = true;
                else error_and_exit("Unknown aes command in param 2");
            } else if (curve) {
                if      (strcmp(command, "sec") == 0 || strcmp(command, "secret") == 0) get_secret = true;
                else if (strcmp(command, "pub") == 0 || strcmp(command, "public") == 0) get_public = true;
                else if (strcmp(command, "keygen") == 0 || strcmp(command, "key") == 0 || 
                         strcmp(command, "gen") == 0 || strcmp(command, "generate") == 0) gen_pair = true;
                else error_and_exit("Unknown curve command in param 2");
            }
        } else if (i >= 3 && i <= 5) {
            const size_t param_length = strlen(argv[i]);
            uint8_t* data = NULL; 
            size_t size = param_length >> 1;
            if (check_if_hex(argv[i])) {
                data = (uint8_t*) malloc(size);
                hex_to_bytes(data, argv[i]);
            }
            switch(i) {
                case 3: data1 = data; data1size = size; break;
                case 4: data2 = data; data2size = size; break;
                case 5: data3 = data; data3size = size; break;
                default: break;
            }
        }
    }

    if (aes) {
        if (data1size != 16 || data2size != 32 || data3size != 16) {
            error_and_exit("'aes *' needs 3 params - of 16, 32 and 16 bytes");
        }
        u_int8_t buffer[16]; memset(buffer, 0, sizeof(buffer));
        memcpy(buffer, data1, 16);
        u_int8_t aes_state[aes_state_size()];
        aes_init(aes_state, data2, data3);
        if (encrypt) {
            aes_encrypt(aes_state, buffer, 16);
        } else if (decrypt) {
            aes_decrypt(aes_state, buffer, 16);
        } else {
            error_and_exit("'aes' neither 'encrypt' not 'decrypt' asked for");
        }
        output_in_hex(stdout, buffer, sizeof(buffer));
        memset(buffer, 0, sizeof(buffer));
    } else if(curve) {
        if (gen_pair) {
            u_int8_t priv[32]; memset(priv, 0, sizeof(priv));
            u_int8_t pub[32];  memset(pub,  0, sizeof(pub));

            // RNG, convert, and derive public key.
            if (!rgn_32_bytes(priv)) error_and_exit("Unable to get bytes from rng.");  
            ec25519_donna_conv_rng_bytes_to_private_key(priv);
            ec25519_donna_public_key_given_private_key(pub, priv);
            output_in_hex(stdout, priv, sizeof(priv));
            fprintf(stdout, "\n");
            output_in_hex(stdout, pub, sizeof(pub));

            // Clean keys from mem
            memset(priv, 0, sizeof(priv));
            memset(pub,  0, sizeof(pub));
        } else if (get_public) {
            if (data1size != 32) {
                error_and_exit("'curve public' needs a 32-byte param");
            }
            u_int8_t pub[32]; memset(pub, 0, sizeof(pub));
            ec25519_donna_public_key_given_private_key(pub, data1);
            output_in_hex(stdout, pub, sizeof(pub));
            memset(pub,  0, sizeof(pub));
        } else if (get_secret) { 
            if (data1size != 32 || data2size != 32) {
                error_and_exit("'curve secret' needs two 32-byte params - priv & pub");
            }
            u_int8_t secret[32]; memset(secret, 0, sizeof(secret));
            ec25519_donna_make_shared_secret(secret, data1, data2);
            output_in_hex(stdout, secret, sizeof(secret));
            memset(secret,  0, sizeof(secret));
        } else {
            error_and_exit("Nothing asked to do for 'curve'");
        }
    } else {
        print_usage();
    }

    // Cleanup
    if (data1) { memset(data1, 0, data1size); free(data1); }
    if (data2) { memset(data2, 0, data2size); free(data2); }
    if (data3) { memset(data3, 0, data3size); free(data3); }
}
