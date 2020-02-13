#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


#include "aes.h"
#include "curve25519-donna.h"

#include "crypto.h"

typedef char bool;
#define true 1
#define false 0


const char hex_table[16] ={ '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
void output_in_hex(FILE* file, const u_int8_t* data, const size_t size) {
    for (size_t i = 0; i < size; i++) {
        fprintf(file, "%c%c", hex_table[(data[i]>>4) & 0xf], hex_table[(data[i]>>0) & 0xf]);
    }
}

bool check_if_hex(const char* string) {
    int i = 0;
    while (string[i] != 0) {
        const char c = string[i];
        if (!((c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9'))) return false;
        i++;
    }
    return (i % 2 == 0);
}

void hex_to_bytes(u_int8_t* output, const char* input) {
    int i = 0;
    char c = 0;
    u_int8_t b = 0;
    while (input[i + 0] != 0 || input[i + 1] != 0) {
        b = 0;
        c = input[i + 0];
        if      (c >= 'A' && c <='F') b |= (c - 'A' + 0xa) << 4;
        else if (c >= 'a' && c <='f') b |= (c - 'a' + 0xa) << 4;
        else if (c >= '0' && c <='9') b |= (c - '0' + 0x0) << 4;
        c = input[i + 1];
        if      (c >= 'A' && c <='F') b |= (c - 'A' + 0xa) << 0;
        else if (c >= 'a' && c <='f') b |= (c - 'a' + 0xa) << 0;
        else if (c >= '0' && c <='9') b |= (c - '0' + 0x0) << 0;
        output[i >> 1] = b;
        i += 2;
    }
}

bool rgn_32_bytes(uint8_t *rng_bytes_out) {
    fprintf(stderr, "Reminder: these keys use /dev/urandom entropy, which might be insufficient.\n");
    fprintf(stderr, "While reportedly good on modern OS, strongly suggest coding to your system-specific CSRNG instead.\n");
    FILE* f = fopen("/dev/urandom", "rb");
    size_t n_bytes_read = fread(rng_bytes_out, 1, 32, f);
    fclose(f);
    if (n_bytes_read == 32) {
        return true;
    } else {
        return false;
    }
}

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
        void* aes_state = alloca(aes_state_size());
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
