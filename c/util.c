#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
    while (input[i + 0] != 0 && input[i + 1] != 0) {
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
