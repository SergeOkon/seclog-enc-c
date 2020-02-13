#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern void output_in_hex(FILE* file, const u_int8_t* data, const size_t size);
extern char check_if_hex(const char* string);
extern void hex_to_bytes(u_int8_t* output, const char* input);
extern char rgn_32_bytes(uint8_t *rng_bytes_out);
