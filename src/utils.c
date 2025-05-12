# include <stdio.h>
# include <stdlib.h>
# include <openssl/err.h>
# include <openssl/evp.h>
# include "../include/utils.h"
# include "math.h"
# include <string.h>

/* todo: error checking */


void handle_error_ssl(){
    ERR_print_errors_fp(stderr);
    abort();
}


void handle_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    abort();
}

/* String Manipulation APIS */

// Convert unsigned char to hex string
void u8str(uint8_t x,uint8_t* out){
    *out = x;
}

// Convert unsigned short int to hex string
void u16str(uint16_t x, uint8_t *out) {
    out[0] = (x >> 8) & 0xFF;
    out[1] = x & 0xFF;
}

// Convert unsigned int to hex string
void u32str(uint32_t x, uint8_t *out){
    out[0] = (x >> 24) & 0xFF;
    out[1] = (x >> 16) & 0xFF;
    out[2] = (x >> 8) & 0xFF;
    out[3] = x & 0xFF;
}


// Convert hex string to unsigned int
uint32_t strTou32(const uint8_t *in) {
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8)  |
           ((uint32_t)in[3]);
}

// Interpret a byte string as a sequence of w-bit values
uint8_t coef(const uint8_t S[], size_t i, int w) {

    // w should be either 1, 2, 4, or 8
    if (w != 1 && w != 2 && w != 4 && w != 8) {
        handle_error("Parameter w not in { 1, 2, 4, 8 }");
    }

    // If i is larger than the number of w-bit values in S, then error
    if (i >= (strlen((char *)S) * 8) / w) {
        handle_error(" I larger than the number of w-bit values in S ");  
    }

    size_t byte_index = floor(i * w / 8);
    int bit_offset = 8 - (w * (i % (8 / w)) + w);
    return (S[byte_index] >> bit_offset) & ((1 << w) - 1);
}

// Convert a byte array to a hex string
void hex_encode(const uint8_t *in, size_t len, char *out) {
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hex[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = hex[in[i] & 0xF];
    }
    out[2 * len] = '\0';
}
