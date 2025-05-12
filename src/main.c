# include "../include/hash.h"
# include "../include/utils.h"
# include "../include/lmots.h"
# include <stdio.h>
# include <string.h>
# include <stdint.h>

int main() {
    // Example data
    const char *data = "abc";
    uint8_t hash[SHA256_DIGEST_LENGTH];

    // Compute SHA-256 hash
    sha256((const uint8_t *)data, strlen(data), hash);

    // Print the hash in hexadecimal format
    printf("SHA-256 hash of '%s': ", data);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");


    // Example usage of string manipulation functions
    // using u8str
    uint8_t x = 0xFD;
    uint8_t c1[1];
    u8str(x, c1);
    // convert to hex string
    printf("u8str: %02X\n", c1[0]);

    // using u16str
    uint16_t y = 0xABCD;
    uint8_t c2[2];
    u16str(y, c2);
    // convert to hex string
    printf("u16str: %02X%02X\n", c2[0], c2[1]);

    // using u32str
    uint32_t z = 0x123A5678;
    uint8_t c3[4];
    u32str(z, c3);
    // convert to hex string
    printf("u32str: %02X%02X%02X%02X\n", c3[0], c3[1], c3[2], c3[3]);

    // using strTou32
    printf("Inverse check:\n");
    uint8_t hexStr[4] = {0xC2, 0xFE, 0xA6, 0x78};
    printf("hexStr: %02X%02X%02X%02X\n", hexStr[0], hexStr[1], hexStr[2], hexStr[3]);
    uint32_t num = strTou32(hexStr);
    printf("strTou32: %u\n", num);
    
    // Check if they are inverse
    uint8_t hexStr2[4];
    u32str(num, hexStr2);
    printf("u32str: %02X%02X%02X%02X\n", hexStr2[0], hexStr2[1], hexStr2[2], hexStr2[3]);
    // Check if they are equal
    if (memcmp(hexStr, hexStr2, 4) == 0) {
        printf("u32str and strTou32 are inverse\n");
    } else {
        printf("u32str and strTou32 are not inverse\n");
    }

    // using coef
    const uint8_t S[] = { 0x12, 0x34 };
    size_t i = 0;
    int w = 4;
    uint8_t coefficient = coef(S, i, w);
    printf("coef: %u\n", coefficient);


    // LMOTS private key generation example
    lmots_private_key_t *priv_key;

    const lmots_param_t *params = lmots_get_params(1); // Example typecode for LMOTS_SHA256_N32_W2
    uint32_t q = 0; // Example leaf index
    priv_key = lmots_generate_private_key(params, q);
    if (priv_key) {
        printf("Private key generated successfully\n");
        printf("Typecode: %u\n", priv_key->params->typecode);
        printf("Leaf index: %u\n", priv_key->q);
        // print the private key values
        for (uint16_t i = 0; i < priv_key->params->p; i++) {
            printf("x[%u]: ", i);
            for (size_t j = 0; j < LMOTS_N; j++) {
                printf("%02x", priv_key->x[i][j]);
            }
            printf("\n");
        }
        // Free the private key
        lmots_free_private_key(priv_key);
    } else {
        printf("Failed to generate private key\n");
    }



    return 0;
}
