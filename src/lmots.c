# include "../include/lmots.h"
# include "../include/utils.h"
# include <stdio.h>

static const lmots_param_t lmots_params_sets[LMOTS_PARAM_COUNT] = {
    {1, 1, 265, 7},  // LMOTS_SHA256_N32_W1
    {2, 2, 133, 6},  // LMOTS_SHA256_N32_W2
    {3, 4, 67,  4},  // LMOTS_SHA256_N32_W4
    {4, 8, 34,  0},  // LMOTS_SHA256_N32_W8
};

// In this implementation, the tree identifier can be static since it's going to be just one in LMS
static const uint8_t LMOTS_I[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
};

const lmots_param_t *lmots_get_params(uint32_t typecode){
    for (int i = 0; i < LMOTS_PARAM_COUNT; i++) {
        if (lmots_params_sets[i].typecode == typecode) {
            return &lmots_params_sets[i];
        }
    }
    handle_error("Invalid typecode");
    return NULL; // This line will never be reached due to the error handling above, used to avoid compiler warnings.
}

// Private key generation
lmots_private_key_t *lmots_generate_private_key(const lmots_param_t *params, uint32_t q) {
    lmots_private_key_t *key = malloc(sizeof(lmots_private_key_t));
    if (!key) {
        handle_error("Memory allocation failed for private key");
    }
    key->params = params;
    key->q = q;

    // Allocate memory for the x array
    key->x = malloc(params->p * sizeof(uint8_t *));
    if (!key->x) {
        handle_error("Memory allocation failed for x array");
    }

    // Allocate memory for each element in the x array
    for (uint16_t i = 0; i < params->p; i++) {
        key->x[i] = malloc(LMOTS_N);
        if (!key->x[i]) {
            handle_error("Memory allocation failed for x[i]");
        }
        // Compute the random value for x[i]
        if (RAND_bytes(key->x[i], LMOTS_N) != 1) {
            handle_error_ssl();
        }
    }

    return key;
}

// Free the private key
void lmots_free_private_key(lmots_private_key_t *key) {
    if (key) {
        for (uint16_t i = 0; i < key->params->p; i++) {
            free(key->x[i]);
        }
        free(key->x);
        free(key);
    }
}

// Public key generation