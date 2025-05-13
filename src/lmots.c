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

// Checksum function as per RFC 8554 section 4.4
uint16_t checksum(const uint8_t *q, const lmots_param_t *params) {
    uint16_t checksum = 0;
    for (uint16_t i = 0; i < (LMOTS_N * 8)/ params->w; i++) {
        checksum += ((1 << params->w) -1) - (coef(q, i, params->w));
    }

    return checksum << params->ls;
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
lmots_public_key_t *lmots_generate_public_key(const lmots_private_key_t *priv) {
    lmots_public_key_t *pub = malloc(sizeof(lmots_public_key_t));

    if (!pub) {
        handle_error("Memory allocation failed for public key");
    }
    pub->params = priv->params;
    pub->q = priv->q;

    uint8_t **y = malloc(priv->params->p * sizeof(uint8_t *));
    if (!y) {
        handle_error("Memory allocation failed for y array");
    }

    uint16_t steps = (1 << pub->params->w) - 1; // Here for efficiency


    for (uint16_t i = 0; i < pub->params->p; i++) {
        
        // Allocate memory for element i in the y array
        y[i] = malloc(LMOTS_N);
        if (!y[i]) {
            handle_error("Memory allocation failed for y[i]");
        }

        uint8_t tmp[LMOTS_N];
        memcpy(tmp, priv->x[i], LMOTS_N);

        // Compute the hash of the concatenation
        // hash inpyt is LMOTS_I || q || i || j || tmp
        // therefore 16 + 4 + 2 + 1 + 32 = 55
        uint8_t hash_input[LMOTS_I_LEN + Q_LEN + sizeof(i) + 1 + LMOTS_N];
        if ( i == 4 ) printf("total size: %zu\n", sizeof(hash_input));

        for (uint16_t j = 0; j < steps; j++) {
            memcpy(hash_input, LMOTS_I, LMOTS_I_LEN);
            u32str(priv->q, &hash_input[LMOTS_I_LEN]);
            u16str(i, &hash_input[LMOTS_I_LEN + Q_LEN]);
            u8str(j, &hash_input[LMOTS_I_LEN + Q_LEN + sizeof(i)]);
            memcpy(&hash_input[LMOTS_I_LEN + Q_LEN + sizeof(i) + 1], tmp, LMOTS_N);
            // Compute the hash
            sha256(hash_input, sizeof(hash_input), tmp);
        }
        // Copy the hash result to y[i]
        memcpy(y[i], tmp, LMOTS_N);
    }

    // Compute K = H(LMOTS_I || q || D_PBLC || y[0] || y[1] || ... || y[p-1])
    uint8_t hash_input2[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN + (LMOTS_N * priv->params->p)];
    memcpy(hash_input2, LMOTS_I, LMOTS_I_LEN);
    u32str(priv->q, &hash_input2[LMOTS_I_LEN]);
    hash_input2[LMOTS_I_LEN + Q_LEN] = D_PBLC >> 8;
    hash_input2[LMOTS_I_LEN + Q_LEN + 1] = D_PBLC & 0xFF;
    for (uint16_t i = 0; i < priv->params->p; i++) {
        memcpy(&hash_input2[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN + (i * LMOTS_N)], y[i], LMOTS_N);
    }

    // Compute the hash
    sha256(hash_input2, sizeof(hash_input2), pub->K);

    // Free the y array
    for (uint16_t i = 0; i < priv->params->p; i++) {
        free(y[i]);
    }
    free(y);

    return pub;
}

// Free the public key
void lmots_free_public_key(lmots_public_key_t *pub) {
    if (pub) {
        free(pub);
    }
}

// Signature generation
lmots_signature_t *lmots_sign(const lmots_private_key_t *priv, const uint8_t *message, size_t msg_len) {
    lmots_signature_t *sig = malloc(sizeof(lmots_signature_t));
    if (!sig) {
        handle_error("Memory allocation failed for signature");
    }
    sig->params = priv->params;

    // Set C to a uniformly random n-byte value
    if (RAND_bytes(sig->C, LMOTS_N) != 1) {
        handle_error_ssl();
    }

    uint8_t q[LMOTS_N];

    uint8_t hash_input[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN + LMOTS_N + msg_len];
    memcpy(hash_input, LMOTS_I, LMOTS_I_LEN);
    u32str(priv->q, &hash_input[LMOTS_I_LEN]);
    hash_input[LMOTS_I_LEN + Q_LEN] = D_MESG >> 8;
    hash_input[LMOTS_I_LEN + Q_LEN + 1] = D_MESG & 0xFF;
    memcpy(&hash_input[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN], sig->C, LMOTS_N);
    memcpy(&hash_input[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN + LMOTS_N], message, msg_len);
    
    // Compute the hash
    sha256(hash_input, sizeof(hash_input), q);

    // Allocate memory for the y array
    sig->y = malloc(priv->params->p * sizeof(uint8_t *));
    if (!sig->y) {
        handle_error("Memory allocation failed for y array");
    }


    for (uint16_t i = 0; i < priv->params->p; i++) {
        // Allocate memory for element i in the y array
        sig->y[i] = malloc(LMOTS_N);
        if (!sig->y[i]) {
            handle_error("Memory allocation failed for y[i]");
        }

        // a = coef(q || checksum(q), i, w)
        // Compute the checksum
        uint16_t cs = checksum(q, sig->params);
        uint8_t coef_input[LMOTS_N + sizeof(cs)];
        memcpy(coef_input, q, LMOTS_N);
        u16str(cs, &coef_input[LMOTS_N]);
        uint64_t a = coef(coef_input, i, sig->params->w);

        uint8_t tmp[LMOTS_N];
        memcpy(tmp, priv->x[i], LMOTS_N);

        uint8_t hash_input2[LMOTS_I_LEN + Q_LEN + sizeof(i) + 1 + LMOTS_N];

        // Compute the hash of the concatenation
        // hash input is LMOTS_I || q || i || j || tmp
        for (uint64_t j = 0; j < a; j++) {
            memcpy(hash_input2, LMOTS_I, LMOTS_I_LEN);
            u32str(priv->q, &hash_input2[LMOTS_I_LEN]);
            u16str(i, &hash_input2[LMOTS_I_LEN + Q_LEN]);
            u8str(j, &hash_input2[LMOTS_I_LEN + Q_LEN + sizeof(i)]);
            memcpy(&hash_input2[LMOTS_I_LEN + Q_LEN + sizeof(i) + 1], tmp, LMOTS_N);
            // Compute the hash
            sha256(hash_input2, sizeof(hash_input2), tmp);
        }
        // Copy the hash result to y[i]
        memcpy(sig->y[i], tmp, LMOTS_N);
    }

    return sig;
}

// Free the signature
void lmots_free_signature(lmots_signature_t *sig) {
    if (sig) {
        for (uint16_t i = 0; i < sig->params->p; i++) {
            free(sig->y[i]);
        }
        free(sig->y);
        free(sig);
    }
}

// Verify a Signature and Message using a public key
int lmots_verify(const lmots_public_key_t *pub, const uint8_t *message, size_t msg_len, const lmots_signature_t *sig){

    // Check for null pointers
    if (!pub || !sig || !message) {
        handle_error("Null input to lmots_verify");
        return -1;
    }

    /* // Uncomment this section if you want to check the parameters
    if (sig->params->typecode != pub->params->typecode) {
        handle_error("Signature and public key typecodes do not match");
        return -1;
    }
    if (sig->params->p != pub->params->p || sig->params->w != pub->params->w || sig->params->ls != pub->params->ls) {
        handle_error("Signature and public key parameters do not match");
        return -1;
    }
    */

    // TODO: Check signature length, must be exactly 4 + n * (p + 1) bytes long
    

    // Compute public key candidate
    // Note: Parameters I, q, K and C should be parsed from the signature when it is serialized (e.g from a network buffer).
    // This implementation is not meant for serialization, so we take the values from the public key.
    lmots_public_key_t *pub_candidate = malloc(sizeof(lmots_public_key_t));
    if (!pub_candidate) {
        handle_error("Memory allocation failed for public key candidate");
    }
    pub_candidate->params = pub->params;
    pub_candidate->q = pub->q;
    memcpy(pub_candidate->K, pub->K, LMOTS_N);

    uint8_t q[LMOTS_N];

    uint8_t hash_input[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN + LMOTS_N + msg_len];
    memcpy(hash_input, LMOTS_I, LMOTS_I_LEN);
    u32str(pub->q, &hash_input[LMOTS_I_LEN]);
    hash_input[LMOTS_I_LEN + Q_LEN] = D_MESG >> 8;
    hash_input[LMOTS_I_LEN + Q_LEN + 1] = D_MESG & 0xFF;
    memcpy(&hash_input[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN], sig->C, LMOTS_N);
    memcpy(&hash_input[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN + LMOTS_N], message, msg_len);
    
    // Compute the hash
    sha256(hash_input, sizeof(hash_input), q);

    // Allocate memory for the z array
    uint8_t **z = malloc(pub->params->p * sizeof(uint8_t *));
    if (!z) {
        handle_error("Memory allocation failed for z array");
    }

    for (uint16_t i = 0; i < pub->params->p; i++) {

        // Allocate memory for element i in the z array
        z[i] = malloc(LMOTS_N);
        if (!z[i]) {
            handle_error("Memory allocation failed for z[i]");
        }

        // a = coef(q || checksum(q), i, w)
        // Compute the checksum
        uint16_t cs = checksum(q, sig->params);
        uint8_t coef_input[LMOTS_N + sizeof(cs)];
        memcpy(coef_input, q, LMOTS_N);
        u16str(cs, &coef_input[LMOTS_N]);
        uint64_t a = coef(coef_input, i, sig->params->w);

        uint8_t tmp[LMOTS_N];
        memcpy(tmp, sig->y[i], LMOTS_N);

        uint8_t hash_input2[LMOTS_I_LEN + Q_LEN + sizeof(i) + 1 + LMOTS_N];
        
        // Compute the hash of the concatenation
        // hash input is LMOTS_I || q || i || j || tmp
        for (uint64_t j = a; j < ((uint64_t)(1 << pub->params->w) - 1); j++) {

            memcpy(hash_input2, LMOTS_I, LMOTS_I_LEN);
            u32str(pub->q, &hash_input2[LMOTS_I_LEN]);
            u16str(i, &hash_input2[LMOTS_I_LEN + Q_LEN]);
            u8str(j, &hash_input2[LMOTS_I_LEN + Q_LEN + sizeof(i)]);
            memcpy(&hash_input2[LMOTS_I_LEN + Q_LEN + sizeof(i) + 1], tmp, LMOTS_N);
            // Compute the hash
            sha256(hash_input2, sizeof(hash_input2), tmp);
        }

        // Copy the hash result to z[i]
        memcpy(z[i], tmp, LMOTS_N);
    }

    // Compute K' = H(LMOTS_I || q || D_PBLC || z[0] || z[1] || ... || z[p-1])
    uint8_t hash_input3[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN + (LMOTS_N * pub->params->p)];
    memcpy(hash_input3, LMOTS_I, LMOTS_I_LEN);
    u32str(pub->q, &hash_input3[LMOTS_I_LEN]);
    hash_input3[LMOTS_I_LEN + Q_LEN] = D_PBLC >> 8;
    hash_input3[LMOTS_I_LEN + Q_LEN + 1] = D_PBLC & 0xFF;
    for (uint16_t i = 0; i < pub->params->p; i++) {
        memcpy(&hash_input3[LMOTS_I_LEN + Q_LEN + HASH_PREFIX_LEN + (i * LMOTS_N)], z[i], LMOTS_N);
    }
    // Compute the hash
    sha256(hash_input3, sizeof(hash_input3), pub_candidate->K);

    // DEBUG Print K' and K values
    printf("K': ");
    for (size_t j = 0; j < LMOTS_N; j++) {
        printf("%02x", pub_candidate->K[j]);
    }
    printf("\nK : ");
    for (size_t j = 0; j < LMOTS_N; j++) {
        printf("%02x", pub->K[j]);
    }
    printf("\n");

    // Compare K' with K
    if (memcmp(pub_candidate->K, pub->K, LMOTS_N) != 0) {
        // Free allocated memory
        for (uint16_t i = 0; i < pub->params->p; i++) {
            free(z[i]);
        }
        free(z);
        lmots_free_public_key(pub_candidate);
        return -1; // Verification failed
    }

    // Free allocated memory
    for (uint16_t i = 0; i < pub->params->p; i++) {
        free(z[i]);
    }

    free(z);
    free(pub_candidate);
    
    return 0; // Verification succeeded
    
}