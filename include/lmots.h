# ifndef LMOTS_H
# define LMOTS_H


# include <stdint.h>
# include <stdlib.h>
# include <openssl/rand.h>
# include <string.h>
# include "hash.h"

# define LMOTS_PARAM_COUNT 4
# define LMOTS_N 32            // Length of the hash output in bytes (sha256)
# define D_PBLC 0X8080         // as per rfc8554
# define D_MESG 0X8181         // as per rfc8554
# define LMOTS_I_LEN 16        // Length of LMOTS_I in bytes
# define Q_LEN 4               // Length of q in bytes
# define HASH_PREFIX_LEN 2     // Length of D_PBLC and D_MESG in bytes

typedef struct
{
    uint32_t typecode; // Typecode
    uint8_t w;         // Winternitz parameter
    uint16_t p;        // Number of hash chains
    uint8_t ls;        // Left shift used in checksum
} lmots_param_t;


const lmots_param_t *lmots_get_params(uint32_t typecode);

// -- Private Key --

typedef struct {
    const lmots_param_t *params;
    uint32_t q;                    // Leaf index
    uint8_t **x;                   // p x n-byte secret values
} lmots_private_key_t;

// -- Public Key --

typedef struct {
    const lmots_param_t *params;
    uint32_t q;                   // Leaf index
    uint8_t K[LMOTS_N];           // Public key value
} lmots_public_key_t;

// -- Signature --

typedef struct {
    const lmots_param_t *params;
    uint8_t C[LMOTS_N];           // Randomizer
    uint8_t **y;                  // p x n-byte signature values
} lmots_signature_t;

// -- API --

lmots_private_key_t *lmots_generate_private_key(const lmots_param_t *params, uint32_t q);
void lmots_free_private_key(lmots_private_key_t *key);

lmots_public_key_t *lmots_generate_public_key(const lmots_private_key_t *priv);
void lmots_free_public_key(lmots_public_key_t *pub);

lmots_signature_t *lmots_sign(const lmots_private_key_t *priv, const uint8_t *message, size_t msg_len);
void lmots_free_signature(lmots_signature_t *sig);

int lmots_verify(const lmots_public_key_t *pub, const uint8_t *message, size_t msg_len, const lmots_signature_t *sig);

// -- Utility Functions --
uint16_t checksum(const uint8_t *q, const lmots_param_t *params);

#endif // LMOTS_H