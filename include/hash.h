#ifndef HASH_H
#define HASH_H
#include <stdint.h>
#include <stddef.h>


# define SHA256_DIGEST_LENGTH 32

void sha256(const uint8_t *data, size_t len, uint8_t *out);
// This function computes the SHA-256 hash of the input data.


#endif // HASH_H