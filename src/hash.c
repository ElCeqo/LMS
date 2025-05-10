# include "../include/hash.h"
# include "../include/utils.h"
# include <openssl/evp.h>
# include <openssl/err.h>



void sha256(const uint8_t *data, size_t len, uint8_t *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if ( ctx == NULL) {
        // Handle error
        handle_error();
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        // Handle error
        EVP_MD_CTX_free(ctx);
        handle_error();
    }
    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        // Handle error
        EVP_MD_CTX_free(ctx);
        handle_error();
    }
    if (EVP_DigestFinal_ex(ctx, out, NULL) != 1) {
        // Handle error
        EVP_MD_CTX_free(ctx);
        handle_error();
    }
    EVP_MD_CTX_free(ctx);
    // No need to free 'out' as it is passed by the caller
}