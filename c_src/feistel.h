#ifndef FEISTEL_H
#define FEISTEL_H

#include <stddef.h>
#include <stdint.h>

// Opaque context
typedef struct FeistelCtx FeistelCtx;

// Create context. master_key copied internally.
// block_size must be even and <= 32. rounds >= 1
FeistelCtx *feistel_create(const uint8_t *master_key, size_t master_key_len,
                           unsigned rounds, unsigned block_size);
// Free context
void feistel_free(FeistelCtx *ctx);

// Encrypt input buffer (arbitrary length) -> output allocated by function.
// out_len set to ciphertext length. Caller must free(*out).
// Returns 0 on success, non-zero on error.
int feistel_encrypt(FeistelCtx *ctx, const uint8_t *in, size_t in_len,
                    uint8_t **out, size_t *out_len);

// Decrypt input buffer -> plaintext allocated by function. Caller frees(*out).
int feistel_decrypt(FeistelCtx *ctx, const uint8_t *in, size_t in_len,
                    uint8_t **out, size_t *out_len);

// Utility: print hex
void print_hex(const uint8_t *buf, size_t len);

#endif // FEISTEL_H
