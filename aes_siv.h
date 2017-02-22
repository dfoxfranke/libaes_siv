/* Copyright (c) 2017 Akamai Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AES_SIV_H_
#define AES_SIV_H_

#include <stddef.h>
#include <stdint.h>

typedef struct AES_SIV_CTX_st AES_SIV_CTX;

AES_SIV_CTX* AES_SIV_CTX_new();
int AES_SIV_CTX_copy(AES_SIV_CTX *dst, AES_SIV_CTX const* src);
void AES_SIV_CTX_cleanup(AES_SIV_CTX *ctx);
void AES_SIV_CTX_free(AES_SIV_CTX *ctx);

int AES_SIV_Init(AES_SIV_CTX *ctx, uint8_t const* key, size_t key_len);
int AES_SIV_AssociateData(AES_SIV_CTX *ctx, const uint8_t *data, size_t len);
int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx,
                         uint8_t *v_out, uint8_t *c_out,
                         const uint8_t *plaintext, size_t len);
int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, uint8_t *out,
                         uint8_t const* v, uint8_t const *c,
                         size_t len);


int AES_SIV_Encrypt(AES_SIV_CTX *ctx,
                    uint8_t *out, size_t *out_len,
                    uint8_t const* key, size_t key_len,
                    uint8_t const* nonce, size_t nonce_len,
                    uint8_t const* plaintext, size_t plaintext_len,
                    uint8_t const *ad, size_t ad_len);

int AES_SIV_Decrypt(AES_SIV_CTX *ctx,
                    uint8_t *out, size_t *out_len,
                    uint8_t const* key, size_t key_len,
                    uint8_t const* nonce, size_t nonce_len,
                    uint8_t const* ciphertext, size_t ciphertext_len,
                    uint8_t const *ad, size_t ad_len);

#endif
