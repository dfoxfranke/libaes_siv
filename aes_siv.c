/* Copyright (c) 2017 Akamai Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "aes_siv.h"

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#ifdef AES_SIV_DEBUG
#include <stdio.h>
#endif
#include <string.h>

#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#if CHAR_BIT != 8
#error "libaes_siv requires an 8-bit char type"
#endif

#if - 1 != ~0
#error "libaes_siv requires a two's-complement architecture"
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901
#undef inline
#elif defined(__GNUC__) || defined(__clang__)
#define inline __inline__
#elif defined(_MSC_VER)
#define inline __inline
#else
#define inline
#endif

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(cond) __builtin_expect(cond, 1)
#define UNLIKELY(cond) __builtin_expect(cond, 0)
#else
#define LIKELY(cond) cond
#define UNLIKELY(cond) cond
#endif

static void debug(const char *label, const unsigned char *hex, size_t len) {
#ifdef AES_SIV_DEBUG
        size_t i;
        printf("%16s: ", label);
        for (i = 0; i < len; i++) {
                if (i > 0 && i % 16 == 0) {
                        printf("\n                  ");
                }
                printf("%.2hhx", hex[i]);
                if (i > 0 && i % 4 == 3) {
                        printf(" ");
                }
        }
        printf("\n");
#else
        (void)label;
        (void)hex;
        (void)len;
#endif
}

typedef union block_un {
        uint64_t word[2];
        unsigned char byte[16];
} block;

const union {
        uint32_t word;
        char byte;
} endian = {0x01020304};

#if defined(__GNUC__) || defined(__clang__)
static inline uint64_t bswap64(uint64_t x) { return __builtin_bswap64(x); }
#elif defined(_MSC_VER)
static inline uint64_t bswap64(uint64_t x) { return __byteswap_uint64(x); }
#else

static inline uint32_t rotl(uint32_t x) { return (x << 8) | (x >> 24); }
static inline uint32_t rotr(uint32_t x) { return (x >> 8) | (x << 24); }

static inline uint64_t bswap64(uint64_t x) {
        uint32_t high = (uint32_t)(x >> 32);
        uint32_t low = (uint32_t)x;

        high = (rotl(high) & 0x00ff00ff) | (rotr(high) & 0xff00ff00);
        low = (rotl(low) & 0x00ff00ff) | (rotr(low) & 0xff00ff00);
        return ((uint64_t)low) << 32 | (uint64_t)high;
}
#endif

static inline uint64_t getword(block const *block, size_t i) {
#ifndef AES_SIV_DEBUG_WEIRD_ENDIAN
        if (endian.byte == 0x01) {
                return block->word[i];
        } else if (endian.byte == 0x04) {
                return bswap64(block->word[i]);
        } else {
#endif
                i <<= 3;
                return ((uint64_t)block->byte[i + 7]) |
                       ((uint64_t)block->byte[i + 6] << 8) |
                       ((uint64_t)block->byte[i + 5] << 16) |
                       ((uint64_t)block->byte[i + 4] << 24) |
                       ((uint64_t)block->byte[i + 3] << 32) |
                       ((uint64_t)block->byte[i + 2] << 40) |
                       ((uint64_t)block->byte[i + 1] << 48) |
                       ((uint64_t)block->byte[i] << 56);
#ifndef AES_SIV_DEBUG_WEIRD_ENDIAN
        }
#endif
}

static inline void putword(block *block, size_t i, uint64_t x) {
#ifndef AES_SIV_DEBUG_WEIRD_ENDIAN
        if (endian.byte == 0x01) {
                block->word[i] = x;
        } else if (endian.byte == 0x04) {
                block->word[i] = bswap64(x);
        } else {
#endif
                i <<= 3;
                block->byte[i] = (unsigned char)(x >> 56);
                block->byte[i + 1] = (unsigned char)((x >> 48) & 0xff);
                block->byte[i + 2] = (unsigned char)((x >> 40) & 0xff);
                block->byte[i + 3] = (unsigned char)((x >> 32) & 0xff);
                block->byte[i + 4] = (unsigned char)((x >> 24) & 0xff);
                block->byte[i + 5] = (unsigned char)((x >> 16) & 0xff);
                block->byte[i + 6] = (unsigned char)((x >> 8) & 0xff);
                block->byte[i + 7] = (unsigned char)(x & 0xff);
#ifndef AES_SIV_DEBUG_WEIRD_ENDIAN
        }
#endif
}

static inline void ctrinc(block *block) {
        putword(block, 1, getword(block, 1) + 1);
}

static inline void xorblock(block *x, block const *y) {
        x->word[0] ^= y->word[0];
        x->word[1] ^= y->word[1];
}

/* Doubles `block`, which is 16 bytes representing an element
   of GF(2**128) modulo the irreducible polynomial
   x**128 + x**7 + x**2 + x + 1. */
static inline void dbl(block *block) {
        uint64_t high = getword(block, 0);
        uint64_t low = getword(block, 1);
        uint64_t high_carry = high & (UINT64_C(1) << 63);
        uint64_t low_carry = low & (UINT64_C(1) << 63);
        /* Assumes two's-complement arithmetic */
        int64_t low_mask = -((int64_t)(high_carry >> 63)) & 0x87;
        uint64_t high_mask = low_carry >> 63;
        high = (high << 1) | high_mask;
        low = (low << 1) ^ (uint64_t)low_mask;
        putword(block, 0, high);
        putword(block, 1, low);
}

struct AES_SIV_CTX_st {
        AES_KEY aes_key;
        /* SIV_AES_Init() sets up cmac_ctx_init. cmac_ctx is a scratchpad used
           by SIV_AES_AssociateData() and SIV_AES_(En|De)cryptFinal. */
        CMAC_CTX *cmac_ctx_init, *cmac_ctx;
        /* d stores intermediate results of S2V; it corresponds to D from the
           pseudocode in section 2.4 of RFC 5297. */
        block d;
};

void AES_SIV_CTX_cleanup(AES_SIV_CTX *ctx) {
        OPENSSL_cleanse(&ctx->aes_key, sizeof ctx->aes_key);
        CMAC_CTX_cleanup(ctx->cmac_ctx_init);
        CMAC_CTX_cleanup(ctx->cmac_ctx);
        OPENSSL_cleanse(&ctx->d, sizeof ctx->d);
}

void AES_SIV_CTX_free(AES_SIV_CTX *ctx) {
        if (ctx) {
                CMAC_CTX_free(ctx->cmac_ctx_init);
                CMAC_CTX_free(ctx->cmac_ctx);
                OPENSSL_free(ctx);
        }
}

AES_SIV_CTX *AES_SIV_CTX_new() {
        AES_SIV_CTX *ctx = OPENSSL_malloc(sizeof(struct AES_SIV_CTX_st));
        if (UNLIKELY(ctx == NULL)) {
                return NULL;
        }

        ctx->cmac_ctx_init = CMAC_CTX_new();
        ctx->cmac_ctx = CMAC_CTX_new();

        if (UNLIKELY(ctx->cmac_ctx_init == NULL || ctx->cmac_ctx == NULL)) {
                AES_SIV_CTX_free(ctx);
                return NULL;
        }

        return ctx;
}

int AES_SIV_CTX_copy(AES_SIV_CTX *dst, AES_SIV_CTX const *src) {
        memcpy(&dst->aes_key, &src->aes_key, sizeof src->aes_key);
        if (CMAC_CTX_copy(dst->cmac_ctx_init, src->cmac_ctx_init) != 1)
                return 0;
        /* Not necessary to copy cmac_ctx since it's just temporary storage */
        memcpy(&dst->d, &src->d, sizeof src->d);
        return 1;
}

int AES_SIV_Init(AES_SIV_CTX *ctx, unsigned char const *key, size_t key_len) {
        const static unsigned char zero[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0};
        size_t out_len;

        switch (key_len) {
        case 32:
                if (UNLIKELY(CMAC_Init(ctx->cmac_ctx_init, key, 16,
                                       EVP_aes_128_cbc(), NULL) != 1)) {
                        return 0;
                }
                if (UNLIKELY(AES_set_encrypt_key(key + 16, 128,
                                                 &ctx->aes_key) != 0)) {
                        return 0;
                }
                break;
        case 48:
                if (UNLIKELY(CMAC_Init(ctx->cmac_ctx_init, key, 24,
                                       EVP_aes_192_cbc(), NULL) != 1)) {
                        return 0;
                }
                if (UNLIKELY(AES_set_encrypt_key(key + 24, 192,
                                                 &ctx->aes_key) != 0)) {
                        return 0;
                }

                break;
        case 64:
                if (UNLIKELY(CMAC_Init(ctx->cmac_ctx_init, key, 32,
                                       EVP_aes_256_cbc(), NULL) != 1)) {
                        return 0;
                }
                if (UNLIKELY(AES_set_encrypt_key(key + 32, 256,
                                                 &ctx->aes_key) != 0)) {
                        return 0;
                }
                break;
        default:
                return 0;
        }

        if (UNLIKELY(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)) {
                return 0;
        }
        if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, zero, sizeof zero) != 1)) {
                return 0;
        }
        out_len = sizeof ctx->d;
        if (UNLIKELY(CMAC_Final(ctx->cmac_ctx, ctx->d.byte, &out_len) != 1)) {
                return 0;
        }
        debug("CMAC(zero)", ctx->d.byte, out_len);
        return 1;
}

int AES_SIV_AssociateData(AES_SIV_CTX *ctx, unsigned char const *data,
                          size_t len) {
        block cmac_out;
        size_t out_len = sizeof cmac_out;
        int ret = 0;

        dbl(&ctx->d);
        debug("double()", ctx->d.byte, 16);

        if (UNLIKELY(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)) {
                goto done;
        }
        if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, data, len) != 1)) {
                goto done;
        }
        if (UNLIKELY(CMAC_Final(ctx->cmac_ctx, cmac_out.byte, &out_len) != 1)) {
                goto done;
        }
        assert(out_len == 16);
        debug("CMAC(ad)", cmac_out.byte, 16);

        xorblock(&ctx->d, &cmac_out);
        debug("xor", ctx->d.byte, 16);
        ret = 1;

done:
        OPENSSL_cleanse(&cmac_out, sizeof cmac_out);
        return ret;
}

int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx, unsigned char *v_out,
                         unsigned char *c_out, unsigned char const *plaintext,
                         size_t len) {
        block t, q, ctmp, ptmp;
        size_t out_len = sizeof q;
        int ret = 0;

#if SIZE_MAX > UINT64_C(0xffffffffffffffff)
        if (UNLIKELY(len >= ((size_t)1) << 67)) {
                goto done;
        }
#endif

        if (UNLIKELY(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)) {
                goto done;
        }
        if (len >= 16) {
                if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, plaintext, len - 16) !=
                             1)) {
                        goto done;
                }
                debug("xorend part 1", plaintext, len - 16);
                memcpy(&t, plaintext + (len - 16), 16);
                xorblock(&t, &ctx->d);
                debug("xorend part 2", t.byte, 16);
                if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, t.byte, 16) != 1)) {
                        goto done;
                }
        } else {
                size_t i;
                memcpy(&t, plaintext, len);
                t.byte[len] = 0x80;
                for (i = len + 1; i < 16; i++)
                        t.byte[i] = 0;
                debug("pad", t.byte, 16);
                dbl(&ctx->d);
                xorblock(&t, &ctx->d);
                debug("xor", t.byte, 16);
                if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, t.byte, 16) != 1)) {
                        goto done;
                }
        }
        if (UNLIKELY(CMAC_Final(ctx->cmac_ctx, q.byte, &out_len) != 1)) {
                goto done;
        }
        assert(out_len == 16);
        debug("CMAC(final)", q.byte, 16);

        memcpy(v_out, &q, 16);
        q.byte[8] &= 0x7f;
        q.byte[12] &= 0x7f;

        while (len >= 16) {
                memcpy(&ptmp, plaintext, 16);
                debug("CTR", q.byte, 16);
                AES_encrypt(q.byte, ctmp.byte, &ctx->aes_key);
                debug("E(K,CTR)", ctmp.byte, 16);
                xorblock(&ctmp, &ptmp);
                memcpy(c_out, &ctmp, 16);
                c_out += 16;
                plaintext += 16;
                len -= 16;
                ctrinc(&q);
        }

        if (len > 0) {
                memcpy(&t, plaintext, len);
                debug("CTR", q.byte, 16);
                AES_encrypt(q.byte, q.byte, &ctx->aes_key);
                debug("E(K,CTR)", q.byte, 16);
                xorblock(&t, &q);
                debug("ciphertext", t.byte, len);
                memcpy(c_out, &t, len);
        }

        ret = 1;
done:
        OPENSSL_cleanse(&t, sizeof t);
        OPENSSL_cleanse(&q, sizeof q);
        OPENSSL_cleanse(&ctmp, sizeof ctmp);
        OPENSSL_cleanse(&ptmp, sizeof ptmp);
        return ret;
}

int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, unsigned char *out,
                         unsigned char const *v, unsigned char const *c,
                         size_t len) {
        block t, q, ctmp, ptmp;
        unsigned char *orig_out = out;
        size_t orig_len = len;
        size_t out_len = sizeof q;
        size_t i;
        int ret = 0;

#if SIZE_MAX > UINT64_C(0xffffffffffffffff)
        if (UNLIKELY(len >= ((size_t)1) << 67))
                goto done;
#endif

        memcpy(&q, v, 16);
        q.byte[8] &= 0x7f;
        q.byte[12] &= 0x7f;

        while (len >= 16) {
                memcpy(&ctmp, c, 16);
                debug("CTR", q.byte, 16);
                AES_encrypt(q.byte, ptmp.byte, &ctx->aes_key);
                debug("E(K,CTR)", ptmp.byte, 16);
                xorblock(&ptmp, &ctmp);
                debug("plaintext", ptmp.byte, 16);
                memcpy(out, &ptmp, 16);
                out += 16;
                c += 16;
                len -= 16;
                ctrinc(&q);
        }

        if (len > 0) {
                memcpy(&t, c, len);
                debug("CTR", q.byte, 16);
                AES_encrypt(q.byte, q.byte, &ctx->aes_key);
                debug("E(K,CTR)", q.byte, 16);
                xorblock(&t, &q);
                debug("plaintext", t.byte, len);
                memcpy(out, &t, len);
        }

        len = orig_len;
        out = orig_out;
        if (UNLIKELY(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1)) {
                goto done;
        }
        if (len >= 16) {
                debug("xorend part 1", out, len - 16);
                if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, out, len - 16) != 1)) {
                        goto done;
                }
                memcpy(&t, out + (len - 16), 16);
                xorblock(&t, &ctx->d);
                debug("xorend part 2", t.byte, 16);
                if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, t.byte, 16) != 1)) {
                        goto done;
                }
        } else {
                memcpy(&t, out, len);
                t.byte[len] = 0x80;
                for (i = len + 1; i < 16; i++)
                        t.byte[i] = 0;
                debug("pad", t.byte, 16);
                dbl(&ctx->d);
                xorblock(&t, &ctx->d);
                debug("xor", t.byte, 16);
                if (UNLIKELY(CMAC_Update(ctx->cmac_ctx, t.byte, 16) != 1)) {
                        goto done;
                }
        }

        if (UNLIKELY(CMAC_Final(ctx->cmac_ctx, t.byte, &out_len) != 1)) {
                goto done;
        }
        debug("CMAC(final)", t.byte, 16);
        assert(out_len == 16);

        for (i = 0; i < 16; i++)
                t.byte[i] ^= v[i];
        ret = (t.word[0] | t.word[1]) == UINT64_C(0);
done:
        OPENSSL_cleanse(&t, sizeof t);
        OPENSSL_cleanse(&q, sizeof q);
        OPENSSL_cleanse(&ctmp, sizeof ctmp);
        OPENSSL_cleanse(&ptmp, sizeof ptmp);
        return ret;
}

int AES_SIV_Encrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *plaintext, size_t plaintext_len,
                    unsigned char const *ad, size_t ad_len) {
        if (UNLIKELY(*out_len < plaintext_len + 16)) {
                return 0;
        }
        *out_len = plaintext_len + 16;

        if (UNLIKELY(AES_SIV_Init(ctx, key, key_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_AssociateData(ctx, ad, ad_len) != 1)) {
                return 0;
        }
        if (nonce != NULL &&
            UNLIKELY(AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_EncryptFinal(ctx, out, out + 16, plaintext,
                                          plaintext_len) != 1)) {
                return 0;
        }
        debug("IV || C", out, *out_len);

        return 1;
}

int AES_SIV_Decrypt(AES_SIV_CTX *ctx, unsigned char *out, size_t *out_len,
                    unsigned char const *key, size_t key_len,
                    unsigned char const *nonce, size_t nonce_len,
                    unsigned char const *ciphertext, size_t ciphertext_len,
                    unsigned char const *ad, size_t ad_len) {
        if (UNLIKELY(ciphertext_len < 16)) {
                return 0;
        }
        if (UNLIKELY(*out_len < ciphertext_len - 16)) {
                return 0;
        }
        *out_len = ciphertext_len - 16;

        if (UNLIKELY(AES_SIV_Init(ctx, key, key_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_AssociateData(ctx, ad, ad_len) != 1)) {
                return 0;
        }
        if (nonce != NULL &&
            UNLIKELY(AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1)) {
                return 0;
        }
        if (UNLIKELY(AES_SIV_DecryptFinal(ctx, out, ciphertext, ciphertext + 16,
                                          ciphertext_len - 16) != 1)) {
                return 0;
        }
        debug("plaintext", out, *out_len);
        return 1;
}
