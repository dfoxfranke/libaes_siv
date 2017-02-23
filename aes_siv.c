/* Copyright (c) 2017 Akamai Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "aes_siv.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#ifdef AES_SIV_DEBUG
#include <stdio.h>
#endif
#include <string.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901
#undef inline
#elif defined(__GNUC__) || defined(__clang__)
#define inline __inline__
#elif defined(_MSC_VER)
#define inline __inline
#else
#define inline
#endif

#if defined(__GNUC__) && __GNUC__ >= 4
#define ATTRIBUTE_UNUSED __attribute__((__unused__))
#elif defined(__clang__)
#define ATTRIBUTE_UNUSED __attribute__((__unused__))
#else
#define ATTRIBUTE_UNUSED
#endif

static void debug(const char *label, const uint8_t *hex, size_t len) {
#ifdef AES_SIV_DEBUG
        size_t i;
        printf("%16s: ", label);
        for(i=0; i<len;i++) {
                if(i > 0 && i%16 == 0) printf("\n                  ");
                printf("%.2hhx", hex[i]);
                if(i>0 && i%4 == 3) printf(" ");

        }
        printf("\n");
#else
        (void)label;
        (void)hex;
        (void)len;
#endif
}

static inline uint64_t be64dec_portable(const void*) ATTRIBUTE_UNUSED;
static inline void be64enc_portable(void*, uint64_t) ATTRIBUTE_UNUSED;

static inline uint64_t be64dec_portable(const void *buf) {
  const uint8_t *b = (const uint8_t*)buf;

  return ((uint64_t)(b[0]) << 56) +
    ((uint64_t)(b[1]) << 48) +
    ((uint64_t)(b[2]) << 40) +
    ((uint64_t)(b[3]) << 32) +
    ((uint64_t)(b[4]) << 24) +
    ((uint64_t)(b[5]) << 16) +
    ((uint64_t)(b[6]) << 8) +
    (uint64_t)(b[7]);
}

static inline void be64enc_portable(void *buf, uint64_t x) {
  uint8_t *b = (uint8_t*)buf;
  
  b[0] = (uint8_t)((x >> 56) & 0xff);
  b[1] = (uint8_t)((x >> 48) & 0xff);
  b[2] = (uint8_t)((x >> 40) & 0xff);
  b[3] = (uint8_t)((x >> 32) & 0xff);
  b[4] = (uint8_t)((x >> 24) & 0xff);
  b[5] = (uint8_t)((x >> 16) & 0xff);
  b[6] = (uint8_t)((x >> 8)  & 0xff);
  b[7] = (uint8_t)x & 0xff;
}

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline void be64enc(void *buf, uint64_t x) {
        uint64_t *b = (uint64_t*)buf;
        *b = x;
}

static inline uint64_t be64dec(void const* buf) {
        uint64_t const* b = (uint64_t const*)buf;
        return *b;
}
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#if defined(__GNUC__) || defined (__clang__)
static inline void be64enc(void *buf, uint64_t x) {
        uint64_t *b = (uint64_t*)buf;
        *b = __builtin_bswap64(x);
}

static inline uint64_t be64dec(void const* buf) {
        uint64_t const* b = (uint64_t const*)buf;
        return __builtin_bswap64(*b);
}
#elif defined(_MSC_VER)
static inline void be64enc(void *buf, uint64_t x) {
        uint64_t *b = (uint64_t*)buf;
        *b = _byteswap_uint64(x);
}

static inline uint64_t be64dec(void const* buf) {
        uint64_t const* b = (uint64_t const*)buf;
        return _byteswap_uint64(x);
}
#else /* not GCC/Clang, not MSVC */
static inline void be64enc(void *buf, uint64_t x) {
        be64enc_portable(buf, x);
}

static inline uint64_t be64dec(void const* buf) {
        return be64dec_portable(buf);
}
#endif
#else /* weird or unspecified byte order */
static inline void be64enc(void *buf, uint64_t x) {
        be64enc_portable(buf, x);
}

static inline uint64_t be64dec(void const* buf) {
        return be64dec_portable(buf);
}
#endif

/* Doubles `block`, which is 16 bytes representing an element
   of GF(2**128) modulo the irreducible polynomial
   x**128 + x**7 + x**2 + x + 1. */
static inline void dbl(void *block) {
        uint8_t *b = block;
        uint64_t high = be64dec(b);
        uint64_t low = be64dec(b + 8);

        uint64_t high_carry = high & (((uint64_t)1)<<63);
        uint64_t low_carry = low & (((uint64_t)1)<<63);
        /* Assumes two's-complement arithmetic */
        int64_t low_mask = -((int64_t)(high_carry>>63)) & 0x87;
        uint64_t high_mask = low_carry >> 63;

        high = (high << 1) | high_mask;
        low = (low << 1) ^ (uint64_t)low_mask;
        be64enc(b, high);
        be64enc(b + 8, low);
}

static inline void xorblock(void *out, const void* with) {
        uint64_t *x = out;
        const uint64_t *y = with;
        x[0] ^= y[0];
        x[1] ^= y[1];
}

struct AES_SIV_CTX_st {
        AES_KEY aes_key;
        CMAC_CTX *cmac_ctx_init, *cmac_ctx;
        uint8_t d[16];
};

void AES_SIV_CTX_cleanup(AES_SIV_CTX *ctx) {
        OPENSSL_cleanse(&ctx->aes_key, sizeof ctx->aes_key);
        CMAC_CTX_cleanup(ctx->cmac_ctx_init);
        CMAC_CTX_cleanup(ctx->cmac_ctx);
        OPENSSL_cleanse(&ctx->d, sizeof ctx->d);
}

void AES_SIV_CTX_free(AES_SIV_CTX *ctx) {
        if(ctx) {
                CMAC_CTX_free(ctx->cmac_ctx_init);
                CMAC_CTX_free(ctx->cmac_ctx);
                OPENSSL_free(ctx);
        }
}

AES_SIV_CTX* AES_SIV_CTX_new() {
        AES_SIV_CTX *ctx = OPENSSL_malloc(sizeof (struct AES_SIV_CTX_st));
        if(ctx == NULL) return NULL;

        ctx->cmac_ctx_init = CMAC_CTX_new();
        ctx->cmac_ctx = CMAC_CTX_new();

        if(ctx->cmac_ctx_init == NULL ||
           ctx->cmac_ctx == NULL) {
                AES_SIV_CTX_free(ctx);
                return NULL;
        }

        return ctx;
}

int AES_SIV_CTX_copy(AES_SIV_CTX *dst, AES_SIV_CTX const* src) {
        memcpy(&dst->aes_key, &src->aes_key, sizeof src->aes_key);
        if(CMAC_CTX_copy(dst->cmac_ctx_init, src->cmac_ctx_init) != 1) return 0;
        /* Not necessary to copy cmac_ctx since it's just temporary storage */
        memcpy(dst->d, src->d, sizeof src->d);
        return 1;
}       

int AES_SIV_Init(AES_SIV_CTX *ctx, uint8_t const* key, size_t key_len) {
        const static uint8_t zero[] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0 };
        size_t out_len;
        
        switch(key_len) {
        case 32:
                if(CMAC_Init(ctx->cmac_ctx_init, key, 16, EVP_aes_128_cbc(), NULL)
                   != 1) return 0;
                if(AES_set_encrypt_key(key + 16, 128, &ctx->aes_key)
                   != 0) return 0;
                break;
        case 48:
                if(CMAC_Init(ctx->cmac_ctx_init, key, 24, EVP_aes_192_cbc(), NULL)
                   != 1) return 0;
                if(AES_set_encrypt_key(key + 24, 192, &ctx->aes_key)
                   != 0) return 0;

                break;
        case 64:
                if(CMAC_Init(ctx->cmac_ctx_init, key, 32, EVP_aes_256_cbc(), NULL)
                   != 1) return 0;
                if(AES_set_encrypt_key(key + 32, 256, &ctx->aes_key)
                   != 0) return 0;
                break;
        default:
                return 0;
        }

        if(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1) return 0;
        if(CMAC_Update(ctx->cmac_ctx, zero, sizeof zero) != 1) return 0;
        out_len = sizeof ctx->d;
        if(CMAC_Final(ctx->cmac_ctx, ctx->d, &out_len) != 1) return 0;
        debug("CMAC(zero)", ctx->d, out_len);
        return 1;
}

int AES_SIV_AssociateData(AES_SIV_CTX *ctx, const uint8_t *data, size_t len) {
        uint8_t cmac_out[16];
        size_t out_len = sizeof cmac_out;

        dbl(ctx->d);
        debug("double()", ctx->d, 16);

        if(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1) goto fail;
        if(CMAC_Update(ctx->cmac_ctx, data, len) != 1) goto fail;
        if(CMAC_Final(ctx->cmac_ctx, cmac_out, &out_len) != 1) goto fail;
        assert(out_len == 16);
        debug("CMAC(ad)", cmac_out, 16);

        xorblock(ctx->d, cmac_out);
        debug("xor", ctx->d, 16);
        OPENSSL_cleanse(cmac_out, sizeof cmac_out);
        return 1;

fail:
        OPENSSL_cleanse(cmac_out, sizeof cmac_out);
        return 0;
}

int AES_SIV_EncryptFinal(AES_SIV_CTX *ctx,
                         uint8_t *v_out, uint8_t *c_out,
                         const uint8_t *plaintext, size_t len) {
        uint8_t t[16], q[16];
        size_t out_len = sizeof q;
        uint64_t ctr;

        if(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1) goto fail;
        if(len >= 16) {
                if(CMAC_Update(ctx->cmac_ctx, plaintext, len-16) != 1) goto fail;
                debug("xorend part 1", plaintext, len-16);
                memcpy(t, plaintext + (len-16), 16);
                xorblock(t, ctx->d);
                debug("xorend part 2", t, 16);
                if(CMAC_Update(ctx->cmac_ctx, t, 16) != 1) goto fail;
        } else {
                size_t i;
                memcpy(t, plaintext, len);
                t[len] = 0x80;
                for(i=len+1; i<16; i++) t[i] = 0;
                debug("pad", t, 16);
                dbl(ctx->d);
                xorblock(t, ctx->d);
                debug("xor", t, 16);
                if(CMAC_Update(ctx->cmac_ctx, t, 16) != 1) goto fail;
        }
        if(CMAC_Final(ctx->cmac_ctx, q, &out_len) != 1) goto fail;
        assert(out_len == 16);
        debug("CMAC(final)", q, 16);

        memcpy(v_out, q, 16);
        q[8] &= 0x7f;
        q[12] &= 0x7f;

        ctr = be64dec(q + 8);
        while(len >= 16) {
                be64enc(q + 8, ctr);
                debug("CTR", q, 16);
                AES_encrypt(q, c_out, &ctx->aes_key);
                debug("E(K,CTR)", c_out, 16);
                xorblock(c_out, plaintext);
                debug("ciphertext", c_out, 16);
                c_out += 16;
                plaintext += 16;
                len -= 16;
                ctr++;
        }

        memcpy(t, plaintext, len);
        debug("CTR", q, 16);
        be64enc(q + 8, ctr);
        AES_encrypt(q, q, &ctx->aes_key);
        debug("E(K,CTR)", q, 16);
        xorblock(t, q);
        debug("ciphertext", t, len);
        memcpy(c_out, t, len);
        OPENSSL_cleanse(t, sizeof t);
        OPENSSL_cleanse(q, sizeof q);
        return 1;

fail:
        OPENSSL_cleanse(t, sizeof t);
        OPENSSL_cleanse(q, sizeof q);
        return 0;
}

int AES_SIV_DecryptFinal(AES_SIV_CTX *ctx, uint8_t *out,
                         uint8_t const* v, uint8_t const *c,
                         size_t len) {
        uint8_t t[16], q[16];
        uint8_t *orig_out = out;
        size_t orig_len = len;
        size_t out_len = sizeof q;
        uint64_t ctr;

        memcpy(q, v, 16);
        q[8] &= 0x7f;
        q[12] &= 0x7f;
        
        ctr = be64dec(q + 8);
        while(len >= 16) {
                be64enc(q + 8, ctr);
                debug("CTR", q, 16);
                AES_encrypt(q, out, &ctx->aes_key);
                debug("E(K,CTR)", q, 16);
                xorblock(out, c);
                debug("plaintext", out, 16);
                out += 16;
                c += 16;
                len -= 16;
                ctr++;
        }

        memcpy(t, c, len);
        be64enc(q + 8, ctr);
        debug("CTR", q, 16);
        AES_encrypt(q, q, &ctx->aes_key);
        debug("E(K,CTR)", q, 16);
        xorblock(t, q);
        debug("plaintext", t, len);
        memcpy(out, t, len);
        OPENSSL_cleanse(t, sizeof t);
        OPENSSL_cleanse(q, sizeof q);

        len = orig_len;
        out = orig_out;
        if(CMAC_CTX_copy(ctx->cmac_ctx, ctx->cmac_ctx_init) != 1) return 0;
        if(len >= 16) {
                debug("xorend part 1", out, len-16);
                if(CMAC_Update(ctx->cmac_ctx, out, len-16)
                   != 1) return 0;
                memcpy(t, out + (len-16), 16);
                xorblock(t, ctx->d);
                debug("xorend part 2", t, 16);
                if(CMAC_Update(ctx->cmac_ctx, t, 16) != 1) return 0;
        } else {
                size_t i;
                memcpy(t, out, len);
                t[len] = 0x80;
                for(i=len+1; i<16; i++) t[i] = 0;
                debug("pad", t, 16);
                dbl(ctx->d);
                xorblock(t, ctx->d);
                debug("xor", t, 16);
                if(CMAC_Update(ctx->cmac_ctx, t, 16) != 1) return 0;
        }
        
        if(CMAC_Final(ctx->cmac_ctx, t, &out_len) != 1) return 0;
        debug("CMAC(final)", t, 16);
        assert(out_len == 16);

        xorblock(t, v);
        return (be64dec(t) | be64dec(t + 8)) == 0;
}
        
int AES_SIV_Encrypt(AES_SIV_CTX *ctx,
                    uint8_t *out, size_t *out_len,
                    uint8_t const* key, size_t key_len,
                    uint8_t const* nonce, size_t nonce_len,
                    uint8_t const* plaintext, size_t plaintext_len,
                    uint8_t const *ad, size_t ad_len) {
        if(*out_len < plaintext_len + 16) return 0;
        *out_len = plaintext_len + 16;
        
        if(AES_SIV_Init(ctx, key, key_len) != 1) return 0;
        if(AES_SIV_AssociateData(ctx, ad, ad_len) != 1) return 0;
        if(nonce != NULL &&
           AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1) return 0;
        if(AES_SIV_EncryptFinal(ctx, out, out+16, plaintext, plaintext_len)
           != 1) return 0;
        debug("IV || C", out, *out_len);

        return 1;
}

int AES_SIV_Decrypt(AES_SIV_CTX *ctx,
                    uint8_t *out, size_t *out_len,
                    uint8_t const* key, size_t key_len,
                    uint8_t const* nonce, size_t nonce_len,
                    uint8_t const* ciphertext, size_t ciphertext_len,
                    uint8_t const *ad, size_t ad_len) {
        if(ciphertext_len < 16) return 0;
        if(*out_len < ciphertext_len - 16) return 0;
        *out_len = ciphertext_len - 16;

        if(AES_SIV_Init(ctx, key, key_len) != 1) return 0;
        if(AES_SIV_AssociateData(ctx, ad, ad_len) != 1) return 0;
        if(nonce != NULL &&
           AES_SIV_AssociateData(ctx, nonce, nonce_len) != 1) return 0;
        if(AES_SIV_DecryptFinal(ctx, out, ciphertext,
                                ciphertext + 16, ciphertext_len - 16)
           != 1) return 0;
        debug("plaintext", out, *out_len);
        return 1;
}

#ifdef AES_SIV_DEBUG
static void test_vector_1() {
        const uint8_t key[] = {
                0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
                0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
                0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
        };

        const uint8_t ad[] = {
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
        };

        const uint8_t plaintext[] = {
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,0x88,
                0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee
        };

        const uint8_t ciphertext[] = {
                0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
                0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
                0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04,
                0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c
        };

        uint8_t ciphertext_out[256];
        uint8_t plaintext_out[256];
        
        size_t plaintext_len = sizeof plaintext_out;
        size_t ciphertext_len = sizeof ciphertext_out;

        AES_SIV_CTX *ctx;
        int ret;

        printf("Test case 1:\n");
        debug("key", key, sizeof key);
        debug("AD", ad, sizeof ad);
        debug("plaintext", plaintext, sizeof plaintext);
        debug("exp. ciphertext", ciphertext, sizeof ciphertext);

        ctx = AES_SIV_CTX_new();
        assert(ctx != NULL);
        
        printf("Encryption:\n");
        ret = AES_SIV_Encrypt(ctx, ciphertext_out, &ciphertext_len,
                              key, sizeof key, NULL, 0,
                              plaintext, sizeof plaintext,
                              ad, sizeof ad);
        assert(ret == 1);
	assert(ciphertext_len == sizeof ciphertext);
	assert(!memcmp(ciphertext, ciphertext_out, ciphertext_len));

        printf("Decryption:\n");
        ret = AES_SIV_Decrypt(ctx, plaintext_out, &plaintext_len,
                              key, sizeof key, NULL, 0,
                              ciphertext_out, ciphertext_len,
                              ad, sizeof ad);
        assert(ret == 1);
        assert(plaintext_len == sizeof plaintext);
	assert(!memcmp(plaintext, plaintext_out, plaintext_len));
	AES_SIV_CTX_cleanup(ctx);
	AES_SIV_CTX_free(ctx);
}

static void test_vector_2() {
        const uint8_t key[] = {
                0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78,
                0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70,
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
        };

        const uint8_t ad1[] = {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                0xde, 0xad, 0xda, 0xda, 0xde, 0xad, 0xda, 0xda,
                0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
                0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
        };

        const uint8_t ad2[] = {
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                0x90, 0xa0
        };

        const uint8_t nonce[] = {
                0x09, 0xf9, 0x11, 0x02, 0x9d, 0x74, 0xe3, 0x5b,
                0xd8, 0x41, 0x56, 0xc5, 0x63, 0x56, 0x88, 0xc0
        };

        const uint8_t plaintext[] = {
                0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
                0x73, 0x6f, 0x6d, 0x65, 0x20, 0x70, 0x6c, 0x61,
                0x69, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x20, 0x74,
                0x6f, 0x20, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70,
                0x74, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20,
                0x53, 0x49, 0x56, 0x2d, 0x41, 0x45, 0x53
        };

        const uint8_t ciphertext[] = {
                0x7b, 0xdb, 0x6e, 0x3b, 0x43, 0x26, 0x67, 0xeb,
                0x06, 0xf4, 0xd1, 0x4b, 0xff, 0x2f, 0xbd, 0x0f,
                0xcb, 0x90, 0x0f, 0x2f, 0xdd, 0xbe, 0x40, 0x43,
                0x26, 0x60, 0x19, 0x65, 0xc8, 0x89, 0xbf, 0x17,
                0xdb, 0xa7, 0x7c, 0xeb, 0x09, 0x4f, 0xa6, 0x63,
                0xb7, 0xa3, 0xf7, 0x48, 0xba, 0x8a, 0xf8, 0x29,
                0xea, 0x64, 0xad, 0x54, 0x4a, 0x27, 0x2e, 0x9c,
                0x48, 0x5b, 0x62, 0xa3, 0xfd, 0x5c, 0x0d
        };
                
        uint8_t ciphertext_out[256];
        uint8_t plaintext_out[256];

        AES_SIV_CTX *ctx;
        int ret;

        printf("Test case 2:\n");
        debug("key", key, sizeof key);
        debug("AD1", ad1, sizeof ad1);
        debug("AD2", ad2, sizeof ad2);
        debug("nonce", nonce, sizeof nonce);
        debug("plaintext", plaintext, sizeof plaintext);
        debug("exp. ciphertext", ciphertext, sizeof ciphertext);

        ctx = AES_SIV_CTX_new();
        assert(ctx != NULL);
        
        printf("Encryption:\n");
        ret = AES_SIV_Init(ctx, key, sizeof key);
        assert(ret == 1);
        ret = AES_SIV_AssociateData(ctx, ad1, sizeof ad1);
        assert(ret == 1);
        ret = AES_SIV_AssociateData(ctx, ad2, sizeof ad2);
        assert(ret == 1);
        ret = AES_SIV_AssociateData(ctx, nonce, sizeof nonce);
        assert(ret == 1);
        ret = AES_SIV_EncryptFinal(ctx, ciphertext_out, ciphertext_out + 16,
                                   plaintext, sizeof plaintext);
        assert(ret == 1);
        debug("IV || C", ciphertext_out, sizeof plaintext + 16);
        assert(!memcmp(ciphertext_out, ciphertext, sizeof ciphertext));

        printf("Decryption:\n");
        ret = AES_SIV_Init(ctx, key, sizeof key);
        assert(ret == 1);
        ret = AES_SIV_AssociateData(ctx, ad1, sizeof ad1);
        assert(ret == 1);
        ret = AES_SIV_AssociateData(ctx, ad2, sizeof ad2);
        assert(ret == 1);
        ret = AES_SIV_AssociateData(ctx, nonce, sizeof nonce);
        assert(ret == 1);
        ret = AES_SIV_DecryptFinal(ctx, plaintext_out, ciphertext_out,
                                   ciphertext_out + 16, sizeof plaintext);
        assert(ret == 1);
        debug("plaintext", plaintext_out, sizeof plaintext);
        assert(!memcmp(plaintext_out, plaintext, sizeof plaintext));
	AES_SIV_CTX_cleanup(ctx);
	AES_SIV_CTX_free(ctx);
}

int main() {
        test_vector_1();
        test_vector_2();
        return 0;
}
#endif
