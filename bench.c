/* Copyright (c) 2017 Akamai Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "config.h"
#include "aes_siv.h"

#include <assert.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const unsigned char key[64];
static const unsigned char ad[65536];
static const unsigned char nonce[16];
static unsigned char in[65536+16];
static unsigned char out[65536+16];


typedef int (*fn)(AES_SIV_CTX *, unsigned char *, size_t *,
                  unsigned char const*, size_t,
                  unsigned char const*, size_t,
                  unsigned char const*, size_t,
                  unsigned char const*, size_t);

const struct {
  size_t key_len;
  size_t nonce_len;
  size_t in_len;
  size_t ad_len;
} call_list[] = {
  { 32, 0, 0, 0 },  
  { 32, 0, 65536, 0 },
  { 32, 0, 0, 65536 },
  { 32, 0, 65536, 65536 },
  { 32, 0, 1536, 0 },
  { 32, 0, 0, 1536 },
  { 32, 0, 1536, 1536 },
  { 32, 0, 64, 0},
  { 32, 0, 0, 64},
  { 32, 0, 64, 64},
  { 32, 16, 0, 0 },  
  { 32, 16, 65536, 0 },
  { 32, 16, 0, 65536 },
  { 32, 16, 65536, 65536 },
  { 32, 16, 1536, 0 },
  { 32, 16, 0, 1536 },
  { 32, 16, 1536, 1536 },
  { 32, 16, 64, 0},
  { 32, 16, 0, 64},
  { 32, 16, 64, 64},

  { 48, 0, 0, 0 },  
  { 48, 0, 65536, 0 },
  { 48, 0, 0, 65536 },
  { 48, 0, 65536, 65536 },
  { 48, 0, 1536, 0 },
  { 48, 0, 0, 1536 },
  { 48, 0, 1536, 1536 },
  { 48, 0, 64, 0},
  { 48, 0, 0, 64},
  { 48, 0, 64, 64},
  { 48, 16, 0, 0 },  
  { 48, 16, 65536, 0 },
  { 48, 16, 0, 65536 },
  { 48, 16, 65536, 65536 },
  { 48, 16, 1536, 0 },
  { 48, 16, 0, 1536 },
  { 48, 16, 1536, 1536 },
  { 48, 16, 64, 0},
  { 48, 16, 0, 64},
  { 48, 16, 64, 64},

  { 64, 0, 0, 0 },  
  { 64, 0, 65536, 0 },
  { 64, 0, 0, 65536 },
  { 64, 0, 65536, 65536 },
  { 64, 0, 1536, 0 },
  { 64, 0, 0, 1536 },
  { 64, 0, 1536, 1536 },
  { 64, 0, 64, 0},
  { 64, 0, 0, 64},
  { 64, 0, 64, 64},
  { 64, 16, 0, 0 },  
  { 64, 16, 65536, 0 },
  { 64, 16, 0, 65536 },
  { 64, 16, 65536, 65536 },
  { 64, 16, 1536, 0 },
  { 64, 16, 0, 1536 },
  { 64, 16, 1536, 1536 },
  { 64, 16, 64, 0},
  { 64, 16, 0, 64},
  { 64, 16, 64, 64},
  
  { 0, 0, 0, 0 }
};
  
volatile int alarm_rung;

void alarm_handler(int num) {
  alarm_rung = 1;
}


static inline double
call(fn fn, AES_SIV_CTX *ctx,
     size_t key_len,
     size_t nonce_len, size_t in_len,
     size_t ad_len) {

  size_t out_len = sizeof out;
  size_t count;
  int ret;
  struct timespec start, end;
  double numerator, denominator;
  
  alarm_rung = 0;
  alarm(3);

  ret = clock_gettime(CLOCK_MONOTONIC, &start);
  assert(ret == 0);
  for(count = 0; !alarm_rung; count++) {
    fn(ctx, out, &out_len, key, key_len,
       nonce_len > 0 ? nonce : NULL, nonce_len,
       in, in_len, ad, ad_len);
  }
  ret = clock_gettime(CLOCK_MONOTONIC, &end);
  assert(ret == 0);

  numerator = (double)count;
  denominator = (double)(end.tv_sec) - (double)(start.tv_sec) +
    ((double)end.tv_nsec - (double)start.tv_nsec)/1000000000.;
  return numerator / denominator;
}
            
  

int main() {
  double rate;
  size_t i;
  AES_SIV_CTX *ctx = AES_SIV_CTX_new();
  signal(SIGALRM, alarm_handler);

  for(i=0; call_list[i].key_len != 0; i++) {
    printf("Encrypt, %3zd bit key, %2zd byte nonce, %5zd byte associated data, %5zd byte plaintext: ",
           call_list[i].key_len * 8, call_list[i].nonce_len, call_list[i].ad_len,
           call_list[i].in_len);
    fflush(stdout);
  
    rate = call(AES_SIV_Encrypt, ctx,
                call_list[i].key_len, call_list[i].nonce_len,
                call_list[i].in_len, call_list[i].ad_len);

    printf("%10.2lf calls/second (%10.2lf MiB/s)\n",
           rate,
           scalbn(rate * (double)(call_list[i].ad_len + call_list[i].in_len),
                  -20));

    memcpy(in, out, call_list[i].in_len + 16);
    
    printf("Decrypt, %3zd bit key, %2zd byte nonce, %5zd byte associated data, %5zd byte plaintext: ",
           call_list[i].key_len * 8, call_list[i].nonce_len, call_list[i].ad_len,
           call_list[i].in_len);
    fflush(stdout);
  
    rate = call(AES_SIV_Decrypt, ctx,
                call_list[i].key_len, call_list[i].nonce_len,
                call_list[i].in_len + 16, call_list[i].ad_len);

    printf("%10.2lf calls/second (%10.2lf MiB/s)\n",
           rate,
           scalbn(rate * (double)(call_list[i].ad_len + call_list[i].in_len),
                  -20));

    memset(in, 0, sizeof in);

    printf("Forgery, %3zd bit key, %2zd byte nonce, %5zd byte associated data, %5zd byte plaintext: ",
           call_list[i].key_len * 8, call_list[i].nonce_len, call_list[i].ad_len,
           call_list[i].in_len);
    fflush(stdout);
    
    rate = call(AES_SIV_Decrypt, ctx,
                call_list[i].key_len, call_list[i].nonce_len,
                call_list[i].in_len + 16, call_list[i].ad_len);

    printf("%10.2lf calls/second (%10.2lf MiB/s)\n",
           rate,
           scalbn(rate * (double)(call_list[i].ad_len + call_list[i].in_len),
                  -20));

    

  }
  
    
  return 0;
}
