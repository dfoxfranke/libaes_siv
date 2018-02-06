/* Copyright (c) 2017 Akamai Technologies, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * demo program for libaes-siv
 */

#include "aes_siv.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * load a file into memory.
 * @param[in] filename pathname of the file to load.
 * @param[out] the buf pointer will be set to a new malloc buffer which contains the file data.
 * @param[out] the len pointer will be set to the size of buf in bytes, which is the same as the file size in bytes.
 * @return 0 upon success, the file could be read and the buf,len output parameters have been set.
 * @return +1 if the file could not be opened.
 * @return -1 if reading the failed.
 * @return -2 upon parameter error.
 */
int load_file(const char *filename, unsigned char **buf, size_t *len)
{
  FILE *f;
  unsigned char *buf_ = NULL;
  size_t len_;

  // check parameters
  if (! filename) return +1;
  if (! buf) return -2;
  if (! len) return -2;

  // get file size
  f = fopen(filename, "rb");
  if (! f) return +1;

  if (fseek(f, 0, SEEK_END) != 0) goto fail;
  len_ = (size_t) ftell(f);
  rewind(f);

  // allocate memory and read
  buf_ = (unsigned char*) malloc(len_);
  if (! buf_) goto fail;
  if (fread(buf_, len_, 1, f) != 1) goto fail;

  // success
  fclose(f);
  *buf = buf_;
  *len = len_;
  return 0;

  fail:
  fclose(f);
  if (buf_) free(buf_);
  return -1;
}

void help()
{
    fprintf(stderr, "usage: aes_siv_test [-d] <key file> <ad file> [nonce file]\n");
    fprintf(stderr, "This program encrypts or decrypts STDIN to STDOUT using the AES-SIV algorithm.\n");
    fprintf(stderr, "-d           decrypt STDIN, by default STDIN is encrypted\n");
    fprintf(stderr, "<key file>   filename which is read for key data, must have a size of 32, 48, 64 bytes.\n");
    fprintf(stderr, "<ad file>    filename which is used for associate data. Can have any size.\n");
    fprintf(stderr, "[nonce file] optional filename which is used for nonce data. Can have any size.\n");
    exit(EXIT_FAILURE);
}

int main(int argc, const char **argv)
{
  int arg = 1;
  int decrypt_mode = 0;
  const char *key_file = NULL;
  const char *nonce_file = NULL;
  const char *ad_file = NULL;
  unsigned char *key = NULL;
  size_t key_len = 0;
  unsigned char *nonce = NULL;
  size_t nonce_len = 0;
  unsigned char *ad = NULL;
  size_t ad_len = 0;
  unsigned char *out = NULL;
  size_t out_len = 0;
  size_t plaintext_allocated = 1024;
  unsigned char *plaintext = malloc(plaintext_allocated);
  size_t plaintext_len = 0;
  AES_SIV_CTX *ctx = NULL;

  assert(plaintext);

  // parse command line
  arg = 1;
  if (arg < argc && strcmp(argv[arg], "-d") == 0)
  {
    decrypt_mode = 1;
    ++arg;
  }

  if (arg >= argc)
  {
    fprintf(stderr, "missing key filename\n\n");
    help();
  }
  key_file = argv[arg++];

  if (arg >= argc)
  {
    fprintf(stderr, "missing associate data filename\n\n");
    help();
  }
  ad_file = argv[arg++];

  if (arg < argc)
  {
    nonce_file = argv[arg++];
  }

  if (arg < argc)
  {
    fprintf(stderr, "unknown command line argument: %s\n\n", argv[arg]);
    help();
  }

  // load files
  if (load_file(key_file, &key, &key_len) < 0)
  {
    fprintf(stderr, "could not load key file %s : %s\n", key_file, strerror(errno));
    return EXIT_FAILURE;
  }
  assert(key);
  assert(key_len > 0);
  if (! (key_len == 32 ||
         key_len == 48 ||
         key_len == 64))
  {
    fprintf(stderr, "invalid key length %zu bytes, must be 32,48,64\n", key_len);
    return EXIT_FAILURE;
  }
  if (load_file(ad_file, &ad, &ad_len) < 0)
  {
    fprintf(stderr, "could not ad key file %s : %s\n", ad_file, strerror(errno));
    return EXIT_FAILURE;
  }
  assert(ad);
  assert(ad_len > 0);
  if (load_file(nonce_file, &nonce, &nonce_len) < 0)
  {
    fprintf(stderr, "could not load nonce file %s : %s\n", nonce_file, strerror(errno));
    return EXIT_FAILURE;
  }

  // read all of STDIN
  while(! feof(stdin))
  {
    unsigned char buf[1024];
    size_t r = fread(buf, 1, sizeof(buf), stdin);
    if (r > 0)
    {
      if (plaintext_len + r > plaintext_allocated)
      {
        plaintext_allocated *= 2;
        plaintext = realloc(plaintext, plaintext_allocated);
        if (! plaintext)
        {
          fprintf(stderr, "could not allocate %zu bytes\n", plaintext_allocated);
          return EXIT_FAILURE;
        }
      }
      assert(plaintext_len + r <= plaintext_allocated);
      memcpy(plaintext + plaintext_len, buf, r);
      plaintext_len += r;
    }
  }

  // allocate output buffer
  out_len = plaintext_len + 16;
  out = (unsigned char*) malloc(out_len);
  if (! out)
  {
    fprintf(stderr, "could not allocate %zu bytes\n", out_len);
    return EXIT_FAILURE;
  }

  // do AES-SIV
  ctx = AES_SIV_CTX_new();
  if (! ctx)
  {
    fprintf(stderr, "could not create AES-SIV context\n");
    return EXIT_FAILURE;
  }
  if (decrypt_mode)
  {
    if (! AES_SIV_Decrypt(ctx, out, &out_len, key, key_len, nonce, nonce_len, plaintext, plaintext_len, ad, ad_len))
    {
      fprintf(stderr, "could not decrypt AES-SIV\n");
      return EXIT_FAILURE;
    }
  }
  else
  {
    if (! AES_SIV_Encrypt(ctx, out, &out_len, key, key_len, nonce, nonce_len, plaintext, plaintext_len, ad, ad_len))
    {
      fprintf(stderr, "could not encrypt AES-SIV\n");
      return EXIT_FAILURE;
    }
  }
  AES_SIV_CTX_free(ctx);

  // write to stdout
  fwrite(out, out_len, 1, stdout);
  return EXIT_SUCCESS;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
