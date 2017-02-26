#undef NDEBUG
#include <assert.h>
#include "aes_siv.h"

int main() {
	/* All these are deliberately left uninitialized. The purpose
	   of this test is run under Valgrind and see if and where it
	   complains: this will flag potentially non-constant-time
	   code. This may yield false positives due to cmov and the
	   like, and if AES-NI is not in use then it will
	   (legitimately) flag inside OpenSSL's AES implementation.
	*/

	unsigned char key[32];
	unsigned char plaintext[34];
	unsigned char ad[14];
	unsigned char nonce[16];

	AES_SIV_CTX *ctx;
	int ret;

	unsigned char ciphertext_out[256];
	size_t ciphertext_len = sizeof ciphertext_out;

	ctx = AES_SIV_CTX_new();
	assert(ctx != NULL);

	ret = AES_SIV_Encrypt(ctx, ciphertext_out, &ciphertext_len,
			      key, sizeof key,
			      nonce, sizeof nonce,
			      plaintext, sizeof plaintext,
			      ad, sizeof ad);
	assert(ret == 1);
	AES_SIV_CTX_cleanup(ctx);
	AES_SIV_CTX_free(ctx);
	return 0;
}
