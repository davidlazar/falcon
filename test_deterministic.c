#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "falcon.h"
#include "deterministic.h"

static void *
xmalloc(size_t len)
{
	void *buf;

	if (len == 0) {
		return NULL;
	}
	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "memory allocation error\n");
		exit(EXIT_FAILURE);
	}
	return buf;
}

int main() {
	void *pubkey, *privkey, *sig; 
	size_t pubkey_len, privkey_len, sig_len;
	uint8_t *tmpkg, *tmpsd, *tmpst, *tmpvv; 
	size_t tmpkg_len, tmpsd_len, tmpst_len, tmpvv_len;
	int r;

	unsigned logn = 10;

	pubkey_len = FALCON_PUBKEY_SIZE(logn);
	privkey_len = FALCON_PRIVKEY_SIZE(logn);
	sig_len = FALCON_SIG_COMPRESSED_MAXSIZE(logn);

	pubkey = xmalloc(pubkey_len);
	privkey = xmalloc(privkey_len);
	sig = xmalloc(sig_len);

	tmpkg_len = FALCON_TMPSIZE_KEYGEN(logn);
	tmpsd_len = FALCON_TMPSIZE_SIGNDYN(logn);
	tmpst_len = FALCON_TMPSIZE_SIGNTREE(logn);
	tmpvv_len = FALCON_TMPSIZE_VERIFY(logn);

	tmpkg = xmalloc(tmpkg_len);
	tmpsd = xmalloc(tmpsd_len);
	tmpst = xmalloc(tmpst_len);
	tmpvv = xmalloc(tmpvv_len);

	shake256_context rng;
	shake256_init_prng_from_seed(&rng, "seed", 4);

	memset(privkey, 0, privkey_len);
	memset(pubkey, 0, pubkey_len);
	r = falcon_keygen_make(&rng, logn, privkey, privkey_len,
		pubkey, pubkey_len, tmpkg, tmpkg_len);
	if (r != 0) {
		fprintf(stderr, "keygen failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	memset(sig, 0, sig_len);
	r = falcon_sign_det(sig, &sig_len, FALCON_SIG_COMPRESSED,
		privkey, privkey_len,
		"data1", 5, tmpsd, tmpsd_len);
	if (r != 0) {
		fprintf(stderr, "sign_dyn failed: %d\n", r);
		exit(EXIT_FAILURE);
	}
	r = falcon_verify(sig, sig_len, FALCON_SIG_COMPRESSED,
		pubkey, pubkey_len, "data1", 5, tmpvv, tmpvv_len);
	if (r != 0) {
		fprintf(stderr, "verify failed: %d\n", r);
		exit(EXIT_FAILURE);
	}
}