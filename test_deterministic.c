#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "falcon.h"
#include "deterministic.h"

void test_inner(size_t data_len) {
	uint8_t pubkey[FALCON_DET1024_PUBKEY_SIZE];
	uint8_t privkey[FALCON_DET1024_PRIVKEY_SIZE];
	uint8_t sig[FALCON_DET1024_SIG_SIZE];
	uint8_t sig2[FALCON_DET1024_SIG_SIZE];
	uint8_t data[data_len];

	memset(privkey, 0, FALCON_DET1024_PRIVKEY_SIZE);
	memset(pubkey, 0, FALCON_DET1024_PUBKEY_SIZE);

	shake256_context rng;
	shake256_init_prng_from_seed(&rng, "seed", 4);
	shake256_extract(&rng, data, data_len);

	int r = falcon_det1024_keygen(&rng, privkey, pubkey);
	if (r != 0) {
		fprintf(stderr, "keygen failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	memset(sig, 0, FALCON_DET1024_SIG_SIZE);
	memset(sig2, 0, FALCON_DET1024_SIG_SIZE);
	r = falcon_det1024_sign(sig, privkey, data, data_len);
	if (r != 0) {
		fprintf(stderr, "sign_det1024 failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_verify(sig, pubkey, data, data_len);
	if (r != 0) {
		fprintf(stderr, "verify failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_sign(sig2, privkey, data, data_len);
	if (r != 0) {
		fprintf(stderr, "sign_det1024 failed: %d\n", r);
		exit(EXIT_FAILURE);
	}

	if (memcmp(sig, sig2, FALCON_DET1024_SIG_SIZE) != 0) {
		fprintf(stderr, "sign_det1024 is non-deterministic\n");
		exit(EXIT_FAILURE);
	}
}

int main() {
	for (int i = 1; i <= 1024; i++) {
		test_inner(i);
	}
}