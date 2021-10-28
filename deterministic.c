#include <stdint.h>
#include "falcon.h"

int falcon_sign_det(
	void *sig, size_t *sig_len, int sig_type,
	const void *privkey, size_t privkey_len,
	const void *data, size_t data_len,
	void *tmp, size_t tmp_len)
{
	shake256_context fixedrng;
	shake256_context detrng;
	shake256_context hd;
	uint8_t nonce[40];
	int r;

	uint8_t seed[10] = {0, 'F', 'A', 'L', 'C', 'O', 'N', 'D', 'E', 'T'};
	shake256_init_prng_from_seed(&fixedrng, seed, 10);

	r = falcon_sign_start(&fixedrng, nonce, &hd);
	if (r != 0) {
		return r;
	}
	shake256_inject(&hd, data, data_len);

	shake256_init(&detrng);
	uint8_t ones[1] = {1};
	shake256_inject(&detrng, ones, 1);
	shake256_inject(&detrng, privkey, privkey_len);
	shake256_inject(&detrng, data, data_len);
	shake256_flip(&detrng);

	return falcon_sign_dyn_finish(&detrng, sig, sig_len, sig_type,
								  privkey, privkey_len, &hd, nonce, tmp, tmp_len);
}