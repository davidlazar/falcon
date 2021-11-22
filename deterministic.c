#include <stdint.h>
#include <string.h>

#include "falcon.h"
#include "inner.h"
#include "deterministic.h"

int falcon_det1024_keygen(shake256_context *rng, void *privkey, void *pubkey) {
	size_t tmpkg_len = FALCON_TMPSIZE_KEYGEN(FALCON_DET1024_LOGN);
	uint8_t tmpkg[tmpkg_len];

	return falcon_keygen_make(rng, FALCON_DET1024_LOGN,
		privkey, FALCON_DET1024_PRIVKEY_SIZE,
		pubkey, FALCON_DET1024_PUBKEY_SIZE,
		tmpkg, tmpkg_len);
}

uint8_t falcon_det1024_nonce[40] = {"FALCON_DET1024"};

int falcon_det1024_sign_compressed(void *sig, size_t *sig_len, const void *privkey, const void *data, size_t data_len) {
	shake256_context detrng;
	shake256_context hd;
	size_t tmpsd_len = FALCON_TMPSIZE_SIGNDYN(FALCON_DET1024_LOGN);
	uint8_t tmpsd[tmpsd_len];
	uint8_t domain[1], logn[1];

	size_t fullsig_len = FALCON_SIG_COMPRESSED_MAXSIZE(FALCON_DET1024_LOGN);
	uint8_t fullsig[fullsig_len];

	if (falcon_get_logn(privkey, FALCON_DET1024_PRIVKEY_SIZE) != FALCON_DET1024_LOGN) {
		return FALCON_ERR_FORMAT;
	}

	// SHAKE(0 || logn || sk || data)
	domain[0] = 0;
	shake256_init(&detrng);
	shake256_inject(&detrng, domain, 1);
	logn[0] = FALCON_DET1024_LOGN;
	shake256_inject(&detrng, logn, 1);
	shake256_inject(&detrng, privkey, FALCON_DET1024_PRIVKEY_SIZE);
	shake256_inject(&detrng, data, data_len);
	shake256_flip(&detrng);

	// SHAKE(nonce || data)
	shake256_init(&hd);
	shake256_inject(&hd, falcon_det1024_nonce, 40);
	shake256_inject(&hd, data, data_len);

	int r = falcon_sign_dyn_finish(&detrng, fullsig, &fullsig_len,
		FALCON_SIG_COMPRESSED, privkey, FALCON_DET1024_PRIVKEY_SIZE,
		&hd, falcon_det1024_nonce, tmpsd, tmpsd_len);
	if (r != 0) {
		return r;
	}

	uint8_t *sigbytes = sig;
	sigbytes[0] = FALCON_DET1024_SIG_PREFIX;
	sigbytes[1] = fullsig[0];
	memcpy(sigbytes+2, fullsig+41, fullsig_len-41);

	*sig_len = fullsig_len-40+1;

	return 0;
}

int falcon_det1024_sig_compressed_to_ct(void *sig_ct, const void *sig_compressed, size_t sig_compressed_len) {
	int16_t buf[1 << FALCON_DET1024_LOGN];
	size_t v;

	v = Zf(comp_decode)(buf, FALCON_DET1024_LOGN, sig_compressed+2, sig_compressed_len-2);
	if (v == 0) {
		return FALCON_ERR_SIZE;
	}

	uint8_t *sig = sig_ct;
	sig[0] = FALCON_DET1024_SIG_PREFIX;
	sig[1] = FALCON_DET1024_SIG_CT_HEADER;
	v = Zf(trim_i16_encode)(sig+2, FALCON_DET1024_SIG_CT_SIZE-2, buf, FALCON_DET1024_LOGN,
		Zf(max_sig_bits)[FALCON_DET1024_LOGN]);
	if (v == 0) {
		return FALCON_ERR_SIZE;
	}

	return 0;
}

int falcon_det1024_verify_compressed(const void *sig, size_t sig_len, const void *pubkey, const void *data, size_t data_len) {
	size_t tmpvv_len = FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN);
	uint8_t tmpvv[tmpvv_len];

	size_t fullsig_len = sig_len + 40 - 1;
	uint8_t fullsig[fullsig_len];

	const uint8_t *sigbytes = sig;
	// det1024 signatures must start with the prefix byte:
	if (sigbytes[0] != FALCON_DET1024_SIG_PREFIX) {
		return FALCON_ERR_BADSIG;
	}
	if (sigbytes[1] != FALCON_DET1024_SIG_COMPRESSED_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	fullsig[0] = sigbytes[1];
	memcpy(fullsig+1, falcon_det1024_nonce, 40);
	memcpy(fullsig+41, sigbytes+2, fullsig_len-41);

	return falcon_verify(fullsig, fullsig_len, FALCON_SIG_COMPRESSED,
		pubkey, FALCON_DET1024_PUBKEY_SIZE, data, data_len,
		tmpvv, tmpvv_len);
}

int falcon_det1024_verify_ct(const void *sig, const void *pubkey, const void *data, size_t data_len) {
	size_t tmpvv_len = FALCON_TMPSIZE_VERIFY(FALCON_DET1024_LOGN);
	uint8_t tmpvv[tmpvv_len];

	size_t fullsig_len = FALCON_SIG_CT_SIZE(FALCON_DET1024_LOGN);
	uint8_t fullsig[fullsig_len];

	const uint8_t *sigbytes = sig;
	// det1024 signatures must start with the prefix byte:
	if (sigbytes[0] != FALCON_DET1024_SIG_PREFIX) {
		return FALCON_ERR_BADSIG;
	}
	if (sigbytes[1] != FALCON_DET1024_SIG_CT_HEADER) {
		return FALCON_ERR_BADSIG;
	}

	fullsig[0] = sigbytes[1];
	memcpy(fullsig+1, falcon_det1024_nonce, 40);
	memcpy(fullsig+41, sigbytes+2, fullsig_len-41);

	return falcon_verify(fullsig, fullsig_len, FALCON_SIG_CT,
		pubkey, FALCON_DET1024_PUBKEY_SIZE, data, data_len,
		tmpvv, tmpvv_len);
}