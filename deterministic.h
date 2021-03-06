#ifndef FALCON_DET1024_H__
#define FALCON_DET1024_H__

#include <stddef.h>
#include <stdint.h>
#include "falcon.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FALCON_DET1024_LOGN 10
#define FALCON_DET1024_PUBKEY_SIZE FALCON_PUBKEY_SIZE(FALCON_DET1024_LOGN)
#define FALCON_DET1024_PRIVKEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_DET1024_LOGN)

// Replace the 40 byte salt (nonce) with a single byte representing
// the salt version:
#define FALCON_DET1024_SIG_COMPRESSED_MAXSIZE FALCON_SIG_COMPRESSED_MAXSIZE(FALCON_DET1024_LOGN)-40+1
#define FALCON_DET1024_SIG_CT_SIZE FALCON_SIG_CT_SIZE(FALCON_DET1024_LOGN)-40+1

// The header bytes for deterministic mode correspond to the headers
// for ordinary compressed/CT format, but with n=1024 and MSB=1:
#define FALCON_DET1024_SIG_COMPRESSED_HEADER (0x3A | 0x80)
#define FALCON_DET1024_SIG_CT_HEADER (0x5A | 0x80)

// This version should be incremented upon any functional
// (input-output) changes to the signing algorithm.
#define FALCON_DET1024_CURRENT_SALT_VERSION 0

/*
 * Generate a keypair (for Falcon parameter n=1024).
 *
 * The source of randomness is the provided SHAKE256 context *rng,
 * which must have been already initialized, seeded, and set to output
 * mode (see shake256_init_prng_from_seed() and
 * shake256_init_prng_from_system()).
 *
 * The private key is written in the buffer pointed to by privkey.
 * The size of that buffer must be FALCON_DET1024_PRIVKEY_SIZE bytes.
 *
 * The public key is written in the buffer pointed to by pubkey.
 * The size of that buffer must be FALCON_DET1024_PUBKEY_SIZE bytes.
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_keygen(shake256_context *rng, void *privkey, void *pubkey);

/*
 * Deterministically sign the data provided in buffer data[] (of
 * length data_len bytes), using the private key held in privkey[] (of
 * length FALCON_DET1024_PRIVKEY_SIZE bytes). The resulting
 * compressed-format, variable-length signature is written in sig[]
 * (which should be at least FALCON_DET1024_SIG_COMPRESSED_MAXSIZE
 * bytes); the signature length is written to sig_len.
 *
 * The resulting signature is incompatible with randomized ("salted")
 * Falcon signatures: it excludes the salt (nonce), adds a salt
 * version byte, and changes the header byte. See the "Deterministic
 * Falcon" specification for further details.
 *
 * This function implements only the following subset of the
 * specification:
 *
 *   -- the parameter n is fixed to n=1024
 *   -- the signature format is 'compressed'
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_sign_compressed(void *sig, size_t *sig_len,
	const void *privkey, const void *data, size_t data_len);

/*
 * Verify the compressed-format, deterministic-mode (det1024)
 * signature provided in sig[] (of length sig_len bytes) with respect
 * to the public key provided in pubkey[] (of length
 * FALCON_DET1024_PUBKEY_SIZE bytes) and the data provided in data[]
 * (of length data_len bytes).
 *
 * This function accepts a strict subset of valid deterministic-mode
 * Falcon signatures, namely, only those having n=1024 and
 * "compressed" signature format (thus matching the choices
 * implemented by falcon_det1024_sign_compressed).
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_verify_compressed(const void *sig, size_t sig_len,
	const void *pubkey, const void *data, size_t data_len);

/*
 * Verify the CT-format, deterministic-mode (det1024) signature
 * provided in sig[] (of length FALCON_DET1024_SIG_CT_SIZE bytes) with
 * respect to the public key provided in pubkey[] (of length
 * FALCON_DET1024_PUBKEY_SIZE bytes) and the data provided in data[]
 * (of length data_len bytes).
 *
 * This function accepts a strict subset of valid deterministic-mode
 * Falcon signatures, namely, only those having n=1024 and "CT"
 * signature format.
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_verify_ct(const void *sig,
	const void *pubkey, const void *data, size_t data_len);

/*
 * Convert the compressed-format, deterministic-mode (det1024)
 * signature in sig_compressed (of length sig_compressed_len bytes) to
 * CT format. The resulting CT signature is written to sig_ct (of
 * length FALCON_DET1024_SIG_CT_SIZE bytes).
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_convert_compressed_to_ct(void *sig_ct,
	const void *sig_compressed, size_t sig_compressed_len);

/*
 * Returns the salt version of a signature, in either compressed or CT
 * form.
 */
int falcon_det1024_get_salt_version(const void* sig);

#ifdef __cplusplus
}
#endif

#endif
