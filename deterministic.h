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
// Drop the 40 byte nonce and add a prefix byte:
#define FALCON_DET1024_SIG_SIZE FALCON_SIG_PADDED_SIZE(FALCON_DET1024_LOGN)-40+1
#define FALCON_DET1024_SIG_PREFIX 0x80
#define FALCON_DET1024_SIG_HEADER 0x3A

/*
 * Fixed nonce used in deterministic signing.
 */
extern uint8_t falcon_det1024_nonce[40];

/*
 * Generate a keypair.
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
 * Deterministically sign the data provided in buffer data[] (of length data_len bytes),
 * using the private key held in privkey[] (of length FALCON_DET1024_PRIVKEY_SIZE bytes)
 * and the fixed nonce in falcon_det1024_nonce.
 *
 * The signature is written in sig[] (of length FALCON_DET1024_SIG_SIZE).
 * The resulting signature is incompatible with standard (randomized) Falcon signatures:
 * it uses an incompatible header byte and does not include the nonce.
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_sign(void *sig, const void *privkey, const void *data, size_t data_len);

/*
 * Verify the deterministic (det1024) signature sig[] (of length
 * FALCON_DET1024_SIG_SIZE bytes) with respect to the provided public key
 * pubkey[] (of length FALCON_DET1024_PUBKEY_SIZE bytes) and the message
 * data[] (of length data_len bytes).
 *
 * Returned value: 0 on success, or a negative error code.
 */
int falcon_det1024_verify(const void *sig, const void *pubkey, const void *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif
