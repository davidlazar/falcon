#ifndef FALCON_DET1024_H__
#define FALCON_DET1024_H__

#include <stddef.h>
#include <stdint.h>
#include "falcon.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Use emulated floating-point implementation.
 *
 * Emulation uses only integer operations with uint32_t and uint64_t
 * types. This is constant-time, provided that the underlying platform
 * offers constant-time opcodes for the following operations:
 *
 *  - Multiplication of two 32-bit unsigned integers into a 64-bit result.
 *  - Left-shift or right-shift of a 32-bit unsigned integer by a
 *    potentially secret shift count in the 0..31 range.
 *
 * Notably, the ARM Cortex M3 does not fulfill the first condition,
 * while the Pentium IV does not fulfill the second.
 *
 * *** CRITICAL SECURITY WARNING ***:
 * 
 * Floating-point emulation is enabled in order to get reliable
 * deterministic signing across supported platforms, because native
 * floating-point units and code optimizations may yield slight
 * discrepancies that could affect determinism.
 *
 * KEEPING FALCON_FPEMU ENABLED IS STRONGLY RECOMMENDED! Emulation is
 * important for obtaining truly deterministic signing across
 * different platforms and configurations, i.e., the same message
 * should always yield the same signature (under the same secret key).
 *
 * Any non-determinism in signing can lead to a CATASTROPHIC SECURITY
 * FAILURE, potentially enabling an attacker to create forgeries for
 * arbitrary messages after obtaining two or more different signatures
 * for the same message (under the same secret key).
 *
 * Determinism can be sanity-checked (but not guaranteed) using the
 * provided KATs. Any deviation from the expected results indicates a
 * lack of determinism, but agreement does not prove determinism for
 * all possible inputs.
 */
#define FALCON_FPEMU  1

/* 
 * Explicitly disable native floating-point operations. (These are
 * already implicitly disabled by enabling FALCON_FPEMU above; here it
 * is made explicit as a defensive measure.)
 */
#define FALCON_FPNATIVE  0

/*
 * Explicitly disable "fused multiply-add" optimizations, which are
 * KNOWN to lead to non-determinism in some cases. (These are already
 * implicitly disabled by enabling FALCON_FPEMU above; here it is made
 * explicit as a defensive measure.)
 *
 * WARNING: IT IS STRONGLY RECOMMENDED *NOT* TO ENABLE BOTH FALCON_FPU
 * AND FALCON_FMA. DOING SO LEADS TO DEMONSTRATED NON-DETERMINISM.
 */
#define FALCON_FMA  0

/*
 * Explicitly disable AVX2 optimizations. (These are already
 * implicitly disabled by enabling FALCON_FPEMU above; here it is made
 * explicit as a defensive measure.)
 * 
 * While we are not aware of any way that AVX2 optimizations could
 * lead to non-determinism, caution should be exercised if they are
 * ever under consideration for usage. (At minimum, check KATs.)
 */
#define FALCON_AVX2  0

/*
 * Explicitly disable the specialized assembly code for ARM Cortex-M4.
 * 
 * While we are not aware of any way that the assembly code could lead
 * to non-determinism, caution should be exercised if it is ever under
 * consideration for usage. (At minimum, check KATs.)
 */
#define FALCON_ASM_CORTEXM4  0

  
#define FALCON_DET1024_LOGN 10
#define FALCON_DET1024_PUBKEY_SIZE FALCON_PUBKEY_SIZE(FALCON_DET1024_LOGN)
#define FALCON_DET1024_PRIVKEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_DET1024_LOGN)
// Drop the 40 byte nonce and add a prefix byte:
#define FALCON_DET1024_SIG_SIZE FALCON_SIG_PADDED_SIZE(FALCON_DET1024_LOGN)-40+1
#define FALCON_DET1024_SIG_PREFIX 0x80

/*
 * Fixed nonce used in deterministic signing.
 */
extern uint8_t falcon_det1024_nonce[40];

/*
 * Generate a new keypair.
 *
 * The source of randomness is the provided SHAKE256 context *rng, which
 * must have been already initialized, seeded, and set to output mode (see
 * shake256_init_prng_from_seed() and shake256_init_prng_from_system())
 *
 * The new private key is written in the buffer pointed to by privkey.
 * The size of that buffer must be FALCON_DET1024_PRIVKEY_SIZE bytes.
 *
 * The new public key is written in the buffer pointed to by pubkey.
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
