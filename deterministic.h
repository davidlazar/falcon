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

extern uint8_t falcon_det1024_nonce[40];

int falcon_det1024_keygen(shake256_context *rng, void *privkey, void *pubkey);
int falcon_det1024_sign(void *sig, const void *privkey, const void *data, size_t data_len);
int falcon_det1024_verify(const void *sig, const void *pubkey, const void *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif