#ifndef FALCON_DETERMINISTIC_H__
#define FALCON_DETERMINISTIC_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int falcon_sign_det(
	void *sig, size_t *sig_len, int sig_type,
	const void *privkey, size_t privkey_len,
	const void *data, size_t data_len,
	void *tmp, size_t tmp_len);

#ifdef __cplusplus
}
#endif

#endif