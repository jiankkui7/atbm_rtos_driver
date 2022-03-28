/*
 * SHA256 hash implementation and interface functions
 * Copyright (c) 2003-2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SHA256_H
#define SHA256_H

#define SHA256_MAC_LEN 32

int hmac_sha256_vector(const atbm_uint8 *key, atbm_size_t key_len, atbm_size_t num_elem,
		       const atbm_uint8 *addr[], const atbm_size_t *len, atbm_uint8 *mac);
int hmac_sha256(const atbm_uint8 *key, atbm_size_t key_len, const atbm_uint8 *data,
		atbm_size_t data_len, atbm_uint8 *mac);
void sha256_prf(const atbm_uint8 *key, atbm_size_t key_len, const char *label,
	      const atbm_uint8 *data, atbm_size_t data_len, atbm_uint8 *buf, atbm_size_t buf_len);
void sha256_prf_bits(const atbm_uint8 *key, atbm_size_t key_len, const char *label,
		     const atbm_uint8 *data, atbm_size_t data_len, atbm_uint8 *buf,
		     atbm_size_t buf_len_bits);
void tls_prf_sha256(const atbm_uint8 *secret, atbm_size_t secret_len,
		    const char *label, const atbm_uint8 *seed, atbm_size_t seed_len,
		    atbm_uint8 *out, atbm_size_t outlen);
int hmac_sha256_kdf(const atbm_uint8 *secret, atbm_size_t secret_len,
		    const char *label, const atbm_uint8 *seed, atbm_size_t seed_len,
		    atbm_uint8 *out, atbm_size_t outlen);

#endif /* SHA256_H */
