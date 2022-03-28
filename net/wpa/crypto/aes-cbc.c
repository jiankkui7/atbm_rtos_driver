/*
 * AES-128 CBC
 *
 * Copyright (c) 2003-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

//#include "mbedtls/config_atbm.h"
#include "atbm_type.h"
#include "aes.h"

#if(ATBM_HW_CHIPER==0)
/**
 * aes_128_cbc_encrypt - AES-128 CBC encryption
 * @key: Encryption key
 * @iv: Encryption IV for CBC mode (16 bytes)
 * @data: Data to encrypt in-place
 * @data_len: Length of data in bytes (must be divisible by 16)
 * Returns: 0 on success, -1 on failure
 */
FLASH_FUNC  int aes_128_cbc_encrypt(const atbm_uint8 *key, const atbm_uint8 *iv, atbm_uint8 *data, size_t data_len)
{
	void *ctx;
	atbm_uint8 cbc[AES_BLOCK_SIZE];
	atbm_uint8 *pos = data;
	int i, j, blocks;

	ctx = aes_encrypt_init(key, 16);
	if (ctx == NULL)
		return -1;
	atbm_memcpy(cbc, iv, AES_BLOCK_SIZE);

	blocks = data_len / AES_BLOCK_SIZE;
	for (i = 0; i < blocks; i++) {
		for (j = 0; j < AES_BLOCK_SIZE; j++)
			cbc[j] ^= pos[j];
		aes_encrypt(ctx, cbc, cbc);
		atbm_memcpy(pos, cbc, AES_BLOCK_SIZE);
		pos += AES_BLOCK_SIZE;
	}
	aes_encrypt_deinit(ctx);
	return 0;
}


/**
 * aes_128_cbc_decrypt - AES-128 CBC decryption
 * @key: Decryption key
 * @iv: Decryption IV for CBC mode (16 bytes)
 * @data: Data to decrypt in-place
 * @data_len: Length of data in bytes (must be divisible by 16)
 * Returns: 0 on success, -1 on failure
 */
FLASH_FUNC int aes_128_cbc_decrypt(const atbm_uint8 *key, const atbm_uint8 *iv, atbm_uint8 *data, size_t data_len)
{
	void *ctx;
	atbm_uint8 cbc[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	atbm_uint8 *pos = data;
	int i, j, blocks;

	ctx = aes_decrypt_init(key, 16);
	if (ctx == NULL)
		return -1;
	atbm_memcpy(cbc, iv, AES_BLOCK_SIZE);

	blocks = data_len / AES_BLOCK_SIZE;
	for (i = 0; i < blocks; i++) {
		atbm_memcpy(tmp, pos, AES_BLOCK_SIZE);
		aes_decrypt(ctx, pos, pos);
		for (j = 0; j < AES_BLOCK_SIZE; j++)
			pos[j] ^= cbc[j];
		atbm_memcpy(cbc, tmp, AES_BLOCK_SIZE);
		pos += AES_BLOCK_SIZE;
	}
	aes_decrypt_deinit(ctx);
	return 0;
}
#else//(ATBM_HW_CHIPER==1)
/**
 * aes_128_cbc_encrypt - AES-128 CBC encryption
 * @key: Encryption key
 * @iv: Encryption IV for CBC mode (16 bytes)
 * @data: Data to encrypt in-place
 * @data_len: Length of data in bytes (must be divisible by 16)
 * Returns: 0 on success, -1 on failure
 */
FLASH_FUNC  int aes_128_cbc_encrypt(const atbm_uint8 *key, const atbm_uint8 *iv, atbm_uint8 *data, size_t data_len)
{
    ATBM_set_hardware(ATBM_CHIPER_TYPE_AES128,ATBM_CHIPER_MODE_CBC,key,(128/8),iv,data,data,data_len,1,0);
	return 0;
}
/**
 * aes_128_cbc_decrypt - AES-128 CBC decryption
 * @key: Decryption key
 * @iv: Decryption IV for CBC mode (16 bytes)
 * @data: Data to decrypt in-place
 * @data_len: Length of data in bytes (must be divisible by 16)
 * Returns: 0 on success, -1 on failure
 */
FLASH_FUNC int aes_128_cbc_decrypt(const atbm_uint8 *key, const atbm_uint8 *iv, atbm_uint8 *data, size_t data_len)
{
    ATBM_set_hardware(ATBM_CHIPER_TYPE_AES128,ATBM_CHIPER_MODE_CBC,key,(128/8),iv,data,data,data_len,0,0);
	return 0;

}

#endif //(ATBM_HW_CHIPER==0)
