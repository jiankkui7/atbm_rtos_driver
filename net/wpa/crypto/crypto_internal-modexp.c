/*
 * Crypto wrapper for internal crypto implementation - modexp
 * Copyright (c) 2006-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "wps_debug.h"

#include "atbm_type.h"

#include "bignum.h"
#include "crypto.h"


FLASH_FUNC int crypto_mod_exp(const atbm_uint8 *base, atbm_size_t base_len,
		   const atbm_uint8 *power, atbm_size_t power_len,
		   const atbm_uint8 *modulus, atbm_size_t modulus_len,
		   atbm_uint8 *result, atbm_size_t *result_len)
{
	int ret = -1;
	atbm_uint32 start_T, end_T;
	start_T = atbm_GetOsTime();
#if 1
	mbedtls_mpi iresult, ibase, ipower, imodulus, ictx;

	mbedtls_mpi_init(&iresult);
	mbedtls_mpi_init(&ibase);
	mbedtls_mpi_init(&ipower);
	mbedtls_mpi_init(&imodulus);
	mbedtls_mpi_init(&ictx);
		
	if (mbedtls_mpi_read_binary(&ibase, base, base_len) < 0 ||
		mbedtls_mpi_read_binary(&ipower, power, power_len) < 0 ||
		mbedtls_mpi_read_binary(&imodulus, modulus, modulus_len) < 0)
		goto error;

	end_T = atbm_GetOsTime();
	wpa_printf(MSG_ALWAYS, "cryptoexp:1 =%dms",  end_T-start_T);

	if (mbedtls_mpi_exp_mod( &iresult, &ibase, &ipower, &imodulus, &ictx ) < 0)
		goto error;
	
	end_T = atbm_GetOsTime();
	wpa_printf(MSG_ALWAYS, "cryptoexp:2 =%dms",  end_T-start_T);
	ret = mbedtls_mpi_write_binary( &iresult, result, *result_len);
	
	
error:
	mbedtls_mpi_free(&iresult);
	mbedtls_mpi_free(&ibase);
	mbedtls_mpi_free(&ipower);
	mbedtls_mpi_free(&imodulus);
	mbedtls_mpi_free(&ictx);


#else	
	struct bignum *bn_base, *bn_exp, *bn_modulus, *bn_result;
	bn_base = bignum_init();
	bn_exp = bignum_init();
	bn_modulus = bignum_init();
	bn_result = bignum_init();
	wifi_printk("crypto_mod_exp\n");

	if (bn_base == NULL || bn_exp == NULL || bn_modulus == NULL ||
	    bn_result == NULL)
		goto error;

	if (bignum_set_unsigned_bin(bn_base, base, base_len) < 0 ||
	    bignum_set_unsigned_bin(bn_exp, power, power_len) < 0 ||
	    bignum_set_unsigned_bin(bn_modulus, modulus, modulus_len) < 0)
		goto error;
	wifi_printk("crypto_mod_exp222\n");

	if (bignum_exptmod(bn_base, bn_exp, bn_modulus, bn_result) < 0)
		goto error;
	wifi_printk("crypto_mod_exp333\n");

	ret = bignum_get_unsigned_bin(bn_result, result, result_len);
	wifi_printk("crypto_mod_exp444\n");

error:
	bignum_deinit(bn_base);
	bignum_deinit(bn_exp);
	bignum_deinit(bn_modulus);
	bignum_deinit(bn_result);
#endif


	return ret;
}
