/**************************************************************************************************************
* altobeam IOT Wi-Fi
*
* Copyright (c) 2018, altobeam.inc   All rights reserved.
*
* The source code contains proprietary information of AltoBeam, and shall not be distributed, 
* copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/
#include "includes.h"
#include "wps_debug.h"


#ifndef wpa_isprint
#define wpa_in_range(c, lo, up)  ((atbm_uint8)c >= lo && (atbm_uint8)c <= up)
#define wpa_isprint(c)           wpa_in_range(c, 0x20, 0x7f)
#define wpa_isdigit(c)           wpa_in_range(c, '0', '9')
#define wpa_isxdigit(c)          (wpa_isdigit(c) || wpa_in_range(c, 'a', 'f') || wpa_in_range(c, 'A', 'F'))
#define wpa_islower(c)           wpa_in_range(c, 'a', 'z')
#define wpa_isspace(c)           (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v')
#endif


extern atbm_uint32 atbm_GetOsTime(atbm_void);
FLASH_FUNC static atbm_void wpa_debug_print_timestamp(atbm_void)
{
	atbm_uint32 msec;

	if (!wpa_debug_timestamp)
		return;

	msec = atbm_GetOsTime();
	wifi_printk(WIFI_WPS, "[%d] ", msec);

	return;
}

FLASH_FUNC static atbm_void _wpa_hexdump(atbm_int32 level, const char *title, const atbm_uint8 *buf, atbm_size_t len, atbm_uint32 show)
{
	atbm_size_t i;

	if (level < wpa_debug_level)
		return;
	
	wpa_debug_print_timestamp();
	wifi_printk(WIFI_WPS, "%s - hexdump(len=%lu):", title, (unsigned long) len);
	
	if (buf == NULL) {
		wifi_printk(WIFI_WPS, " [NULL]");
	} else if (show) {
		for (i = 0; i < len; i++){
			wifi_printk(WIFI_WPS, " %02x", buf[i]);
			if(i!=0 && i%8==0)
				wifi_printk(WIFI_WPS, "\n");
		}
	} else {
		wifi_printk(WIFI_WPS, " [REMOVED]");
	}
	wifi_printk(WIFI_WPS, "\n");
	
	return;
}

FLASH_FUNC atbm_void wpa_hexdump(atbm_int32 level, const char *title, const atbm_uint8 *buf, atbm_size_t len)
{
	_wpa_hexdump(level, title, buf, len, 1);

	return;
}

FLASH_FUNC static atbm_void _wpa_hexdump_ascii(atbm_int32 level, const char *title, const atbm_uint8 *buf, atbm_size_t len, atbm_uint32 show)
{
	atbm_size_t i, llen;
	const atbm_uint8 *pos = buf;
	const atbm_size_t line_len = 16;

	if (level < wpa_debug_level)
		return;
	
	wpa_debug_print_timestamp();

	if (!show) {
		wifi_printk(WIFI_WPS, "%s - hexdump_ascii(len=%lu): [REMOVED]\n",
		       title, (unsigned long) len);
		return;
	}
	if (buf == NULL) {
		wifi_printk(WIFI_WPS, "%s - hexdump_ascii(len=%lu): [NULL]\n",
		       title, (unsigned long) len);
		return;
	}
	wifi_printk(WIFI_WPS, "%s - hexdump_ascii(len=%lu):\n", title, (unsigned long) len);
	while (len) {
		llen = len > line_len ? line_len : len;
		wifi_printk(WIFI_WPS, "    ");
		for (i = 0; i < llen; i++)
			wifi_printk(WIFI_WPS, " %02x", pos[i]);
		for (i = llen; i < line_len; i++)
			wifi_printk(WIFI_WPS, "   ");
		wifi_printk(WIFI_WPS, "   ");
		for (i = 0; i < llen; i++) {
			if (wpa_isprint(pos[i]))
				wifi_printk(WIFI_WPS, "%c", pos[i]);
			else
				wifi_printk(WIFI_WPS, "_");
		}
		for (i = llen; i < line_len; i++)
			wifi_printk(WIFI_WPS, " ");
		wifi_printk(WIFI_WPS, "\n");
		pos += llen;
		len -= llen;
	}

	return;
}


FLASH_FUNC atbm_void wpa_hexdump_ascii(atbm_int32 level, const char *title, const atbm_uint8 *buf, atbm_size_t len)
{
	_wpa_hexdump_ascii(level, title, buf, len, 1);

	return;
}



