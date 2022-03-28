
#include "p2p_debug.h"
#include "atbm_hal.h"


#ifndef p2p_isprint
#define p2p_in_range(c, lo, up)  ((atbm_uint8)c >= lo && (atbm_uint8)c <= up)
#define p2p_isprint(c)           p2p_in_range(c, 0x20, 0x7f)
#endif


FLASH_FUNC static void p2p_debug_print_timestamp(void)
{
	unsigned int msec;

	if (!p2p_debug_timestamp)
		return;

	msec = atbm_GetOsTimeMs();
	p2p_printf(MSG_DEBUG, "[%d] ", msec);

	return;
}

FLASH_FUNC static void _p2p_hexdump(int level, const char *title, const atbm_uint8 *buf, size_t len, int show)
{
	size_t i;

	if (level < P2P_DEBUG_LEVEL)
		return;
	
	p2p_debug_print_timestamp();
	printf("%s - hexdump(len=%lu):", title, (unsigned long) len);
	
	if (buf == NULL) {
		printf(" [NULL]");
	} else if (show) {
		for (i = 0; i < len; i++){
			printf(" %02x", buf[i]);
			if(i!=0 && i%8==0)
				printf("\n");
		}
	} else {
		printf(" [REMOVED]");
	}
	printf("\n");
	
	return;
}

FLASH_FUNC void p2p_hexdump(int level, const char *title, const atbm_uint8 *buf, size_t len)
{
	_p2p_hexdump(level, title, buf, len, 1);

	return;
}

FLASH_FUNC static void _p2p_hexdump_ascii(int level, const char *title, const atbm_uint8 *buf, size_t len, int show)
{
	size_t i, llen;
	const atbm_uint8 *pos = buf;
	const size_t line_len = 16;

	if (level < P2P_DEBUG_LEVEL)
		return;
	
	p2p_debug_print_timestamp();

	if (!show) {
		printf("%s - hexdump_ascii(len=%lu): [REMOVED]\n",
		       title, (unsigned long) len);
		return;
	}
	if (buf == NULL) {
		printf("%s - hexdump_ascii(len=%lu): [NULL]\n",
		       title, (unsigned long) len);
		return;
	}
	printf("%s - hexdump_ascii(len=%lu):\n", title, (unsigned long) len);
	while (len) {
		llen = len > line_len ? line_len : len;
		printf("    ");
		for (i = 0; i < llen; i++)
			printf(" %02x", pos[i]);
		for (i = llen; i < line_len; i++)
			printf("   ");
		printf("   ");
		for (i = 0; i < llen; i++) {
			if (p2p_isprint(pos[i]))
				printf("%c", pos[i]);
			else
				printf("_");
		}
		for (i = llen; i < line_len; i++)
			printf(" ");
		printf("\n");
		pos += llen;
		len -= llen;
	}

	return;
}


FLASH_FUNC void p2p_hexdump_ascii(int level, const char *title, const atbm_uint8 *buf, size_t len)
{
	_p2p_hexdump_ascii(level, title, buf, len, 1);

	return;
}


FLASH_FUNC void p2p_hexdump_buf(int level, const char *title,
				   const struct wpabuf *buf)
{
	wpa_hexdump(level, title, buf ? wpabuf_head(buf) : NULL,
		    buf ? wpabuf_len(buf) : 0);
}



