
#ifndef __P2P_DEBUG_H__
#define __P2P_DEBUG_H__


#include "p2p_common.h"
#include "wpabuf.h"


enum {
	MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR, MSG_ALWAYS
};


#define p2p_debug_timestamp 	1

#define P2P_DEBUG_LEVEL 	MSG_WARNING

#define p2p_printf(_level,...)	do {if((_level >= P2P_DEBUG_LEVEL)) {iot_printf(__VA_ARGS__);iot_printf("\n");}} while (0)


void p2p_hexdump(int level, const char *title, const atbm_uint8 *buf, size_t len);
void p2p_hexdump_ascii(int level, const char *title, const atbm_uint8 *buf, size_t len);
void p2p_hexdump_buf(int level, const char *title, const struct wpabuf *buf);


#endif

