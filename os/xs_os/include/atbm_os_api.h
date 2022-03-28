/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#ifndef ATBM_OS_API_H
#define ATBM_OS_API_H

#include <logger/elog.h>
#include <string.h>
#include "atbm_type.h"

#if ATBM_SDIO_BUS
#include "atbm_os_sdio.h"
#endif
#if ATBM_USB_BUS
#include "atbm_os_usb.h"
#endif
#define HZ  1000

#ifndef atbm_packed
#define atbm_packed __attribute__ ((packed))
#endif //__packed

#ifndef MAX_SSID_LEN
#define MAX_SSID_LEN 32
#endif

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN   6
#endif 

#ifndef MAX_AP_COUNT
#define MAX_AP_COUNT   10
#endif

#ifndef MAX_KEY_LEN
#define MAX_KEY_LEN   16
#endif

#ifndef __INLINE
#define __INLINE inline
#endif

#define __INLINE inline
#define iot_printf log_d
#define  atbm_random()   rand()

#define  rcu_read_lock()
#define  rcu_read_unlock()
#define  TargetUsb_lmac_start()
#define ZEROSIZE 0

struct __una_u16 { atbm_uint16 x; } atbm_packed ;
struct __una_u32  { atbm_uint32 x; } atbm_packed ;

typedef struct wifi_ap_info {
    unsigned char   ssid[MAX_SSID_LEN];
    unsigned char   bssid[MAC_ADDR_LEN];
    unsigned int    channel;
    unsigned int    security;
    unsigned int    rssi;
} wifi_ap_info_t;

typedef struct wifi_ap_list
{
	unsigned short  ap_count;
	wifi_ap_info_t ap_info[MAX_AP_COUNT];
}wifi_ap_list_t;

struct _apcfg
{
	unsigned char mac_addr[MAC_ADDR_LEN];
	unsigned char ssid[MAX_SSID_LEN];
	unsigned int  ssid_len;
	unsigned char mode;    // bg, bgn, an,...
	unsigned char channel;
	unsigned char txpower; //0 means max power
	unsigned int  enc_protocol; // encryption protocol	eg.wep, wpa, wpa2 
	unsigned char key[MAX_KEY_LEN];
	unsigned int  key_len;
	
};


static __INLINE atbm_uint32 get_unaligned_le32(const atbm_void *p)
{
	atbm_uint32 tmp;
	memcpy(&tmp, p, 4);

	return tmp;
}

#if ATBM_USB_BUS
int atbm_usb_register_init();
int atbm_usb_register_deinit();
#elif ATBM_SDIO_BUS
int atbm_sdio_register_init(void);
int atbm_sdio_register_deinit(void);
#endif

int atbmwifi_event_OsCallback(atbm_void *prv,int eventid,atbm_void *param);
int atbm_wifi_get_mac(unsigned char *mac_addr);
atbm_uint32 atbm_os_random(void);
enum xs_wifi_mode atbm_wifi_get_mode(void);
int atbm_wifi_set_mode(enum xs_wifi_mode);
int atbm_wifi_connect(char *ssid, char *password);
int atbm_wifi_disconnect(void);
int atbm_wifi_isconnected(void);
int atbm_wifi_create_ap(struct _apcfg *ap_cfg);
int atbm_wifi_destroy_ap(void);
int atbm_wifi_scan(wifi_ap_list_t *ap_list);
int atbm_wifi_netstack_init(void);
int atbm_wifi_init(void);
int atbm_wifi_netif_init(void);

#endif //ATBM_OS_API_H
