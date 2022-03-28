/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#include "atbm_hal.h"

struct atbmwifi_cfg hmac_cfg;

#if 0

#ifdef CONFIG_OS_FREERTOS
#define HTONS(n) (atbm_uint16)((((atbm_uint16) (n)) << 8) | (((atbm_uint16) (n)) >> 8))
#define uip_ipaddr(addr, addr0,addr1,addr2,addr3) do { \
                     ((atbm_uint16 *)(addr))[0] = HTONS(((addr0) << 8) | (addr1)); \
                     ((atbm_uint16 *)(addr))[1] = HTONS(((addr2) << 8) | (addr3)); \
                  } while(0)

#endif //CONFIG_OS_FREERTOS


FLASH_FUNC atbm_void hmac_config_init()
{
#ifndef WPA_SUPPLICANT
	atbm_memcpy(hmac_cfg.ssid,TEST_AP_SSID,strlen(TEST_AP_SSID));
	hmac_cfg.ssid_len = strlen(TEST_AP_SSID);
	hmac_cfg.password_len = 0;
	hmac_cfg.privacy = 0;
#endif
	/***************iot_boot_sect*********************/
	iot_boot_sect.boot_param.static_ip = 0;
	iot_boot_sect.tcpip_param.iot_listen_port = 1234;
	iot_boot_sect.tcpip_param.iot_connect_rport = 1234;
	iot_boot_sect.tcpip_param.iot_connect_lport = 1234;

#ifdef HMAC_AP_MODE
	iot_boot_sect.boot_param.wifimode= 1;
	hmac_cfg.ap_mode = 1;
	uip_ipaddr(iot_boot_sect.tcpip_param.static_ipaddr, 192, 168, 1,  1);
	uip_ipaddr(iot_boot_sect.tcpip_param.static_gwaddr, 192, 168, 1,  1);
	uip_ipaddr(iot_boot_sect.tcpip_param.static_ipmask, 255, 255, 255, 0);
	uip_ipaddr(iot_boot_sect.tcpip_param.iot_connect_ip, 192, 168, 1,  2 );
#else
	iot_boot_sect.boot_param.wifimode= 0;
	hmac_cfg.ap_mode = 0;
	uip_ipaddr(iot_boot_sect.tcpip_param.static_ipaddr, 192, 168, 1,  2 );
	uip_ipaddr(iot_boot_sect.tcpip_param.static_gwaddr, 192, 168, 1,  1);
	uip_ipaddr(iot_boot_sect.tcpip_param.static_ipmask, 255, 255, 255, 0);
	uip_ipaddr(iot_boot_sect.tcpip_param.iot_connect_ip, 192, 168, 1,  1 );
#endif /*HMAC_AP_MODE*/

}
#endif
