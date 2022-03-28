/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/
#define ATBM_WIFI_DRIVER_API_H 1
/*include os platform*/
extern struct sdio_func func;

#include "atbm_hal.h"
/******** Functions below is Wlan API **********/
//#include "wlan_ATBM.h"
#include "atbm_os_sdio.h"
int atbmwifi_event_OsCallback(atbm_void *prv,int eventid,atbm_void *param)
{
	#if 0
	struct atbmwifi_vif *priv = prv;
	wlan_event_msg_t event;
	memset(&event,0,sizeof(wlan_event_msg_t));
	if((priv->iftype == ATBM_NL80211_IFTYPE_AP)||
			(priv->iftype == ATBM_NL80211_IFTYPE_P2P_GO)){
		atbm_uint8 * staMacAddr ;
		switch(eventid){

			case ATBM_WIFI_DEAUTH_EVENT:
				wifi_printk(WIFI_ALWAYS,"event_OsCallback DEAUTH\n");
				//atbm_uint8 * staMacAddr =(atbm_uint8 *) param;
				event.event_type = WLAN_E_DISASSOC_IND;
				memcpy(event.addr.mac,param,6);
				WLAN_SYS_StatusCallback(&event);
				break;
			case ATBM_WIFI_AUTH_EVENT:
				break;
			case ATBM_WIFI_ASSOC_EVENT:
				break;
			case ATBM_WIFI_ASSOCRSP_TXOK_EVENT: 
				staMacAddr =(atbm_uint8 *) param;
				event.event_type = WLAN_E_ASSOC_IND;
				memcpy(event.addr.mac,staMacAddr,6);
				WLAN_SYS_StatusCallback(&event);	
				break;
			case ATBM_WIFI_DEASSOC_EVENT:
				break;
			case ATBM_WIFI_JOIN_EVENT:			
				staMacAddr =(atbm_uint8 *) param;
				event.event_type = WLAN_E_ASSOC_IND;
				memcpy(event.addr.mac,staMacAddr,6);
				WLAN_SYS_StatusCallback(&event);					
				break;
			default:
				break;
		}
	}
	else {	
		switch(eventid){
			case ATBM_WIFI_SCANSTART_EVENT:
				break;
			case ATBM_WIFI_SCANDONE_EVENT:				
				event.event_type = WLAN_E_SCAN_COMPLETE;
				WLAN_SYS_StatusCallback(&event);	
				break;
			case ATBM_WIFI_DEAUTH_EVENT:				
				event.event_type = WLAN_E_LINK;
				event.flags = 0;
				memcpy(event.addr.mac,priv->bssid,6);
				WLAN_SYS_StatusCallback(&event);
				break;
			case ATBM_WIFI_AUTH_EVENT:
				break;
			case ATBM_WIFI_ASSOC_EVENT:				
				event.event_type = WLAN_E_LINK;
				memcpy(event.addr.mac,priv->bssid,6);
				event.flags = 1;
				WLAN_SYS_StatusCallback(&event);
				break;
			case ATBM_WIFI_DEASSOC_EVENT:
				break;
			case ATBM_WIFI_JOIN_EVENT:	
				event.event_type = WLAN_E_PSK_SUP;
				memcpy(event.addr.mac,priv->bssid,6);
				WLAN_SYS_StatusCallback(&event);				
				break;
			default:
				break;
		}
	}
	#endif
}
//static struct atbm_sdio_driver atmbwifi_driver;
extern int atbm_sdio_probe(struct atbm_sdio_func *func,const struct atbm_sdio_device_id *id);
extern void atbm_sdio_disconnect(struct atbm_sdio_func *func);
//static const struct atbm_sdio_device_id atbm_sdio_ids[] = {
	//{ SDIO_DEVICE(SDIO_ANY_ID, SDIO_ANY_ID) },
	//{ /* end: all zeroes */			},
//};
int atbm_sdio_register_init()
{
#if STM32_UCOS
	struct atbm_sdio_func * atbm_func =(struct atbm_sdio_func*)&func;
	atbm_sdio_probe(atbm_func,ATBM_NULL);
#else
	int ret =0;
	atbm_memcpy(atmbwifi_driver.name, "atbm6021",sizeof("atbm6021"));;
	atmbwifi_driver.match_id_table	= atbm_sdio_ids;
	atmbwifi_driver.probe_func		= atbm_sdio_probe;
	atmbwifi_driver.discon_func		= atbm_sdio_disconnect;
	ret = atbm_sdio_register(&atmbwifi_driver);
	if (ret){
		wifi_printk(WIFI_DBG_ERROR,"atbmwifi usb driver register error\n");	
		return ret;
	}
	return 0;
	
#endif
}
int atbm_sdio_register_deinit(atbm_void)
{
#if 0
	atbm_sdio_deregister(&atmbwifi_driver);
#endif
	return 0;
}
atbm_uint32 atbm_os_random()
{
	atbm_uint32 data = atbm_random()/3;
	return (data>>1);
}
