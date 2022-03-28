/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/
#define ATBM_WIFI_DRIVER_API_H 1
#include "atbm_hal.h"
/******** Functions below is Wlan API **********/
#include "wlan_ATBM.h"
#include "atbm_os_sdio.h"
int atbmwifi_event_OsCallback(atbm_void *prv,int eventid,atbm_void *param)
{
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
				event.event_type = WLAN_E_PSK_SUP;
				memcpy(event.addr.mac,priv->bssid,6);
				event.flags = 1;
				WLAN_SYS_StatusCallback(&event);
				break;
			case ATBM_WIFI_DEASSOC_EVENT:
				break;
			case ATBM_WIFI_JOIN_EVENT:	
				event.event_type = WLAN_E_LINK;
				memcpy(event.addr.mac,priv->bssid,6);
				event.flags = 1;
				WLAN_SYS_StatusCallback(&event);				
				break;
			default:
				break;
		}
	}
}

#define GET_INTERFACE_INFO(cl,sc,pr) \
        USBDEV_MATCH_ID_VENDOR|USBDEV_MATCH_ID_PRODUCT,(sc), (pr),0,0,0,0,0,(cl), 0,0,0


static struct usb_device_id atbm_usb_ids[] =
{
    /* Generic USB  Class */
    {GET_INTERFACE_INFO(USB_CLASS_VENDOR_SPEC, 0x007a, 0x8888) }, //ATBM USB Device 
    {GET_INTERFACE_INFO(USB_CLASS_VENDOR_SPEC, 0x1B20, 0x8888) }, //SigmaStar USB Device 
    {0,0,0,0,0,0,0,0,0,0,0,0}
};

static struct atbm_usb_driver atmbwifi_driver;
extern int atbm_usb_probe(struct atbm_usb_interface *intf,const struct atbm_usb_device_id *id);
extern atbm_void atbm_usb_disconnect(struct atbm_usb_interface *intf);

int atbm_usb_register_init()
{
	int ret =0;
	atbm_memcpy(atmbwifi_driver.name, "atbm6022",sizeof("atbm6022"));;
	atmbwifi_driver.match_id_table	= atbm_usb_ids;
	atmbwifi_driver.probe_func		= atbm_usb_probe;
	atmbwifi_driver.discon_func		= atbm_usb_disconnect;
	ret = atbm_usb_register(&atmbwifi_driver);
	if (ret){
		wifi_printk(WIFI_DBG_ERROR,"atbmwifi usb driver register error\n");	
		return ret;
	}
	return 0;
}
int atbm_usb_register_deinit()
{
	atbm_usb_deregister(&atmbwifi_driver);
}

atbm_uint32 atbm_os_random()
{
	atbm_uint32 data = atbm_random()/3;
	return (data>>1);
}
