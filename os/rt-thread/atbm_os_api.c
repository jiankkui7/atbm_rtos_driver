/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/
#include "atbm_hal.h"
/******** Functions below is Wlan API **********/
#include <usb.h>
#include <rtdef.h>
#include <rtthread.h>
#include <rtdevice.h>
#include <rthw.h>
#include <dma_mem.h>
#include <interrupt.h>
#include <sys/types.h>
#include <sys/time.h>
#include <lwip/netifapi.h>
#include <lwip/tcpip.h>
#include <lwip/dns.h>
#include <lwip/dhcp.h>
#include <lwip/netif.h>
#include <lwip/netifapi.h>
#include "lwip/opt.h"

#include <usb_wifi.h>

int atbmwifi_event_OsCallback(atbm_void *prv,int eventid,atbm_void *param)
{
	struct atbmwifi_vif *priv = prv;

	if(atbmwifi_is_ap_mode(priv->iftype)){
		atbm_uint8 * staMacAddr ;
		switch(eventid){

			case ATBM_WIFI_DEAUTH_EVENT:
				wifi_printk(WIFI_ALWAYS,"event_OsCallback DEAUTH\n");
				
				break;
			case ATBM_WIFI_AUTH_EVENT:
				break;
			case ATBM_WIFI_ASSOC_EVENT:
				break;
			case ATBM_WIFI_ASSOCRSP_TXOK_EVENT: 
				staMacAddr =(atbm_uint8 *) param;

				break;
			case ATBM_WIFI_DEASSOC_EVENT:
				break;
			case ATBM_WIFI_JOIN_EVENT:			
				staMacAddr =(atbm_uint8 *) param;
				atbm_printk("ATBM_WIFI_JOIN_EVENT\n");
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
				break;
			case ATBM_WIFI_DEAUTH_EVENT:				
				
				break;
			case ATBM_WIFI_AUTH_EVENT:
				break;
			case ATBM_WIFI_ASSOC_EVENT:				
				
				break;
			case ATBM_WIFI_DEASSOC_EVENT:
				break;
			case ATBM_WIFI_JOIN_EVENT:
				if(atbmwifi_is_sta_mode(priv->iftype))
					wifi_printk(WIFI_ALWAYS,"Do Station other things\n");
				break;
			default:
				break;
		}
	}
}
struct atbmusb_info
{
    const char        *name;
    atbm_uint8            ep_in;        /* bulk/intr source */
    atbm_uint8            ep_out;        /* bulk/intr sink */
    unsigned        autoconf:1;
    unsigned        ctrl_out:1;
    unsigned        iso:1;        /* try iso in/out */
    int            alt;
};

static struct atbmusb_info atbm_info = {
    .name        = "ATBM-USB device",
    .ep_in        = 1,
    .ep_out        = 2,
    .alt        = 1,
};

static const struct usb_device_id atbm_usb_ids[] =
{
    { USB_DEVICE(0x0547, 0x2235),
        .driver_info = (unsigned long) &atbm_info,
    },
};

extern int atbm_usb_probe(struct atbm_usb_interface *intf,const struct atbm_usb_device_id *id);
extern atbm_void atbm_usb_disconnect(struct atbm_usb_interface *intf);

static atbm_usb_driver atmbwifi_driver = {
	.name = 	   "atbm6022",
	.id_table =    atbm_usb_ids,
	.probe =	atbm_usb_probe,
	.disconnect =	 atbm_usb_disconnect,
};

atbm_uint32 atbm_usb_register_init()
{
	int ret =0;
	ret = atbm_usb_register(&atmbwifi_driver);
	if (ret){
		wifi_printk(WIFI_DBG_ERROR,"atbmwifi usb driver register error\n");	
		return ret;
	}
	return 0;
}
atbm_uint32 atbm_usb_register_deinit()
{
	atbm_usb_deregister(&atmbwifi_driver);
}
atbm_void atbm_usb_int(){
	atbm_usb_module_init();
}
atbm_void atbm_usb_exit(){
	atbm_usb_module_exit();
}
usbwifi_handle_t p_usb_handle;
usbwifi_handle_t usbwifi_sta_init(wifi_device_type_t wifi_type){

}
void usbwifi_sta_connect(usbwifi_handle_t handle, wifi_sta_cfg_t *p_cfg){

}
void usbwifi_sta_disconnect(usbwifi_handle_t handle){

}
void usbwifi_sta_search(usbwifi_handle_t handle){

}
void usbwifi_sta_get_apcnt(usbwifi_handle_t handle, signed long *ap_cnt){

}
int usbwifi_sta_get_apinfo(usbwifi_handle_t handle, unsigned long index, wifi_found_ap_info_t *p_info){

}
int usbwifi_sta_status(usbwifi_handle_t handle){

}


