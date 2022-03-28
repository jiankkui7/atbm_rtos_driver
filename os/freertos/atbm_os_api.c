/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "atbm_hal.h"

int atbmwifi_event_OsCallback(struct atbmwifi_vif *priv,int eventid,atbm_void *param)
{
}

extern int atbm_usb_probe(struct atbm_usb_interface *intf,const struct atbm_usb_device_id *id);
extern atbm_void atbm_usb_disconnect(struct atbm_usb_interface *intf);

static struct atbm_usb_driver atmbwifi_driver;

int atbm_usb_register_init()
{
	int ret =0;
	memcpy(atmbwifi_driver.name, "atbm6022",sizeof("atbm6022"));;
	//atmbwifi_driver.match_id_table	= atbm_usb_ids;
	atmbwifi_driver.probe_func		= atbm_usb_probe;
	atmbwifi_driver.discon_func		= atbm_usb_disconnect;
	ret = atbm_usb_register(&atmbwifi_driver);
	if (ret){
		wifi_printk(WIFI_DBG_ERROR,"atbmwifi usb driver register error\n");	
		return ret;
	}
	
	//atbm_wifi_on(ATBM_WIFI_STA_MODE);
	//wifi_ConnectAP("wifi_test_ap7",strlen("wifi_test_ap7"),"1234567890",10,ATBM_KEY_WPA2);
	atbm_wifi_on(ATBM_WIFI_AP_MODE);
	atbm_wifi_ap_create("RTK_RTOS_wp", 0x0080, 4,"1234567890", 1, 0);
	//atbm_wifi_ap_create("RTK_RTOS_open", 0, 0,"", 1, 0);
	
	return 0;
}
int atbm_usb_register_deinit()
{
	atbm_usb_deregister(&atmbwifi_driver);
}

atbm_uint32 atbm_os_random()
{
	atbm_uint32 data = atbm_random();
	return data;
}
