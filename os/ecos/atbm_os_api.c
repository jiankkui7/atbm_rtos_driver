/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "atbm_hal.h"
#include "atbm_os_api.h"

int atbmwifi_event_OsCallback(struct atbmwifi_vif *priv,int eventid,atbm_void *param)
{
}

static struct atbm_usb_device_id atbm_usb_ids[] = {
	/*vendor id, product id*/
	{USB_DEVICE(0x007a, 0x8888)},
	{ }/* Terminating entry */
};

static atbm_usb_driver atmbwifi_driver;

extern int atbm_usb_probe(struct atbm_usb_interface *intf,const struct atbm_usb_device_id *id);
extern atbm_void atbm_usb_disconnect(struct atbm_usb_interface *intf);
static atbm_int8 tmp_buf[16];
int atbm_usb_register_init(atbm_void)
{
	int ret =0;
	//memcpy(atmbwifi_driver.name, "atbm6022",sizeof("atbm6022"));
#if 1
	atbm_memset(tmp_buf, 0, 16);
	atbm_memcpy(tmp_buf, "atbm6022", 8);
	atmbwifi_driver.name = tmp_buf;
	atmbwifi_driver.probe		= atbm_usb_probe;
	atmbwifi_driver.disconnect		= atbm_usb_disconnect;
	atmbwifi_driver.id_table	= atbm_usb_ids;
#endif
	ret = atbm_usb_register(&atmbwifi_driver);
	if (ret){
		wifi_printk(WIFI_DBG_ERROR,"atbmwifi usb driver register error\n");	
		return ret;
	}
	wifi_printk(WIFI_DBG_MSG,"atbm: usb register successed...\n");

	//atbm_wifi_on(ATBM_WIFI_STA_MODE);
	//wifi_ConnectAP("wifi_test_ap7",strlen("wifi_test_ap7"),"1234567890",10,ATBM_KEY_WPA2);
	//wifi_ConnectAP("gg",strlen("gg"),"11111111",8,ATBM_KEY_WPA2);
	//atbm_wifi_on(ATBM_WIFI_AP_MODE);
	//atbm_wifi_ap_create("RTK_RTOS", 4, 4,"1234567890", 1, 0);

	return 0;
}
int atbm_usb_register_deinit(atbm_void)
{
	atbm_usb_deregister(&atmbwifi_driver);
}

atbm_uint32 atbm_os_random(void)
{
	atbm_uint32 data = atbm_random();
	return data;
}

