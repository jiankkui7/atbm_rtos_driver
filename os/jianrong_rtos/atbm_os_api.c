/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/
#include "atbm_hal.h"
#include "atbm_os_sdio.h"
#include "atbm_wifi_driver_api.h"
extern int atbm_sdio_probe(struct atbm_sdio_func *func,const struct atbm_sdio_device_id *id);
extern int atbm_sdio_disconnect(struct atbm_sdio_func *func);
extern struct atbmwifi_vif *  g_vmac;
extern struct atbmwifi_common g_hw_prv;

atbm_uint32 atbm_os_random()
{
	atbm_uint32 data = atbm_random()/3;
	return (data>>1);
}
int atbm_wifi_get_mac(unsigned char *mac_addr)
{
	memcpy(mac_addr,g_hw_prv.mac_addr,6);

	return 0;
}


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
				wifi_printk(WIFI_ALWAYS,"ATBM_WIFI_JOIN_EVENT\n");
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
//				event.event_type = WLAN_E_SCAN_COMPLETE;
//				WLAN_SYS_StatusCallback(&event);	
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
				wifi_printk(WIFI_ALWAYS,"ATBM_WIFI_JOIN_EVENT\n");
				if(atbmwifi_is_sta_mode(priv->iftype))
					atbm_register_Station_netdevice(priv->ndev);
				break;
			default:
				break;
		}
	}
}
static struct atbm_sdio_driver atmbwifi_driver;
static struct atbm_sdio_device_id atbm_sdio_ids[] = {
	//{ SDIO_DEVICE(SDIO_ANY_ID, SDIO_ANY_ID) },
	{ /* end: all zeroes */			},
};
int atbm_sdio_register_init()
{	
	int ret =0;
	atbm_memcpy(atmbwifi_driver.name, "atbm6021",sizeof("atbm6021"));;
	atmbwifi_driver.match_id_table	= atbm_sdio_ids;
	atmbwifi_driver.probe_func		= atbm_sdio_probe;
	atmbwifi_driver.discon_func		= atbm_sdio_disconnect;	
	ret = atbm_sdio_register(&atmbwifi_driver);
	if (ret){
		return ret;
	}
	return 0;
}
int atbm_sdio_register_deinit()
{
	atbm_sdio_deregister(&atmbwifi_driver);
	return 0;
}

#if (PLATFORM==JIANRONG_RTOS_3268)

#else
extern struct mmc_host bw_mmc_host;

#endif
static int atbm_wifi_init_sdio(void)
{
	wifi_printk(WIFI_ALWAYS,"atbm_wifi_init_sdio \n");
	int ret= 0;
#if (PLATFORM==JIANRONG_RTOS_3268)
	wifi_printk(WIFI_ALWAYS,"atbm_wifi_init_sdio 1\n");
	ret = sd_init();			
#else
	struct mmc_host *sd_host;
		sd_host = &bw_mmc_host; 
	ret = sdio_init(sd_host,sd_host->card);
#endif
	if(ret) 
		return -2;
	return 0;
}
int wifi_init(void *init_param)
{
	wifi_printk(WIFI_ALWAYS,"wifi_init \n");
	return atbm_wifi_init_sdio();
}

