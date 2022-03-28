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
#include "atbm_sysops.h"
#include <stdint.h>
#include "netif/etharp.h"
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "lwip/capture.h"
#include "lwip/dhcp.h"
#include "akos_api.h"
#include "drv_api.h"
#include "platform_devices.h"
#include "dev_drv.h"
#include "drv_gpio.h"
#include "err.h"
#include "wifi.h"
static atbm_uint8 ip_addr = 0;
extern err_t atbm_wifi_tx_pkt_netvif(struct netif *netif, struct pbuf *p);
#if (PLATFORM==AK_RTOS_300)
extern err_t etharp_output(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr);
#else
extern err_t etharp_output(struct netif *netif, struct pbuf *q, ip_addr_t *ipaddr);
#endif
int atbm_akwifistation_netif_init(void);
int atbm_akwifi_netif_init(void);

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
				wifi_printk(WIFI_ALWAYS, "ATBM_WIFI_JOIN_EVENT\n");
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
				//wifi_printk(WIFI_ALWAYS, "~~~~ATBM_WIFI_JOIN_EVENT\n");
				//if(atbmwifi_is_sta_mode(priv->iftype))
					//atbm_akwifistation_netif_init();
				break;
			case ATBM_WIFI_WPS_SUCCESS:
				{
					struct atbm_wpa_ssid *ssid = (struct atbm_wpa_ssid *)param;
					wifi_printk(WIFI_ALWAYS, "ssid:%s ssidlen:%d key:%s keylen:%d mgmt:%d id:%d\n", ssid->ssid, ssid->ssid_len, ssid->passphrase, strlen(ssid->passphrase), ssid->key_mgmt, ssid->wep_tx_keyidx);
					wpa_connect_ap(priv, ssid->ssid, ssid->ssid_len, ssid->passphrase, strlen(ssid->passphrase), 2, ssid->wep_tx_keyidx);
				}
				break;
			default:
				break;
		}
	}
}

#if ATBM_USB_BUS
#define GET_INTERFACE_INFO(cl,sc,pr) \
        USBDEV_MATCH_ID_VENDOR|USBDEV_MATCH_ID_PRODUCT,(sc), (pr),0,0,0,0,0,(cl), 0,0,0


static struct usb_device_id atbm_usb_ids[] =
{
    /* Generic USB  Class */
    {GET_INTERFACE_INFO(USB_CLASS_VENDOR_SPEC, 0x007a, 0x8888) }, // 
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
#elif ATBM_SDIO_BUS
static struct atbm_sdio_driver atmbwifi_driver;
extern int atbm_sdio_probe(struct atbm_sdio_func *func,const struct atbm_sdio_device_id *id);
extern int atbm_sdio_disconnect(struct atbm_sdio_func *func);
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
	wifi_printk(WIFI_ALWAYS, "atbm_sdio_register_init\r\n");
	ret = atbm_sdio_register(&atmbwifi_driver);
	if (ret){
		wifi_printk(WIFI_DBG_ERROR,"atbmwifi usb driver register error\n");	
		return ret;
	}
	return 0;
}
int atbm_sdio_register_deinit()
{
	atbm_sdio_deregister(&atmbwifi_driver);
	return 0;
}
#endif
void atbm_akwifi_slect_sdio(int slect_gpio)
{
	/*
	*select sdio mode
	*/
	wifi_printk(WIFI_ALWAYS, "atbm_akwifi_slect_sdio slect sdio mode,pin(%d)\r\n",slect_gpio);
	gpio_set_pin_as_gpio(slect_gpio);
	gpio_set_pull_up_r(slect_gpio,0);
	gpio_set_pull_down_r(slect_gpio,0);
	gpio_set_pin_dir(slect_gpio,0);
//	gpio_set_pin_level(wifi->gpio_int.nb,0);
	atbm_SleepMs(200);
}

void atbm_akwifi_reset_sdio(int reset_gpio)
{
	/*
	*reset
	*/
	gpio_set_pin_as_gpio(reset_gpio);
	gpio_set_pull_down_r(reset_gpio,0);
	gpio_set_pin_dir(reset_gpio,1);
	wifi_printk(WIFI_ALWAYS, "atbm_akwifi_reset_sdio reset  0(%d)\r\n",reset_gpio);
	gpio_set_pin_level(reset_gpio,0);
	atbm_SleepMs(10);
	gpio_set_pin_level(reset_gpio,1);
	wifi_printk(WIFI_ALWAYS, "atbm_akwifi_reset_sdio reset  1(%d)\r\n",reset_gpio);
}

#if 1
int atbm_akwifi_setup_sdio(void)
{
	int fd;
	int ret= 0;
	uint8_t width = USE_FOUR_BUS; //USE_ONE_BUS;
	T_WIFI_INFO  *wifi =  ATBM_NULL; //(T_WIFI_INFO *)wifi_dev.dev_data;
	fd = dev_open(DEV_WIFI);
    if(fd < 0)
    {
        wifi_printk(WIFI_DBG_ERROR, "open wifi faile\r\n");
        return -1;
    }
	dev_read(fd,  &wifi, sizeof(unsigned int *));
	
	gpio_share_pin_set( ePIN_AS_SDIO , wifi->sdio_share_pin);
	//atbm_akwifi_slect_sdio(wifi->gpio_int.nb);
	atbm_akwifi_reset_sdio(wifi->gpio_reset.nb);
	if(1 == wifi->bus_mode)
	{
		width = USE_ONE_BUS;
		
		wifi_printk(WIFI_DBG_ERROR, "atbm_akwifi_init reset  USE_ONE_BUS\r\n");
	}else if(4 == wifi->bus_mode)
	{
		width = USE_FOUR_BUS;
		
		wifi_printk(WIFI_DBG_ERROR, "atbm_akwifi_init reset  USE_FOUR_BUS\r\n");
	}	
	dev_close(fd);
	
	ret = sdio_initial(3, width , ATBM_SDIO_BLOCK_SIZE);//(3, width , 512)
	if(ret == false){
		wifi_printk(WIFI_DBG_ERROR, "sdio_initial (%d) err\r\n",ret);
		return -1;
	}
//	sdio_set_clock(wifi->clock, get_asic_freq(), 0); // SD_POWER_SAVE_ENABLE
	
	wifi_printk(WIFI_ALWAYS, "atbm_akwifi_setup_sdio success\n");
	return 0;
}
#else
int atbm_akwifi_setup_sdio(void)
{
	int ret;
	ret = sdio_initial(3, USE_FOUR_BUS , 256);//(3, width , 512)
	if(ret == 0){
		return -1;
	}	
	return 0;
}
#endif

/**
 * @brief initializing wifi 
 * @author
 * @date 
 * @param [in] pParam a pointer to T_WIFI_INITPARAM type
 * @return int
 * @retval   0  initializing sucessful
 * @retval  -1 initializing fail
 */
int atbm_akwifi_init(int init_param)
{
	int ret = 0;
	
	ret = atbm_akwifi_setup_sdio();

	if(ret <0 ){
		iot_printf("atbm_akwifi_init err\n");

		return -1;
	}
	if(init_param == 0){
		#if ATBM_USB_BUS
//		atbm_usb_register_init();
		#else
		atbm_sdio_module_init();
		#endif
		tcpip_init(ATBM_NULL,ATBM_NULL);
	}

	return 0;
}
struct netif *atbm_priv_get_netif(void)
{
	return g_vmac->ndev->nif;
}
atbm_uint8 atbm_get_wifimode(void)
{
	return g_vmac->iftype;
}
void atbm_akwifi_get_netif_addr(struct ip_info *wifi_ip_info)
{
	struct netif *p_netif = ATBM_NULL;
	if(!atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"wifistation_netif_init err\n");	
		return ;
	}

	p_netif = atbm_priv_get_netif();

	if(p_netif == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR,"wifi_get_netif_addr p_netif == ATBM_NULL\n");	
		return ;
	}

	wifi_ip_info->ipaddr.addr = p_netif->ip_addr.addr;
	wifi_ip_info->netmask.addr = p_netif->netmask.addr;
	wifi_ip_info->gw.addr = p_netif->gw.addr;
}
atbm_uint32 atbm_os_random()
{
	atbm_uint32 data = atbm_random()/3;
	return (data>>1);
}
static void atbm_akwifi_set_netaddr(struct netif *netif){
	struct atbmwifi_vif *priv = (struct atbmwifi_vif *)(netif->state);
	struct atbmwifi_common	*hw_priv = ATBM_NULL;
	ATBM_BUG_ON(priv != g_vmac);
	hw_priv = priv->hw_priv;
	netif->hwaddr_len = 6;
	atbm_memcpy(netif->hwaddr,priv->mac_addr,netif->hwaddr_len);
		
	wifi_printk(WIFI_ALWAYS,"atbm_akwifi_set_netaddr:"MACSTR"\n",MAC2STR(netif->hwaddr));
}

err_t atbm_akwifi_if_init(struct netif *netif)
{
	netif->state = g_vmac;
	netif->output = etharp_output;
	netif->linkoutput = atbm_wifi_tx_pkt_netvif;
	/* set MAC hardware address length */
	atbm_akwifi_set_netaddr(netif);
	netif->hwaddr_len = 6;


	/* maximum transfer unit */
	netif->mtu = 1500;

	/* device capabilities */
	/* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
	return 0;
}


int atbm_akwifi_netif_init(void)
{
#if (PLATFORM==AK_RTOS_300)
		struct ip4_addr ipaddr, netmask, gw;
#else
		struct ip_addr ipaddr, netmask, gw;
#endif
	struct netif *p_netif = ATBM_NULL;
	const char * IP_ADDR = 	"192.168.43.1";
	const char * GW_ADDR = 	"192.168.43.1";
	const char * MASK_ADDR = 	"255.255.255.0";
	
	if(!atbm_wifi_initialed()){
		printk("wifi_netif_init err\n");	
		return 0;
	}
	
	gw.addr = inet_addr(GW_ADDR);
	ipaddr.addr = inet_addr(IP_ADDR);
	netmask.addr = inet_addr(MASK_ADDR);

	p_netif = atbm_priv_get_netif();

	if(p_netif == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init p_netif == ATBM_NULL\n");	
		return 0;
	}
	netif_remove(p_netif);
	if (netif_add(p_netif, &ipaddr, &netmask, &gw, (void*)g_vmac, atbm_akwifi_if_init, tcpip_input) == 0)
	{
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init netif_add err\n");	
		return  - 1;
	}

	netif_set_default(p_netif);
	netif_set_up(p_netif);

	dhcps_stop();
	dhcps_start(ipaddr);
	
	return 0;
}

void dhcp_restart(struct netif *p_netif)
{
	dhcp_stop(p_netif);
	atbm_mdelay(50);
	dhcp_start(p_netif);
	return;
}
static int restart_cnt;
int atbm_akwifistation_netif_init(void)
{
#if (PLATFORM==AK_RTOS_300)
	struct ip4_addr ipaddr, netmask, gw;
#else
	struct ip_addr ipaddr, netmask, gw;
#endif
	unsigned int start_time;
	struct netif *p_netif = ATBM_NULL;
	
	wifi_printk(WIFI_DBG_ERROR,"atbm_akwifistation_netif_init\n");	
	if(!atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"wifistation_netif_init err\n");	
		return 0;
	}
	p_netif = atbm_priv_get_netif();

	if(p_netif == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init p_netif == ATBM_NULL\n");	
		return 0;
	}
	gw.addr =  0;
	ipaddr.addr = 0;
	netmask.addr = 0;
	netif_remove(p_netif);
	netif_set_down(p_netif);
	//dhcp_stop(p_netif);
	
	if (netif_add(p_netif, &ipaddr, &netmask, &gw, (void*)g_vmac, atbm_akwifi_if_init, tcpip_input) == 0)
	{
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init netif_add err\n");	
		return  - 1;
	}
	
	netif_set_default(p_netif);
	netif_set_up(p_netif);
	restart_cnt = 0;

	//if (dhcp_start(p_netif) !=0)
	//{
	//	wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init dhcp_start err\n");	
	//	return -1;
	//}
	return 0;
}
/**
 * @brief  wifi_netif_deinit, remove netif of wifi
 * @param  : 
 * @retval void
 */
void atbm_akwifi_netif_deinit(void)
{
	struct netif *p_netif = NULL;
	
	if(!atbm_wifi_initialed()){
		printk("wifi_netif_deinit err\n");	
		return ;
	}
	
	p_netif = atbm_priv_get_netif();
	if(p_netif == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_deinit p_netif == ATBM_NULL\n");	
		return;
	}
	if(atbm_get_wifimode() == WIFI_MODE_STA)
		dhcp_stop(p_netif);
	else if(atbm_get_wifimode() == WIFI_MODE_AP)
		dhcps_stop();
	atbm_akwifi_set_netaddr(p_netif);

	netif_set_down(p_netif);
	netif_remove(p_netif);
}

