/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed,
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/
#include <stdint.h>
#include <xs/driver/gpio_drv.h>
#include <netmgr/wifi.h>
#include <xs/device.h>

#include "atbm_hal.h"
#include "atbm_os_sdio.h"
#include "atbm_os_api.h"
#include "lwip/tcpip.h"
#include "lwip/netifapi.h"
#include "lwip/sockets.h"
#include "lwip/dhcp.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"
#include "lwip/init.h"

extern struct atbmwifi_common g_hw_prv;
extern struct atbmwifi_vif *  g_vmac;
extern err_t atbm_wifi_tx_pkt_netvif(struct netif *netif, struct pbuf *p);

static atbm_uint8 ip_addr = 0;
static uint8_t netif_init_flag = 0;
static uint8_t connected_flag = 0;

int atbmwifi_event_OsCallback(atbm_void *prv,int eventid,atbm_void *param)
{
	struct atbmwifi_vif *priv = prv;

	if(atbmwifi_is_ap_mode(priv->iftype)){
		atbm_uint8 * staMacAddr ;
		switch(eventid){

			case ATBM_WIFI_DEAUTH_EVENT:
				wifi_printk(WIFI_ALWAYS,"event_OsCallback DEAUTH\r\n");

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
				wifi_printk(WIFI_ALWAYS,"ATBM_WIFI_JOIN_EVENT\r\n");
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
				wifi_printk(WIFI_ALWAYS, "~~~~ATBM_WIFI_JOIN_EVENT\r\n");
				if(atbmwifi_is_sta_mode(priv->iftype) && netif_init_flag == 0) {
					atbm_wifi_netif_init();
					netif_init_flag = 1;
				}
				break;
			default:
				break;
		}
	}
}

static ATBM_SECURITY_TYPE __atbm_wifi_keytype(int key_type)
{
	return key_type;
}

int __atbm_wifi_initialed(void)
{
	return (g_vmac != ATBM_NULL);
}

static enum atbm_nl80211_iftype __atbm_skwifimode_to_nl80211(enum xs_wifi_mode mode)
{
	enum atbm_nl80211_iftype if_type = ATBM_NUM_NL80211_IFTYPES;

	switch(mode)
	{
		case XS_WIFI_MODE_STATION:
			if_type = ATBM_NL80211_IFTYPE_STATION;
			break;
		case XS_WIFI_MODE_AP:
		case XS_WIFI_MODE_ADHOC:
			if_type = ATBM_NL80211_IFTYPE_AP;
			break;
		default:
			if_type = ATBM_NUM_NL80211_IFTYPES;
			break;
	}

	return if_type;
}

int atbm_wifi_get_mac(unsigned char *mac_addr)
{
	memcpy(mac_addr,g_hw_prv.mac_addr,6);

	return 0;
}

atbm_uint32 atbm_os_random(void)
{
	atbm_uint32 data = atbm_random()/3;
	return (data>>1);
}

enum xs_wifi_mode atbm_wifi_get_mode(void)
{
	switch(g_vmac->iftype) {
	case ATBM_NL80211_IFTYPE_STATION:
	case ATBM_NL80211_IFTYPE_P2P_CLIENT:
		return XS_WIFI_MODE_STATION;
		break;
	case ATBM_NL80211_IFTYPE_AP:
	case ATBM_NL80211_IFTYPE_P2P_GO:
		return XS_WIFI_MODE_AP;
	default:
		return XS_WIFI_MODE_UNKNOW;

	}
}

/**
 * @brief  wifi_set_mode, set wifi mode.
 * ap_wifi_dev and sta_wifi_dev are two different device, set mode just set the global variable wifi_dev
 * @param  :
 * @retval AK_WIFI_MODE
 */
int atbm_wifi_set_mode(enum xs_wifi_mode type)
{
	enum atbm_nl80211_iftype if_type= ATBM_NUM_NL80211_IFTYPES;
	if(!__atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"not init\n");
		return -1;
	}
	if((type<XS_WIFI_MODE_STATION)||(type>XS_WIFI_MODE_ADHOC))
		return -1;

	if_type = __atbm_skwifimode_to_nl80211(type);

	if(if_type == ATBM_NUM_NL80211_IFTYPES)
		return -1;

	atbmwifi_start_wifimode(g_vmac,if_type);

	return 0;
}

/*
 * @brief  wifi_isconnected, return wifi connect status
 * @param  :
 * @retval 1 - connect , 0 - not connected
 */
int atbm_wifi_disconnect(void)
{
	if(!__atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"not init\n");
		return -1;
	}
	//AT_WDisConnect_vif(g_vmac,ATBM_NULL);
	AT_WDisConnect(ATBM_NULL);
	connected_flag = 0;
	netif_init_flag = 0;
	return 0;
}

/**
 * @brief  wifi_connect, wifi connect to ap
 * @param  : ssid, key
 * @retval 0 - send connect msg ok , -1 - some error happen
 */
int atbm_wifi_connect(char *ssid, char *password)
{
	ip_addr = 0;
	TickType_t t1, t2, connect_wait = 0;

	if (connected_flag == 1) {
		AT_WDisConnect(ATBM_NULL);
		connected_flag = 0;
	}

	if(!__atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"no init\n");
		return -1;
	}
	if((ssid == ATBM_NULL)){
		wifi_printk(WIFI_DBG_ERROR,"wifi_connect ssid err\r\n");
		return -1;
	}

	t1 = xTaskGetTickCount();
	atbmwifi_start_wifimode(g_vmac,ATBM_NL80211_IFTYPE_STATION);

	if (strlen(password) == 0)
		wifi_ConnectAP_vif(g_vmac,ssid,strlen(ssid),password,0,ATBM_KEY_NONE);
	else
		wifi_ConnectAP_vif(g_vmac,ssid,strlen(ssid),password,strlen(password),ATBM_KEY_WPA2);

	while(ip_addr == 0 && connect_wait < 30 * 1000){
		atbm_SleepMs(100);
		connect_wait+=100;
	}

	if(ip_addr) {
		t2 = xTaskGetTickCount();
		wifi_printk(WIFI_ALWAYS,"%s Connect time %f\n", __func__, (float)(t2 - t1)/1000);
		connected_flag = 1;
	} else {
		wifi_printk(WIFI_ALWAYS,"%s timeout\n", __func__);
		atbm_wifi_disconnect();
	}
	return 0;
}

/**
 * @brief  wifi_isconnected, return wifi connect status
 * @param  :
 * @retval 1 - connect , 0 - not connected
 */
int atbm_wifi_isconnected(void)
{
	if(!__atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"not init\n");
		return 0;
	}
	return g_vmac->connect_ok;
}

int atbm_wifi_create_ap(struct _apcfg *ap_cfg)
{
	//todo check ap_cfg
	if(!__atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"not init\n");
		return -1;
	}
	atbmwifi_start_wifimode(g_vmac,ATBM_NL80211_IFTYPE_AP);
	wifi_StartAP_vif(g_vmac,ap_cfg->ssid,ap_cfg->ssid_len,
		ap_cfg->key,ap_cfg->key_len,ap_cfg->channel,__atbm_wifi_keytype(ap_cfg->enc_protocol),0);

	return 0;
}

int atbm_wifi_destroy_ap(void)
{
	if(!__atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"not init\n");
		return -1;
	}
	atbmwifi_stop_wifimode(g_vmac,ATBM_NL80211_IFTYPE_AP);
}


int atbm_wifi_scan(wifi_ap_list_t *ap_list)
{
	struct atbmwifi_common *hw_priv = &g_hw_prv;
	atbm_uint8 i = 0;
	struct atbmwifi_scan_result_info *info;
	wifi_ap_info_t *bss_info = ATBM_NULL;
	atbm_uint8 scan_cnt = 0;
	atbm_uint8 ssd_len = 0;
	if(!__atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"not init\n");
		return -1;
	}

	atbmwifi_start_wifimode(g_vmac,ATBM_NL80211_IFTYPE_STATION);
	vTaskDelay(2000 / portTICK_PERIOD_MS);
	if(atbmwifi_scan_process(g_vmac)){
			return -2;
	}
	memset(ap_list,0,sizeof(wifi_ap_list_t));
	//wait scan done,, wait scan complete
	while(1){
		atbm_mdelay(1000);
		if(hw_priv->scan.in_progress==0)
			break;
	}
	wifi_printk(WIFI_ALWAYS,"wait scan done--,scan_ret.len(%d)\r\n",hw_priv->scan_ret.len);

	scan_cnt = hw_priv->scan_ret.len < MAX_AP_COUNT ? hw_priv->scan_ret.len:MAX_AP_COUNT;
	bss_info = &ap_list->ap_info[0];
	for(i=0;i<scan_cnt;i++){
		info = hw_priv->scan_ret.info + i;
		//Copy ATBM scanned bss list  to platform dependent BSS list
		ssd_len = info->ssidlen > ATBM_MAX_SSID_LEN ? ATBM_MAX_SSID_LEN:info->ssidlen;
		atbm_memcpy(bss_info->ssid, info->ssid, ssd_len);
		atbm_memcpy(bss_info->bssid, info->BSSID, ATBM_ETH_ALEN);

		bss_info->channel       = info->channel;
		bss_info->rssi =  info->rssi;
		bss_info->security = info->encrypt;
		bss_info++;
		ap_list->ap_count++;
	}

	g_vmac->scan_no_connect = g_vmac->scan_no_connect_back;

	wifi_printk(WIFI_ALWAYS,"wait scan done,pScanResult->count(%d)\r\n",hw_priv->scan_ret.len);

	return 0;
}


int atbm_wifi_netstack_init(void)
{
	tcpip_init(NULL, NULL);

	return 0;
}

int atbm_wifi_init(void)
{
	
	atbm_sdio_module_init();

	return 0;
}

static __atbm_wifi_set_netaddr(struct netif *netif){
	struct atbmwifi_vif *priv = (struct atbmwifi_vif *)(netif->state);
	struct atbmwifi_common	*hw_priv = ATBM_NULL;
	ATBM_BUG_ON(priv != g_vmac);
	hw_priv = priv->hw_priv;
	netif->hwaddr_len = 6;
	atbm_memcpy(netif->hwaddr,priv->mac_addr,netif->hwaddr_len);

	wifi_printk(WIFI_ALWAYS,"%s:"MACSTR"\n", __func__, MAC2STR(netif->hwaddr));
}

err_t __atbm_wifi_if_init(struct netif *netif)
{
	netif->state = g_vmac;
	netif->output = etharp_output;
	netif->linkoutput = atbm_wifi_tx_pkt_netvif;
	/* set MAC hardware address length */
	__atbm_wifi_set_netaddr(netif);

	/* maximum transfer unit */
	netif->mtu = 1500;

	/* device capabilities */
	/* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
	return 0;
}


int atbm_wifi_netif_init(void)
{
	ip_addr_t ipaddr, netmask, gw;
	unsigned int start_time;
	struct netif *p_netif = ATBM_NULL;

	wifi_printk(WIFI_ALWAYS, "%s\n", __func__);
	if(!__atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"not init\n");
		return 0;
	}

	if (g_vmac != NULL)
		p_netif = g_vmac->ndev->nif;
	else
		return -1;

	if(p_netif == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR,"atbm netif not exist\n");
		return 0;
	}
	gw.addr =  0;
	ipaddr.addr = 0;
	netmask.addr = 0;

	netifapi_netif_remove(p_netif);
	netifapi_netif_set_down(p_netif);
	netifapi_dhcp_stop(p_netif);

	if (netifapi_netif_add(p_netif, &ipaddr, &netmask, &gw, (void*)g_vmac, __atbm_wifi_if_init, tcpip_input) != ERR_OK)
	{
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init netif_add err\r\n");
		return  - 1;
	} else {
		wifi_printk(WIFI_ALWAYS,"ADD NETIF OK\r\n");
	}

	netifapi_netif_set_default(p_netif);
	netifapi_netif_set_link_up(p_netif);
	netifapi_netif_set_up(p_netif);

	start_time = atbm_GetOsTimeMs();


	netifapi_dhcp_stop(p_netif);
	atbm_mdelay(50);
	netifapi_dhcp_start(p_netif);

	while(1)
	{
		if (!atbm_TimeAfter(start_time+20000))
		{
			wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init dhcp_start get err\r\n");
			netifapi_dhcp_stop(p_netif);
			return -1;
		}
		if (p_netif->ip_addr.addr !=0)
		{
			atbm_uint8 *ip = (atbm_uint8 *)(&p_netif->ip_addr.addr);
			ip_addr = 1;
			wifi_printk(WIFI_ALWAYS,"wifi_netif_init dhcp_start ok\r\n");
			wifi_printk(WIFI_ALWAYS,"IP[%d:%d:%d:%d]\r\n",ip[0],ip[1],ip[2],ip[3]);
			break;
		}
	}

	return 0;
}

static int __atbm_enable(struct wifi_netif_device *dev)
{
	// reset
	static gpio_t gpio_rst = {
		.array = XGPIO_LA,
		.offset = 3,
	};

	pinmux_cfg("pinmux_wifi");
	gpio_set_direction(gpio_rst, GPIO_MODE_OUTPUT);
	gpio_set_value(gpio_rst, 0);
	vTaskDelay(50 / portTICK_PERIOD_MS);
	gpio_set_value(gpio_rst, 1);

	vTaskDelay(50 / portTICK_PERIOD_MS);

	// init driver
	atbm_sdio_module_init();
}

static int __atbm_ap_connect(struct wifi_netif_device *dev, struct xs_wifi_ap *pap)
{
	atbm_wifi_connect(pap->ssid, pap->pwd);
	return 0;
}

static int __atbm_ap_disconnect(struct wifi_netif_device *dev)
{
	atbm_wifi_disconnect();
	return 0;
}

static int __atbm_ap_scan_1(struct wifi_netif_device *dev, struct xs_wifi_ap_list *ap_list)
{
	struct atbmwifi_common *hw_priv = &g_hw_prv;
	atbm_uint8 i = 0;
	struct atbmwifi_scan_result_info *info;
	atbm_uint8 scan_cnt = 0;
	atbm_uint8 ssd_len = 0;
	struct xs_wifi_ap *ap;

	if(!__atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"not init\n");
		return -1;
	}

	atbmwifi_start_wifimode(g_vmac,ATBM_NL80211_IFTYPE_STATION);
	vTaskDelay(2000 / portTICK_PERIOD_MS);
	if(atbmwifi_scan_process(g_vmac)){
		return -2;
	}
	while(1){
		atbm_mdelay(1000);
		if(hw_priv->scan.in_progress==0)
			break;
	}
	scan_cnt = hw_priv->scan_ret.len < MAX_AP_COUNT ? hw_priv->scan_ret.len:MAX_AP_COUNT;
	ap_list->valid_num = ap_list->size < scan_cnt ? ap_list->size : scan_cnt;

	for(i=0;i<ap_list->valid_num;i++){
		info = hw_priv->scan_ret.info + i;
		ap = ap_list->ap + i;
		ssd_len = info->ssidlen > ATBM_MAX_SSID_LEN ? ATBM_MAX_SSID_LEN:info->ssidlen;
		atbm_memcpy(ap->ssid, info->ssid, ssd_len);
		wifi_printk(WIFI_ALWAYS,"%d %s", i+1, ap->ssid);
	}

	return 0;
}

struct wifi_netif_device atbm_netif_device = {
	.common.if_type = XS_NETIF_WIFI,
	.common.ifname = "atbm",
	.enable = __atbm_enable,
	.ap_connect = __atbm_ap_connect,
	.ap_disconnect = __atbm_ap_disconnect,
	.ap_scan_1 = __atbm_ap_scan_1,
#if 0
	.ap_get_list = atbm_ap_get_list,
	.ap_get_count = atbm_ap_get_count,
	.ap_get_connected_info = atbm_ap_get_connected_info,
	.hostap_create = atbm_hostap_create,
	.hostap_destroy = atbm_hostap_destroy,
	.set_mode = atbm_set_mode,
	.get_mode = atbm_get_mode,
	.disable = atbm_disable,
#endif
};

static int atbm_driver_init(void)
{
	xs_netmgr_add_netif_dev((struct netif_device_common *)&atbm_netif_device);
	return 0;
}

module_driver(atbm_driver, atbm_driver_init, NULL)
