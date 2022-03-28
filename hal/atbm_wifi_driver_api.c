/**************************************************************************************************************
 * altobeam RTOS API
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#include "atbm_hal.h"
#include "atbm_wifi_driver_api.h"
#include "atbm_etf.h"


extern struct atbmwifi_vif *g_vmac;
extern struct atbmwifi_cfg hmac_cfg; 
extern struct atbmwifi_common g_hw_prv;
/*ATBM WIFI READY*/
extern atbm_uint32 AtbmwifiRdy;

extern atbm_void* atbm_wifi_vif_get();
extern atbm_int32 atbm_etf_start_tx(atbm_int32 channel,atbm_int32 rate_value,atbm_int32 is_40M, atbm_int32 greedfiled);
extern atbm_int32 atbm_etf_stop_tx(atbm_void);
extern atbm_int32 atbm_etf_start_rx(atbm_int32 channel ,atbm_int32 is_40M);
extern atbm_int32 atbm_etf_stop_rx(atbm_void);
extern atbm_int32 atbm_etf_start_tx_single_tone(atbm_int32 channel,atbm_int32 is_40M);
extern atbm_int32 atbm_etf_PT_Test_start(/*atbm_int32 targetFreq, atbm_int32 rssiFilter, atbm_int32 evmFilter, atbm_int32 cableLoss, */atbm_int32 isWriteEfuse);

atbm_int32 atbm_wifi_get_current_mode_vif(atbm_uint8 if_id);   //0 : sta, 1: SW AP

/****************************************************************************
* Function:   	atbm_wifi_hw_init
*
* Purpose:   	This function is used to initialize and start atbm wifi  hardware.
may be GPO, BUS PROBE, firmware init etc.
*
* Parameters: none
*
* Returns:	Returns 0 if succeed, otherwise a negative error code.
****************************************************************************/
atbm_int32  atbm_wifi_hw_init(atbm_void)
{
	//1, init done or not init;
	//hmac may init done in USB probe, but in SPI etc none probe cases, hmac may not inited, here check g_vmac.
	if(!g_vmac)
	{
		wifi_printk(WIFI_ALWAYS,"[Wifi] Enter %s \n", __func__);
		#if ATBM_USB_BUS
		atbm_usb_module_init();
		#elif ATBM_SDIO_BUS
		atbm_sdio_module_init();
		#endif
		//Atbmwifi_halEntry(sbus)
	}
	return 0;
}



/****************************************************************************
* Function:   	atbm_wifi_on
*
* Purpose:   	This function is used to initialize and start atbm wifi  module as AP mode or STA mode.                     
*
* Parameters: AP_sta_mode     0: Ap Mode, 1 STA mode
*
* Returns:	Returns 0 if succeed, otherwise a negative error code.
****************************************************************************/
atbm_void* atbm_wifi_on_vif(ATBM_WIFI_MODE AP_sta_mode,atbm_uint8 if_id)
{

	atbm_int32 i32current_mode;
	struct atbmwifi_vif *priv;
	
	if(if_id>=2){
		return ATBM_NULL;
	}
	priv = atbm_wifi_vif_get();

	if(priv == ATBM_NULL)
		return ATBM_NULL;
	i32current_mode =  atbm_wifi_get_current_mode_vif(if_id);  //get current mode
	if(atbmwifi_is_ap_mode(i32current_mode) &&(AP_sta_mode == ATBM_WIFI_AP_MODE)){
		wifi_printk(WIFI_ALWAYS,"<WARNING>atbm_wifi_on_vif+_mode %d+\n",i32current_mode);
		return ATBM_NULL;
	}
	if(atbmwifi_is_sta_mode(i32current_mode) &&(AP_sta_mode == ATBM_WIFI_STA_MODE)){
		wifi_printk(WIFI_ALWAYS,"<WARNING>atbm_wifi_on_vif+_mode %d+\n",i32current_mode);
		return ATBM_NULL;
	}

	wifi_printk(WIFI_ALWAYS,"atbm_wifi_on_vif+_mode %d+\n",i32current_mode);

	if(AP_sta_mode == ATBM_WIFI_AP_MODE)
	{

		atbmwifi_start_wifimode(priv,ATBM_NL80211_IFTYPE_AP);
	} 
	if(AP_sta_mode == ATBM_WIFI_STA_MODE)
	{
		atbmwifi_start_wifimode(priv,ATBM_NL80211_IFTYPE_STATION);
	}

	return (atbm_void* )priv->ndev;

}
atbm_void* atbm_wifi_on( ATBM_WIFI_MODE AP_sta_mode)
{
	return atbm_wifi_on_vif(AP_sta_mode,0);
}
atbm_void* atbm_wifi_vif_get()
{
	/*Wait for atbmwifi fw & hmac done*/
	while (1) {
		if(AtbmwifiRdy){	
			return g_hw_prv.vif_list[0];
		}
        else {
             atbm_SleepMs(50);

        }
	}
}
/****************************************************************************
* Function:   	atbm_wifi_off
*
* Purpose:   	This function is used to stop atbm wifi  module.
*
* Returns:	Returns none.
*****************************************************************************/
atbm_void  atbm_wifi_off_vif(atbm_uint8 if_id)
{

	//stop sta or ap

	atbm_int32 i32current_mode;
	struct atbmwifi_vif *priv;	
	
	if(if_id>=2){
		return ;
	}
	priv = g_hw_prv.vif_list[if_id];

	if(priv == ATBM_NULL)
		return ;

	i32current_mode =	atbm_wifi_get_current_mode_vif(if_id);   // get current mode

	wifi_printk(WIFI_ALWAYS,"atbm_wifi_off_vif mode %d\n",i32current_mode);
	atbmwifi_stop_wifimode(priv,priv->iftype);
}
atbm_void  atbm_wifi_off(atbm_void)
{
	atbm_wifi_off_vif(0);
}

/****************************************************************************
* Function:   	atbm_wifi_scan_network
*
* Purpose:   	This function is used to ask driver to perform channel scan and return scan result.
*
* Parameters: scan_buf		Buffer to store the information of the found APs
*			buf_size		Size of the buffer
*
* Returns:	Returns 0 if succeed, otherwise a negative error code.
******************************************************************************/
int	atbm_wifi_scan_network_vif(struct atbmwifi_vif *priv,char* scan_buf, atbm_uint32 buf_size)
{
	WLAN_BSS_INFO *bss_info;
	WLAN_SCAN_RESULT *pScanResult;
	struct atbmwifi_scan_result_info *info;
	int i=0;
	struct atbmwifi_common *hw_priv = ATBM_NULL;
	if(priv == ATBM_NULL)
	{   
		//return or hw init
		wifi_printk(WIFI_ALWAYS,"wait scan done++,priv == ATBM_NULL\n");
		return -1;
	}

	//g_hw_prv.scan_ret.len = 0;
	//g_hw_prv.scan.direct_probe =1;
	hw_priv = priv->hw_priv;
	priv->scan_expire = 2;
	if(atbmwifi_scan_process(priv)){
		return -2;
	}

	wifi_printk(WIFI_ALWAYS,"wait scan done++\n");
	//wait scan done,, wait scan complete
	while(1){
		atbm_mdelay(1000);
		if(hw_priv->scan.in_progress==0)
			break;
	}
	wifi_printk(WIFI_ALWAYS,"wait scan done--,scan_ret.len(%d)\n",hw_priv->scan_ret.len);
	
	//atbm_wifi_get_scaned_list(scan_buf, buf_size);	
	pScanResult = (WLAN_SCAN_RESULT*)scan_buf;
	bss_info =  (WLAN_BSS_INFO *)(&pScanResult->bss_info[0]);
	if(buf_size<sizeof(WLAN_SCAN_RESULT))
	{
		wifi_printk(WIFI_ERROR,"scan_buf very tlitle\n");
		return -1;
	}

	//will copy to user API and delete AP list from driver's ap list. here porting for Mstar
//	info = hw_priv->scan_ret.info + hw_priv->scan_ret.len;
	for(i=0;i<hw_priv->scan_ret.len;i++){
		info = hw_priv->scan_ret.info + i;
		if((char *)(bss_info + 1) > (scan_buf+buf_size))
		{
			wifi_printk(WIFI_ERROR,"scan_buf very tlitle\n");
			return 0;
		}
		//Copy ATBM scanned bss list  to platform dependent BSS list
		bss_info->SSID_len = info->ssidlen;
		if( bss_info->SSID_len > 32 )
		{
			 wifi_printk(WIFI_ALWAYS,"atbm_wifi_scan_network_vif SSID_len(%d)\n",bss_info->SSID_len);
			 bss_info->SSID_len = 32;
		}
		atbm_memcpy(bss_info->SSID, info->ssid,  bss_info->SSID_len);
		atbm_memcpy(bss_info->BSSID, info->BSSID, ATBM_ETH_ALEN);

		bss_info->beacon_period = info->beacon_interval;
		bss_info->capability    = info->capability;
		bss_info->chanspec      = info->channel;
		bss_info->RSSI = (atbm_uint16)info->rssi;
		bss_info->dtim_period   =  info->dtim_period;
		bss_info->security		= info->security;
		bss_info->length = sizeof(WLAN_BSS_INFO); //no ies
		bss_info++;
		pScanResult->count++;
	}
	
	priv->scan_no_connect = priv->scan_no_connect_back;

	wifi_printk(WIFI_ALWAYS,"wait scan done,pScanResult->count(%d)\n",pScanResult->count);
	return 0;
}

int atbm_wifi_scan_network(char* scan_buf, atbm_uint32 buf_size)
{ 
	atbm_wifi_scan_network_vif(g_vmac,scan_buf,buf_size);
	return 0;

}

/****************************************************************************
* Function:   	atbm_wifi_get_mode
*
* Purpose:   	This function is used to get  wifi mode 
*
* Parameters: None
*
* Returns:	Returns 0 if in STA mode, 1 in SW AP mode.
******************************************************************************/
atbm_int32 atbm_wifi_get_current_mode_vif(atbm_uint8 if_id)   //0 : sta, 1: SW AP
{
	struct atbmwifi_vif *priv;
	
	if(if_id>=2){
		return -1;
	}
	priv = g_hw_prv.vif_list[if_id];

	if(priv == ATBM_NULL)
		return -1;
	  
	return priv->iftype ;
}

atbm_int32 atbm_wifi_get_current_mode(atbm_void)   //0 : sta, 1: SW AP
{
	return atbm_wifi_get_current_mode_vif(0);  //default mode.
}


/****************************************************************************
* Function:   	atbm_wifi_get_mac_address
*
* Purpose:   	This function is used to get wifi MAC address
*
* Parameters: point to buffer of MAC address
*
* Returns:	None.
******************************************************************************/
atbm_void atbm_wifi_get_mac_address_vif(atbm_uint8 if_id,unsigned char *addr)
{

	struct atbmwifi_vif *priv;

	if(if_id>=2){
		return;
	}
	priv = g_hw_prv.vif_list[if_id];

	if(priv == ATBM_NULL)
		return;
	if(addr == ATBM_NULL)
	{		   
		return;
	}

	atbm_memcpy(addr, priv->mac_addr, 6);  //AP or STA 
}

atbm_void atbm_wifi_get_mac_address(unsigned char *addr)
{

	atbm_wifi_get_mac_address_vif(0,addr);
}

/****************************************************************************
* Function:   	atbm_wifi_get_avail_tx_queue_count
*
* Purpose:   	This function is used to return the available buffer count of driver TX queue
*
* Parameters: None
*
* Returns:	Returns number of available buffer count of driver TX queue.
******************************************************************************/
atbm_int32 atbm_wifi_get_avail_tx_queue_count(atbm_void)
{
	//bg queue, thro-qnum
	struct atbmwifi_vif *priv;
    atbm_int32  avail_tx_queue_count = 0;
	struct atbmwifi_common * hw_priv;
	int cnt =0;
	
	priv = g_vmac;
	hw_priv = priv->hw_priv;
	cnt = hw_priv->tx_queue[0].num_queued + 
			hw_priv->tx_queue[1].num_queued	+
			hw_priv->tx_queue[2].num_queued	+
			hw_priv->tx_queue[3].num_queued;
	//back ground queue.  there is no QOS.
  	if(hw_priv->vif0_throttle  > cnt)
   	{
		avail_tx_queue_count = hw_priv->vif0_throttle - cnt;
   	}
	//else  {
	//
	//}
	//if(avail_tx_queue_count < 8){
		//iot_printf("avail_tx_queue_count %d %d %d\n", hw_priv->vif0_throttle , hw_priv->tx_queue[0].num_queued,avail_tx_queue_count);
	//}
	return avail_tx_queue_count;

}




/****************************************************************************
* Function:     atbm_wifi_sta_join_ap
*
* Purpose:      This function is used to ask driver to join a network.
*
* Parameters: ssid          SSID of the AP used to join a network
*            authMode   authentication mode used to join a network
*            encryption encryption mode used to join a network
*            key            passphrase used to join a network
*
* Returns:  Returns 0 if succeed, otherwise a negative error code.
******************************************************************************/

atbm_int32 atbm_wifi_sta_join_ap_vif(atbm_uint8 if_id,char *ssid, char *bssid, WLAN_AUTH_MODE authMode, WLAN_ENCRYPTION encryption, const char *key)
{

	//add authMode: wpa_psk, wpa2_psk
	int ssidlen = 0, passwdlen = 0;
	ATBM_SECURITY_TYPE key_mgmt;
	struct atbmwifi_vif *priv;

	if(if_id>=2){
		return -1;
	}
	priv = g_hw_prv.vif_list[if_id];

	if(priv == ATBM_NULL)
		return -1;
	
	key_mgmt = ATBM_KEY_NONE;  //default set as ATBM_KEY_NONE

	if(encryption == WLAN_ENCRYPT_WEP) //which auth mode?????
	{
		key_mgmt= ATBM_KEY_WEP;  //auth shared key
	}	
	if(encryption == WLAN_ENCRYPT_WEP_SHARED) //which auth mode?????
	{
		key_mgmt= ATBM_KEY_WEP_SHARE;  //auth shared key
	}	
	if(authMode == WLAN_WPA_AUTH_PSK)
	{
		key_mgmt = ATBM_KEY_WPA;
	}
	if(authMode == WLAN_WPA2_AUTH_PSK)
	{
		key_mgmt = ATBM_KEY_WPA2;
	}   
	//ask zhiqiang ASCor hex

	ssidlen = strlen(ssid);
	if(key != NULL)
		passwdlen = strlen(key);
	else 
		passwdlen = 0;
	wifi_ConnectAP_vif(priv,(atbm_uint8 *)ssid,  ssidlen,(atbm_uint8 *)key, passwdlen, key_mgmt);

	return 0;
}

atbm_int32 atbm_wifi_sta_join_ap(char *ssid, char *bssid, WLAN_AUTH_MODE authMode, WLAN_ENCRYPTION encryption, const char *key)
{
	wifi_printk(WIFI_ALWAYS,"atbm_wifi_sta_join_ap++\n");
	atbm_wifi_sta_join_ap_vif(0,ssid, bssid, authMode, encryption,key);
	return 0;
}

#if FAST_CONNECT_MODE
atbm_int32 atbm_wifi_set_fast_connect_mode(atbm_uint8 enable, atbm_uint8 channel, atbm_uint8 *pmk){
	struct atbmwifi_cfg *config = &g_vmac->config;
	if(enable){
		g_vmac->fast_connect = 1;
		g_vmac->fast_channel = channel;
		if(channel && pmk[0] != '\0'){
			config->psk_set = 1;
			atbm_memcpy(config->psk, pmk, 32);
		}else{
			config->psk_set = 0;
		}
	}else{
		g_vmac->fast_connect = 0;
		config->psk_set = 0;
	}
	return 0;
}

atbm_int32 atbm_wifi_get_fast_connect_info(atbm_uint8 *channel, atbm_uint8 *pmk){
	struct atbmwifi_cfg *config = &g_vmac->config;
	*channel = config->channel_index;
	if(config->psk_set){
		atbm_memcpy(pmk, config->psk, 32);
	}
	return 0;
}
#endif

#if FAST_CONNECT_NO_SCAN
//First connect:config serve as ssid while bss as password
atbm_int32 atbm_wifi_fast_link_noscan(FAST_LINK_INFO * finfo){
	struct atbmwifi_vif *priv = g_vmac;
	struct atbmwifi_cfg80211_bss *bss = &priv->bss;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);

	if(finfo->enable){
		priv->fast_conn_noscan = 1;
		atbm_memcpy(&hmac_cfg, finfo->config, sizeof(struct atbmwifi_cfg));
		config->psk_set = hmac_cfg.psk_set;
		atbm_memcpy(config->psk, hmac_cfg.psk, sizeof(hmac_cfg.psk));
		atbm_memcpy(bss, finfo->bss, sizeof(struct atbmwifi_cfg80211_bss));
		if(bss->len_information_elements){
			bss->information_elements = atbm_kmalloc(bss->len_information_elements, GFP_KERNEL);
			if(bss->information_elements){
				atbm_memcpy(bss->information_elements, finfo->ie, bss->len_information_elements);
			}
		}
		bss->rc_priv = ATBM_NULL;
		atbm_memcpy(priv->daddr,bss->bssid,6);
		atbm_memcpy(priv->bssid,bss->bssid,6);
		priv->auth_retry = 1;
		return atbmwifi_wpa_event_queue((atbm_void*)priv,(atbm_void*)(&hmac_cfg),
			 ATBM_NULL,WPA_EVENT__SUPPLICANT_START_CONNECT,ATBM_WPA_EVENT_NOACK);
	}else{
		priv->fast_conn_noscan = 0;
		atbm_memset(&hmac_cfg, 0, sizeof(struct atbmwifi_cfg));
		atbm_memset(bss, 0, sizeof(struct atbmwifi_cfg80211_bss));
		config->psk_set = 0;
		priv->auth_retry = 0;
		return atbm_wifi_sta_join_ap((char *)finfo->config,NULL,0,0,(char *)finfo->bss);
	}
}

atbm_void atbm_wifi_get_linkinfo_noscan(FAST_LINK_INFO * finfo){
	struct atbmwifi_vif *priv = g_vmac;
	struct atbmwifi_cfg80211_bss *bss = &priv->bss;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);

	finfo->enable = 1;
	hmac_cfg.psk_set = config->psk_set;
	atbm_memcpy(hmac_cfg.psk, config->psk, sizeof(hmac_cfg.psk));
	atbm_memcpy(finfo->config, &hmac_cfg, sizeof(struct atbmwifi_cfg));
	finfo->ssid_offset = offsetof(struct atbmwifi_cfg, ssid);
	finfo->psk_offset = offsetof(struct atbmwifi_cfg, password);
	if(bss->len_information_elements){
		if(bss->len_information_elements <= sizeof(finfo->ie)){
			atbm_memcpy(finfo->ie, bss->information_elements, bss->len_information_elements);
		}else{
			if((bss->len_information_elements = atbm_wifi_reserve_key_ie(finfo->ie, sizeof(finfo->ie), bss->information_elements, bss->len_information_elements)) <= 0){
				wifi_printk(WIFI_ALWAYS, "error:cannot save ies for fastlink!!\n");				
			}
		}
	}
	atbm_memcpy(finfo->bss, bss, sizeof(struct atbmwifi_cfg80211_bss));
}
#endif

atbm_int32 atbm_wifi_sta_disjoin_ap()
{
	if(!atbm_wifi_initialed()){
		wifi_printk(WIFI_DBG_ERROR,"atbm_wifi_initialed err\n");	
		return -1;
	}
	AT_WDisConnect_vif(g_vmac,ATBM_NULL);
	return 0;
}

int atbm_wifi_isconnected(void)
{
	if(g_vmac == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR,"not init\n");
		return 0;
	}
	return g_vmac->connect_ok;
}

/****************************************************************************
* Function:   	atbm_wifi_get_driver_version
*
* Purpose:   	This function is used to return the driver's release version
*
* Parameters: None
*
* Returns:	Returns the driver release version
*****************************************************************************
*/
signed char* atbm_wifi_get_driver_version(atbm_void)
{
	if(g_vmac == ATBM_NULL)
	{	 
	//return or hw init
	//return priv->driver_version;
		return 0;
	}

	return (signed char*)0;

}



/****************************************************************************
* Function:     wlan_get_connection_info
*
* Purpose:      This function is used to get the current connection information at STA mode
*
* Parameters: wlan connection information
*
* Returns:  Returns 0 if succeed, otherwise a negative error code.

******************************************************************************/
int atbm_wifi_get_connected_info_vif(atbm_uint8 if_id,ATBM_WLAN_CONNECTION_INFO *wlan_connection_info )
{
	struct atbmwifi_vif *priv;

	if(if_id>=2){
		return -1;
	}
	priv = g_hw_prv.vif_list[if_id];

	if(priv == ATBM_NULL)
		return -1;

	if(wlan_connection_info->Ssid != ATBM_NULL)
	{

		wlan_connection_info->Ssid_len = hmac_cfg.ssid_len;
		atbm_memcpy(wlan_connection_info->Ssid, hmac_cfg.ssid, wlan_connection_info->Ssid_len);

	}
	wlan_connection_info->channel = priv->bss.channel_num;	  
	//RSSI, PHY rate?? mapping?  or current used  rx/tx rate?//from rx_status
	wlan_connection_info->Rssi = priv->bss.rssi;
			
	return 0;
}

int atbm_wifi_get_connected_info(ATBM_WLAN_CONNECTION_INFO *wlan_connection_info )
{
	return atbm_wifi_get_connected_info_vif(0,wlan_connection_info);
}




/*************************************************************************************

**************                SW AP functions                                                                        *********

**************************************************************************************/

/****************************************************************************
* Function:     atbm_wifi_ap_create
*
* Purpose:      This function is used to create a SW AP network
*
* Parameters: ssid          SSID of the SW AP to be created
*            authMode   Authentication mode used for the SW AP
*            encryption Encryption mode used for the SW AP
*            key            Passphrase used for the SW AP
*            channel        Channel used for the SW AP
*            ssidBcst       0: to broadcast SSID, 1: to hide SSID
*
* Returns:  Returns 0 if succeed, otherwise a negative error code.
******************************************************************************/
extern atbm_void wifi_StartAP(atbm_uint8 * ssid,int ssidlen,atbm_uint8 * password,int passwdlen,int channel,ATBM_SECURITY_TYPE key_mgmt,ATBM_BOOL ssidBcst);
atbm_int32 atbm_wifi_ap_create_vif(atbm_uint8 if_id,char* ssid, int authMode, int encryption, 
	const char *key, int channel, ATBM_BOOL ssidBcst )

{
	int ssidlen = 0, passwdlen = 0;
	ATBM_SECURITY_TYPE key_mgmt;
	struct atbmwifi_vif *priv = g_vmac;

	wifi_printk(WIFI_ALWAYS,"atbm_wifi_ap_create++ channel %d\n",channel);

	key_mgmt = ATBM_KEY_NONE;  //default set as ATBM_KEY_NONE

	if(encryption == WLAN_ENCRYPT_WEP) //which auth mode?????
	{
		key_mgmt= ATBM_KEY_WEP;	//auth open
	}	
	if(encryption == WLAN_ENCRYPT_WEP_SHARED) //which auth mode?????
	{
		key_mgmt= ATBM_KEY_WEP_SHARE;	//auth sharedkey
	}	
	if(authMode == WLAN_WPA_AUTH_PSK)
	{
		key_mgmt = ATBM_KEY_WPA;
	}
	if(authMode == WLAN_WPA2_AUTH_PSK)
	{
		key_mgmt = ATBM_KEY_WPA2;
	}	
	if(authMode == WLAN_MIX_AUTH_PSK)
	{
		key_mgmt = ATBM_KEY_MIX;
	}		
	//ask zhiqiang ASCor hex
	if(encryption != WLAN_ENCRYPT_NONE){
		passwdlen = strlen(key);
	}
	ssidlen = strlen(ssid);
	if(priv->enabled){
	}
	else {
		atbmwifi_start_wifimode(priv,ATBM_NL80211_IFTYPE_AP);
	}

	//add Auth mode and channel 
	wifi_StartAP((atbm_uint8 *)ssid,ssidlen, (atbm_uint8 *)key, passwdlen,channel,key_mgmt,ssidBcst);

	return 0;

}
atbm_int32 atbm_wifi_ap_create(char* ssid, int authMode, int encryption, 
	const char *key, int channel, ATBM_BOOL ssidBcst )

{
	return atbm_wifi_ap_create_vif(0,ssid,authMode,encryption,key,channel,ssidBcst);

}


/****************************************************************************
* Function:     wlan_get_assoc_list
*
* Purpose:      This function is used to the associated client list in SW AP mode
*
* Parameters: buf           The buffer to store the associated client list
*                    uiBufSize       size of the buffer
*
* Returns:  Returns 0 if succeed, otherwise a negative error code.

* For ioctls that take a list of MAC addresses *

******************************************************************************/

int atbm_wifi_get_associated_client_list_vif(atbm_uint8 if_id,atbm_void *pchBuf, unsigned int uiBufSize)
{

	struct atbmwifi_vif *priv;
	WLAN_MACLIST *maclist = (WLAN_MACLIST*)pchBuf;
	
	if(if_id>=2){
		return -1;
	}
	priv = g_hw_prv.vif_list[if_id];

	if(priv == ATBM_NULL)
		return -1;

	atbm_memset(pchBuf, 0, uiBufSize);

	if(maclist->count >  ATBMWIFI__MAX_STA_IN_AP_MODE)
	{
		maclist->count = ATBMWIFI__MAX_STA_IN_AP_MODE;
	}	

	maclist->count = atbmwifi_get_hard_linked_macs(priv,  maclist->ea[0].mac, maclist->count);

	return 0;
}


int atbm_wifi_get_associated_client_list(atbm_void *pchBuf, unsigned int uiBufSize)
{
	return atbm_wifi_get_associated_client_list_vif(0,pchBuf, uiBufSize);
}

extern atbm_int32 atbmwifi_get_rssi_avg(atbm_void);
extern atbm_int32 atbmwifi_set_tx_time(atbm_uint32 time_period, atbm_uint32 time_transmit);
extern atbm_int32 atbmwifi_set_retry(atbm_uint32 retry_num, atbm_uint32 retry_time_ms);
extern atbm_int32 atbmwifi_set_txpower_mode(atbm_uint32 txpower_idx);
extern atbm_int32 atbmwifi_set_txpower(atbm_uint32 txpower_idx);
extern atbm_int32 atbmwifi_set_tx_rate(atbm_int32 rate);
extern atbm_int32 atbmwifi_set_sgi(atbm_uint32 sgi);
extern atbm_int32 atbmwifi_set_rate_txpower_mode(atbm_uint32 txpower_idx);
extern atbm_int32 atbmwifi_get_lmacLog_to_host(atbm_uint32 value);
extern atbm_int32 atbm_set_debug_to_host(atbm_uint32 value);

atbm_int32 atbmwifi_enable_lmaclog(atbm_uint32 value ){

	atbm_int32 ret = 0;
	
	ret = atbmwifi_get_lmacLog_to_host(value);
	
	if(value)
		ret = wsm_write_mib(&g_hw_prv, WSM_MIB_ID_FW_CMD,"ccastart ", 9, g_vmac->if_id);
	else
		ret = wsm_write_mib(&g_hw_prv, WSM_MIB_ID_FW_CMD,"ccastop ", 8, g_vmac->if_id);
	return ret;
}

atbm_int32 atbm_wifi_get_rssi_avg(atbm_void)
{
	return atbmwifi_get_rssi_avg();
}
atbm_int32 atbm_wifi_set_tx_time(atbm_uint32 time_period, atbm_uint32 time_transmit)
{
	return atbmwifi_set_tx_time(time_period, time_transmit);
}
atbm_int32 atbm_wifi_set_retry(atbm_uint32 retry_num, atbm_uint32 retry_time_ms)
{
	return atbmwifi_set_retry(retry_num, retry_time_ms);
}

/****************************************************
Function Name: atbmwifi_set_txpower_mode
Parameters:
		txpower_idx: [0:12]  -> [-3:0.5:3]dB -> [-30:5:30]/10 dB
Return: Success(0), Error(<0)
******************************************************/
atbm_int32 atbm_wifi_set_txpower_mode(atbm_uint32 txpower_idx)
{
	return atbmwifi_set_txpower_mode(txpower_idx);
}

/****************************************************
Function Name: atbmwifi_set_txpower
Parameters:
		txpower_flag: [0:15,63]
Return: Success(0), Error(<0)
******************************************************/
atbm_int32 atbm_wifi_set_txpower(atbm_uint32 txpower_flag)
{
	return atbmwifi_set_txpower(txpower_flag);
}
atbm_int32 atbm_wifi_set_tx_rate(atbm_int32 rate)
{
	return atbmwifi_set_tx_rate(rate);
}
atbm_int32 atbm_wifi_set_sgi(atbm_uint32 sgi)
{
	return atbmwifi_set_sgi(sgi);
}

atbm_int32 atbm_wifi_get_256BITSEFUSE(atbm_uint8 *data, atbm_uint32 length)
{
	int ret = 0;
	int i;
	struct atbmwifi_vif *priv = g_vmac;
	struct atbmwifi_common *hw_priv = priv->hw_priv;

	if((data == NULL) || (length != 32)){
		wifi_printk(WIFI_ERROR, "invalid parameter,please try again!\n");
		return -1;
	}
	
	if ((ret = wsm_get_SIGMSTAR_256BITSEFUSE(hw_priv, data, length)) == 0){
		
		wifi_printk(WIFI_ERROR, "Get efuse data:\n");
		for(i = 0; i < length; i++)
		{
			wifi_printk(WIFI_ALWAYS, "%x ", data[i]);
		}
		wifi_printk(WIFI_ALWAYS, "\n");
		return ret;
	}
	else{
		wifi_printk(WIFI_ERROR, "read efuse failed\n");
		return -1;
	}
	
	return ret;	
}
atbm_int32 atbm_wifi_set_256BITSEFUSE(atbm_uint8 *data, atbm_uint32 length)
{
	atbm_int32 i;
	atbm_int32 ret = 0;
	struct atbmwifi_vif *priv = g_vmac;
	struct atbmwifi_common *hw_priv = priv->hw_priv;
	
	if((data == NULL) || (length != 32)){
		wifi_printk(WIFI_ERROR, "invalid parameter,please try again!\n");
		return -1;
	}

	if ((ret = wsm_set_SIGMSTAR_256BITSEFUSE(hw_priv, data, length)) == 0){
		
		wifi_printk(WIFI_ALWAYS, "Set efuse data:\n");
		for(i = 0; i < length; i++)
		{
			wifi_printk(WIFI_ALWAYS, "%x ", data[i]);
		}
		wifi_printk(WIFI_ALWAYS, "\n");
		return ret;
	}
	else{
		wifi_printk(WIFI_ERROR, "write efuse failed\n");
		return -1;
	}

	return ret;
}

int atbm_save_efuse(struct atbmwifi_common *hw_priv, struct efuse_headr *efuse_save)
{
	int ret = 0;
	int iResult=0;
	//struct atbm_vif *vif;
	struct efuse_headr efuse_bak;

	ret = wsm_efuse_change_data_cmd(hw_priv, efuse_save,0);
	if (ret == LMC_STATUS_CODE__EFUSE_FIRST_WRITE)
	{
		iResult = -3;
	}else if (ret == LMC_STATUS_CODE__EFUSE_PARSE_FAILED)
	{
		iResult = -4;
	}else if (ret == LMC_STATUS_CODE__EFUSE_FULL)
	{
		iResult = -5;
	}else if (ret == LMC_STATUS_CODE__EFUSE_VERSION_CHANGE)
	{
		iResult = -6;
	}else
	{
		iResult = 0;
	}
	
	wsm_get_efuse_data(hw_priv,(void *)&efuse_bak, sizeof(struct efuse_headr));
	
	if(atbm_memcmp((void *)&efuse_bak,(void *)efuse_save, sizeof(struct efuse_headr)) !=0)
	{
		iResult = -2;
	}else
	{
		iResult = 0;
	}

	return iResult;
}

/*
txpower_idx: [-16:16] -> [-8:0.5:8]dB -> [-80:5:80]/10 dB
*/
atbm_int32 atbm_wifi_set_rate_txpower_mode(atbm_int32 txpower_idx)
{
	return atbmwifi_set_rate_txpower_mode(txpower_idx);
}

/*************************************************************************************

**************                  Manufacturing test functions                                                     *********

**************************************************************************************/

atbm_void  atbm_wifi_mfg_start(atbm_void)
{
	wifi_printk(WIFI_ALWAYS, "atbm_wifi_mfg_start()\n");
	return;
}


/**************************************************************************************
* Function:     atbm_wifi_mfg_set_pktTxBG
*
* Purpose:      This function is used to perform manufacturing 11b/g continuous TX test
*
* Parameters:   channel       Channel used for TX
*               	  rate          11b/g rate used for TX
*               	  powerValue    Output power index, -1 means default power
*
* Returns:      Returns 0 if succeed, otherwise a negative error code.
****************************************************************************************/
atbm_int32 atbm_wifi_mfg_set_pktTxBG(WLAN_CHANNEL channel, WLAN_RATE rate, atbm_int32 powerValue)
{
	atbm_int32 rate_val = 0;

	wifi_printk(WIFI_ALWAYS, "atbm_wifi_mfg_set_pktTxBG()\n");
	
	if(channel < 1 || channel > 14){
		wifi_printk(WIFI_DBG_ERROR, "invalid channel! %d\n", channel);
		return -1;
	}

	switch(rate){
		//11b
		case WLAN_RATE_1M: rate_val = 10;
		break;
		case WLAN_RATE_2M: rate_val = 20;
		break;
		case WLAN_RATE_5M5: rate_val = 55;
		break;
		case WLAN_RATE_11M: rate_val = 110;
		break;
		//11g
		case WLAN_RATE_6M: rate_val = 60;
		break;
		case WLAN_RATE_9M: rate_val = 90;
		break;
		case WLAN_RATE_12M: rate_val = 120;
		break;
		case WLAN_RATE_18M: rate_val = 180;
		break;
		case WLAN_RATE_24M: rate_val = 240;
		break;
		case WLAN_RATE_36M: rate_val = 360;
		break;
		case WLAN_RATE_48M: rate_val = 480;
		break;
		case WLAN_RATE_54M: rate_val = 540;
		break;

		default:
			wifi_printk(WIFI_DBG_ERROR, "invalid rate! %d\n", rate);
			return -1;			
	}
	
	//txpower_idx: [-16:16] -> [-8:0.5:8]dB -> [-80:5:80]/10 dB
	if(powerValue > 16 || powerValue < -16){
		wifi_printk(WIFI_DBG_ERROR, "invalid txpower index! %d\n", powerValue);
		return -1;
	}
	
	if(atbm_wifi_set_rate_txpower_mode(powerValue) < 0){
		wifi_printk(WIFI_DBG_ERROR, "set rate txpower mode failed! %d\n", powerValue);
		return -1;
	}

	if(atbm_etf_start_tx(channel, rate_val, 0/*40M*/, 0/*greedfiled*/) < 0){
		wifi_printk(WIFI_DBG_ERROR, "start tx bg failed!\n");
		return -1;
	}

	return 0;
}


/***********************************************************************************
* Function:     atbm_wifi_mfg_set_PktTxN
*
* Purpose:      This function is used to perform manufacturing 11n continuous TX test
*
* Parameters:   channel       Channel used for TX
*              	   rate          11n rate used for TX
*               	  powerValue    Output power index, -1 means default power
*
* Returns:      Returns 0 if succeed, otherwise a negative error code.
************************************************************************************/
atbm_int32 atbm_wifi_mfg_set_PktTxN(WLAN_CHANNEL channel, WLAN_RATE rate, atbm_int32 powerValue)
{
	atbm_int32 rate_val = 0;

	wifi_printk(WIFI_ALWAYS, "atbm_wifi_mfg_set_PktTxN()\n");
	
	if(channel < 1 || channel > 14){
		wifi_printk(WIFI_DBG_ERROR, "invalid channel! %d\n", channel);
		return -1;
	}
	
	switch(rate){
		case WLAN_MCS_RATE_0: rate_val = 65;
		break;
		case WLAN_MCS_RATE_1: rate_val = 130;
		break;
		case WLAN_MCS_RATE_2: rate_val = 195;
		break;
		case WLAN_MCS_RATE_3: rate_val = 260;
		break;
		case WLAN_MCS_RATE_4: rate_val = 390;
		break;
		case WLAN_MCS_RATE_5: rate_val = 520;
		break;
		case WLAN_MCS_RATE_6: rate_val = 585;
		break;
		case WLAN_MCS_RATE_7: rate_val = 650;
		break;
		
		default:
			wifi_printk(WIFI_DBG_ERROR, "invalid rate! %d\n", rate);
			return -1;			
	}

	//txpower_idx: [-16:16] -> [-8:0.5:8]dB -> [-80:5:80]/10 dB
	if(powerValue > 16 || powerValue < -16){
		wifi_printk(WIFI_DBG_ERROR, "invalid txpower index! %d\n", powerValue);
		return -1;
	}

	if(atbm_wifi_set_rate_txpower_mode(powerValue) < 0){
		wifi_printk(WIFI_DBG_ERROR, "set rate txpower mode failed! %d\n", powerValue);
		return -1;
	}

	if(atbm_etf_start_tx(channel, rate_val, 1/*40M*/, 0/*greedfiled*/) < 0){
		wifi_printk(WIFI_DBG_ERROR, "start tx bg failed!\n");
		return -1;
	}

	return 0;
}

atbm_int32 atbm_wifi_mfg_PT_Test(/*atbm_int32 targetFreq, atbm_int32 rssiFilter, atbm_int32 evmFilter, atbm_int32 cableLoss, */atbm_int32 isWriteEfuse)
{

	atbm_etf_PT_Test_start(/*targetFreq, rssiFilter, evmFilter, cableLoss, */isWriteEfuse);
	
	
	return 0;
}


/****************************************************************************
* Function:     atbm_wifi_mfg_CarrierTone
*
* Purpose:      This function is used to perform manufacturing non-modulation TX test
*
* Parameters:   channel       Channel used for test
*
* Returns:      Returns 0 if succeed, otherwise a negative error code.
******************************************************************************/
atbm_int32 atbm_wifi_mfg_CarrierTone(WLAN_CHANNEL channel)
{
	wifi_printk(WIFI_ALWAYS, "atbm_wifi_mfg_CarrierTone()\n");
	
	if(channel < 1 || channel > 14){
		wifi_printk(WIFI_DBG_ERROR, "invalid channel! %d\n", channel);
		return -1;
	}

	if(atbm_etf_start_tx_single_tone(channel, 0/*40M*/) < 0){
		wifi_printk(WIFI_DBG_ERROR, "start tx CarrierTone failed!\n");
		return -1;
	}

	return 0;
}
extern int atbm_etf_start_tx(int channel,int rate_value,int is_40M, int greedfiled);
extern int atbm_etf_stop_tx();
extern int atbm_etf_start_rx(int channel ,int is_40M);
extern int atbm_etf_stop_rx();

int atbm_wifi_etf_start_tx(int channel,int rate_value,int is_40M, int greedfiled)
{
	atbm_etf_stop_tx();

	return atbm_etf_start_tx(channel, rate_value, is_40M, greedfiled);
}
int atbm_wifi_etf_stop_tx()
{
	return atbm_etf_stop_tx();
}
int atbm_wifi_etf_start_rx(int channel ,int is_40M)
{
	return atbm_etf_start_rx(channel, is_40M);
}
int atbm_wifi_etf_stop_rx()
{
	return atbm_etf_stop_rx();
}




/****************************************************************************
* Function:     atbm_wifi_mfg_set_PktRxMode
*
* Purpose:      This function  is used to perform manufacturing RX test
*
* Parameters:   channel     Channel used for RX
*
* Returns:      Returns 0 if succeed, otherwise a negative error code.
******************************************************************************/
atbm_int32 atbm_wifi_mfg_set_PktRxMode(WLAN_CHANNEL channel)
{
	wifi_printk(WIFI_ALWAYS, "atbm_wifi_mfg_set_PktRxMode()\n");

	if(channel < 1 || channel > 14){
		wifi_printk(WIFI_DBG_ERROR, "invalid channel! %d\n", channel);
		return -1;
	}

	if(atbm_etf_start_rx(channel, 0/*40M*/) < 0){
		wifi_printk(WIFI_DBG_ERROR, "start etf rx failed!\n");
		return -1;
	}
	
	return 0;
}


/****************************************************************************
* Function:     atbm_wifi_mfg_get_RxPkt
*
* Purpose:      This function is used to get received packet count
*
* Parameters:   uiCount     Received packet count
*
* Returns:      Returns 0 if succeed, otherwise a negative error code.
******************************************************************************/
atbm_int32 atbm_wifi_mfg_get_RxPkt(atbm_uint32* uiCount)
{
	wifi_printk(WIFI_ALWAYS, "atbm_wifi_mfg_get_RxPkt()\n");
	return 0;
}



/****************************************************************************
* Function:     atbm_wifi_mfg_stop
*
* Purpose:      This function is used to stop manufacturing test
*
* Parameters:   None
*
* Returns:      Returns 0 if succeed, otherwise a negative error code.
******************************************************************************/
atbm_int32 atbm_wifi_mfg_stop(atbm_void)
{
	wifi_printk(WIFI_ALWAYS, "atbm_wifi_mfg_stop()\n");

	atbm_etf_stop_rx();
	atbm_etf_stop_tx();
	return 0;
}

atbm_uint8 atbm_smartconfig_start(void)
{

struct smartconfig_config st_cfg = {0};
#if 0
	if((g_vmac->iftype != ATBM_NL80211_IFTYPE_STATION)&&(g_vmac->iftype !=ATBM_NL80211_IFTYPE_P2P_CLIENT)) {	
		rt_kprintf("not support scan in AP mode!\n");
		return;		
	}
	if(g_hw_prv.scan.scan_smartconfig){
		rt_kprintf("scan_smartconfig now!please try later!");
		return;
   }	
	if(!g_vmac->enabled){
		rt_kprintf("not support not enabled!\n");
		return;
	}
#endif

	{
		st_cfg.type = CONFIG_TP_ATBM_SMART;
		st_cfg.magic_cnt = 1;
		st_cfg.magic_time = 70;
		st_cfg.payload_time = 12000;
	};

	atbm_ht_smt_setting();
    smartconfig_start(&st_cfg);
	return 0;
}

atbm_uint8 atbm_get_st_status(void)
{
	return g_hw_prv.st_status;
}

atbm_uint8 atbm_get_st_ssid_pwd(char *ssid, char *pwd)
{
	atbm_memcpy(ssid, hmac_cfg.ssid, hmac_cfg.ssid_len);
	atbm_memcpy(pwd, hmac_cfg.password, hmac_cfg.password_len);

	ssid[hmac_cfg.ssid_len] = '\0';
	pwd[hmac_cfg.password_len] = '\0';
	return 0;
}

atbm_uint32 atbm_smartconfig_stop()
{
	return smartconfig_stop();

}


#ifdef CONFIG_P2P
/****************************************************************************
* Function: 	atbm_wifi_p2p_start
*
* Purpose:		This function is used to create p2p main task
*
* Parameters:	None
*
* Returns: None
******************************************************************************/
int atbm_wifi_p2p_start()
{
	int ret = 0;
	struct atbmwifi_vif *priv = g_vmac;
	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS, "p2p:error, priv is NULL\n");
		ret = -1;
		goto _error;
	}

	atbm_p2p_start(priv);
_error:
	return ret;
}

/****************************************************************************
* Function: 	atbm_wifi_p2p_find
*
* Purpose:		This function is used to create p2p main task
*
* Parameters:	None
*
* Returns: None
******************************************************************************/
int atbm_wifi_p2p_find(int timeout)
{
	int ret = 0;
	struct atbmwifi_vif *priv = g_vmac;

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS, "p2p:error, priv is NULL\n");
		ret = -1;
		goto _error;
	}

	ret = atbm_p2p_find_only(priv, timeout);
_error:
	return ret;
}

/****************************************************************************
* Function: 	atbm_wifi_p2p_find
*
* Purpose:		This function is used to create p2p main task
*
* Parameters:	None
*
* Returns: None
******************************************************************************/
int atbm_wifi_p2p_find_accept(int go_intent)
{
	int ret = 0;
	struct atbmwifi_vif *priv = g_vmac;

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS, "p2p:error, priv is NULL\n");
		ret = -1;
		goto _error;
	}

	ret = atbm_p2p_find_wait_connect(priv, go_intent);
_error:
	return ret;
}

/****************************************************************************
* Function: 	atbm_wifi_p2p_find_stop
*
* Purpose:		This function is used to create p2p main task
*
* Parameters:	None
*
* Returns: None
******************************************************************************/
int atbm_wifi_p2p_find_stop(int timeout)
{
	int ret = 0;
	struct atbmwifi_vif *priv = g_vmac;

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS, "p2p:error, priv is NULL\n");
		ret = -1;
		goto _error;
	}
	iot_printf("#############atbm_wifi_p2p_find_stop###########\n");
	atbm_p2p_stop_find(priv);
_error:
	return ret;
}

/****************************************************************************
* Function: 	atbm_wifi_p2p_show_peers
*
* Purpose:		This function is used to create p2p main task
*
* Parameters:	None
*
* Returns: None
******************************************************************************/
int atbm_wifi_p2p_show_peers()
{
	int ret = 0;
	struct atbmwifi_vif *priv = g_vmac;

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS, "p2p:error, priv is NULL\n");
		ret = -1;
		goto _error;
	}

	atbm_p2p_get_peers(priv);
_error:
	return ret;
}

/****************************************************************************
* Function: 	atbm_wifi_p2p_go_start
*
* Purpose:		This function is used to create p2p main task
*
* Parameters:	None
*
* Returns: None
******************************************************************************/
int atbm_wifi_p2p_go_start()
{
	int ret = 0;
	struct atbmwifi_vif *priv = g_vmac;

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS, "p2p:error, priv is NULL\n");
		ret = -1;
		goto _error;
	}

	atbm_p2p_go_start(priv);
_error:
	return ret;
}

/****************************************************************************
* Function: 	atbm_wifi_p2p_connect
*
* Purpose:		This function is used to create p2p main task
*
* Parameters:	None
*
* Returns: None
******************************************************************************/
int atbm_wifi_p2p_connect(atbm_uint8 *mac, int go_intent)
{
	int ret = 0;
	struct atbmwifi_vif *priv = g_vmac;

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS, "p2p:error, priv is NULL\n");
		ret = -1;
		goto _error;
	}

	atbm_p2p_stop_find(priv);
	atbm_SleepMs(200);
	ret = atbm_p2p_auto_connect(priv, mac, go_intent);
_error:
	return ret;
}

/****************************************************************************
* Function: 	atbm_wifi_p2p_stop
*
* Purpose:		This function is used to create p2p main task
*
* Parameters:	None
*
* Returns: None
******************************************************************************/
int atbm_wifi_p2p_stop()
{
	int ret = 0;
	struct atbmwifi_vif *priv = g_vmac;

	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS, "p2p:error, priv is NULL\n");
		ret = -1;
		goto _error;
	}

	ret = atbm_p2p_deinit(priv);
_error:
	return ret;
}
#endif

#ifdef CONFIG_WPS
atbm_int32 atbm_wifi_wps_start_pbc(atbm_uint8 *wps_info)
{
	return atbmwps_start_pbc(g_vmac, wps_info);

}
atbm_int32 atbm_wifi_wps_start_pin(const char *pin, atbm_uint8* buf, atbm_uint32 info)
{
	return atbmwps_start_pin(g_vmac, pin, buf, info);
}
atbm_int32 atbm_wifi_wps_cancel(void)
{
	return atbmwps_cancel(g_vmac);
}
#endif

atbm_uint8 atbm_set_Freq(int channel, int frq)
{
	char cmd[20] = {0};
	
	wifi_printk(WIFI_ALWAYS, "atbm set freq: ch:%d, frq:%d\n", channel, frq);
	
	sprintf(cmd, "set_freq %d %d ", channel, frq);
	return wsm_write_mib(&g_hw_prv, WSM_MIB_ID_FW_CMD, cmd, strlen(cmd), g_vmac->if_id);
}


