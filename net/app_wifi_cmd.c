/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "atbm_hal.h"

extern struct atbmwifi_cfg hmac_cfg; 
extern struct atbmwifi_vif *  g_vmac;
extern struct atbmwifi_common g_hw_prv;

FLASH_FUNC atbm_void wifi_ConnectAP_vif(struct atbmwifi_vif *priv,atbm_uint8 * ssid,int ssidlen,atbm_uint8 * password,int passwdlen,ATBM_SECURITY_TYPE key_mgmt)
{
	if(ssidlen > 32){
		wifi_printk(WIFI_ALWAYS,"ssidlen atbm_max=32,please set again\n");
		return;
	}	
	if(passwdlen > 64){
		wifi_printk(WIFI_ALWAYS,"passwdlen atbm_max=64,please set again\n");
		return;
	}
	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS," %s priv == ATBM_NULL,please set again\n",__FUNCTION__);
		return;
	}

	//clear ssid & psw buffer
	atbm_memset(hmac_cfg.ssid, 0, sizeof(hmac_cfg.ssid));
	atbm_memset(hmac_cfg.password, 0, sizeof(hmac_cfg.password));

	atbm_memcpy(hmac_cfg.ssid,ssid,ssidlen);
	hmac_cfg.ssid_len = ssidlen;
	if(passwdlen){
		atbm_memcpy(hmac_cfg.password,password,passwdlen);
	}
	if(ATBM_KEY_WEP_SHARE != key_mgmt){
		hmac_cfg.auth_alg = ATBM_WLAN_AUTH_OPEN;
	}
	else {
		hmac_cfg.auth_alg = ATBM_WLAN_AUTH_SHARED_KEY;
	}
	hmac_cfg.password_len = passwdlen;
	hmac_cfg.privacy = passwdlen?1:0;
	hmac_cfg.key_mgmt = key_mgmt;
	hmac_cfg.key_id = 0;
	wifi_printk(WIFI_ATCMD,"%s ssid[%s]:%d passwod[%s]:%d\n",__func__,hmac_cfg.ssid,hmac_cfg.ssid_len,hmac_cfg.password,hmac_cfg.password_len);
	wpa_connect_ap(priv,ssid,ssidlen,password,passwdlen,key_mgmt,hmac_cfg.key_id);
}

/*connect AP*/
FLASH_FUNC atbm_void wifi_ConnectAP(atbm_uint8 * ssid,int ssidlen,atbm_uint8 * password,int passwdlen,ATBM_SECURITY_TYPE key_mgmt)
{
	wifi_ConnectAP_vif(g_vmac, ssid, ssidlen,password, passwdlen, key_mgmt);
}

/*start AP*/
FLASH_FUNC atbm_void __wifi_StartAP_vif(struct atbmwifi_vif *priv,atbm_uint8 * ssid,int ssidlen,atbm_uint8 * password,int passwdlen,int channel,ATBM_SECURITY_TYPE key_mgmt,ATBM_BOOL ssidBcst)
{
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);;
	wifi_printk(WIFI_ALWAYS,"wifi_StartAP_vif++ channel %d\n",channel);
	if(ssidlen > 32){
		wifi_printk(WIFI_ALWAYS,"ssidlen atbm_max=32,please set again\n");
		return;
	}	
	if(passwdlen > 64){
		wifi_printk(WIFI_ALWAYS,"passwdlen atbm_max=64,please set again\n");
		return;
	}
	if(priv == ATBM_NULL){		
		wifi_printk(WIFI_ALWAYS," %s priv == ATBM_NULL,please set again\n",__FUNCTION__);
		return;
	}
	if(atbmwifi_iee80211_check_combination(priv,channel) == ATBM_FALSE){
		wifi_printk(WIFI_ALWAYS,"channel combination err,please check\n");
		return;
	}
	atbm_memcpy(config->ssid,ssid,ssidlen);
	config->ssid_len = ssidlen;
	if(passwdlen){
		atbm_memcpy(config->password,password,passwdlen);
	}
	config->password_len = passwdlen;
	config->privacy = passwdlen?1:0;
	config->key_mgmt = key_mgmt;
	config->hide_ssid = ssidBcst;
	priv->hw_priv->channel_idex = channel;
	wifi_printk(WIFI_ATCMD,"%s ssid[%s]:%d channel_idex %d\n",__func__,config->ssid,config->ssid_len,priv->hw_priv->channel_idex);
	hostapd_start(priv,(const char *)config->ssid,config->ssid_len,(char *)config->password,config->password_len,config->key_mgmt);
}
FLASH_FUNC atbm_void wifi_StartAP_vif(struct atbmwifi_vif *priv,atbm_uint8 * ssid,int ssidlen,atbm_uint8 * password,int passwdlen,int channel,ATBM_SECURITY_TYPE key_mgmt,ATBM_BOOL ssidBcst)
{
	if(ssidlen == 0){
		wifi_printk(WIFI_DBG_ERROR,"wifi_StartAP_vif ssid len is zero err\n");
		return;
	}

	if((channel > 14)){
		wifi_printk(WIFI_DBG_ERROR,"wifi_StartAP_vif channel is zero err\n");
		return;
	}
	atbm_memset(&hmac_cfg,0,sizeof(struct atbmwifi_cfg));
	atbm_memcpy(hmac_cfg.ssid,ssid,ssidlen);
	hmac_cfg.ssid_len = ssidlen;

	hmac_cfg.password_len = passwdlen;
	if(hmac_cfg.password_len)
		atbm_memcpy(hmac_cfg.password,password,hmac_cfg.password_len);

	hmac_cfg.privacy = !!hmac_cfg.password_len;
	hmac_cfg.key_mgmt = key_mgmt;
	hmac_cfg.hide_ssid = ssidBcst;
	/*If use the ap auto channel function,user need set channle 0*/
	//channel=0;
	if(channel==0){
		atbm_autoChann_Select(priv,(atbm_uint8 *)&hmac_cfg.channel_index);
	}else{
		hmac_cfg.channel_index = channel;
	}
	atbmwifi_wpa_event_queue((atbm_void*)priv,(atbm_void*)(&hmac_cfg),ATBM_NULL,WPA_EVENT__HOSTAPD_START,ATBM_WPA_EVENT_NOACK);
}
FLASH_FUNC atbm_void atbmwifi_wpa_event_start_ap(struct atbmwifi_vif *priv,struct atbmwifi_cfg *config)
{
	__wifi_StartAP_vif(priv,config->ssid,config->ssid_len,config->password,
		config->password_len,config->channel_index,config->key_mgmt,config->hide_ssid);
}
FLASH_FUNC atbm_void wifi_StartAP(atbm_uint8 * ssid,int ssidlen,atbm_uint8 * password,int passwdlen,int channel,ATBM_SECURITY_TYPE key_mgmt,ATBM_BOOL ssidBcst)
{
	wifi_printk(WIFI_ALWAYS,"wifi_StartAP++ channel %d\n",channel);
	wifi_StartAP_vif(g_vmac,ssid, ssidlen, password, passwdlen, channel, key_mgmt,ssidBcst);
}

/*
change wifi powersave mode
*/
FLASH_FUNC atbm_void wifi_ChangePsMode(struct atbmwifi_vif *priv,atbm_uint8 enable,atbm_uint8 ds_timeout)
{
	atbmwifi_set_pm(priv,enable,ds_timeout);
}

FLASH_FUNC atbm_void AT_WDisConnect_vif(struct atbmwifi_vif *priv,char *pLine)
{		
	atbmwifi_ieee80211_connection_loss(priv);
	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"not support not enabled!\n");
		return;
	}
	if((priv->iftype != ATBM_NL80211_IFTYPE_STATION)&&(priv->iftype !=ATBM_NL80211_IFTYPE_P2P_CLIENT)) {
		wifi_printk(WIFI_ALWAYS,"not support scan in AP mode!\n");
		return;
	}
	//if(g_vmac->iftype == ATBM_NL80211_IFTYPE_STATION)
	{
		priv->auto_connect_when_lost = 0;
		wifi_printk(WIFI_ALWAYS,"AT_WDisConnect_vif() ---deauth\n");
		sta_deauth(priv);
		atbm_mdelay(100);
		wpa_disconnect(priv);
		atbm_mdelay(200);
	}
}

FLASH_FUNC atbm_void AT_WDisConnect(char *pLine)
{		
	AT_WDisConnect_vif(g_vmac,pLine);
}


/*scan AP. the scan ap result will iot_printf auto*/
FLASH_FUNC int atbmwifi_scan_process(struct atbmwifi_vif	*priv)
{
	struct atbmwifi_common *hw_priv = priv->hw_priv;

	if((priv->iftype != ATBM_NL80211_IFTYPE_STATION)&&(priv->iftype !=ATBM_NL80211_IFTYPE_P2P_CLIENT)) {	
		wifi_printk(WIFI_ALWAYS,"not support scan in AP mode!\n");
		return -1;		
	}
	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"not support not enabled!\n");
		return -2;
	}

	if(hw_priv->scan.scan_smartconfig){
		wifi_printk(WIFI_ALWAYS,"scan_smartconfig now!please try later!\n");
		return -3;
   }

	if(!hw_priv->scan.in_progress){
		if(hw_priv->scan_ret.info==ATBM_NULL){
			hw_priv->scan_ret.info = (struct atbmwifi_scan_result_info *)atbm_kmalloc(sizeof(struct atbmwifi_scan_result_info) * MAX_SCAN_INFO_NUM,GFP_KERNEL);
			if(hw_priv->scan_ret.info ==ATBM_NULL){
				wifi_printk(WIFI_ALWAYS,"scan malloc fail!");
				return -4;
			}
		}
		hw_priv->scan_ret.len = 0;
		hw_priv->scan.if_id = priv->if_id;
		priv->scan_expire = 2;
		priv->scan_no_connect_back = priv->scan_no_connect;
		priv->scan_no_connect = 1;
		return sta_scan(priv);
		//atbmwifi_scan_start(g_vmac);
		//g_vmac->scan_no_connect = 0;
	}
	else {
		wifi_printk(WIFI_ALWAYS,"scan busy!please try later!");
		return -5;
	}
}

/*
change wifi mode
mode :0 stamode
mode : 1 APmode
*/
#ifndef ATBM_COMB_IF
/*scan AP. the scan ap result will iot_printf auto*/
FLASH_FUNC int atbm_wifiScan()
{	
//#ifdef HMAC_STA_MODE
	return atbmwifi_scan_process(g_vmac);
//#endif //#ifdef HMAC_STA_MODE
}
#else


FLASH_FUNC int atbm_wifiScan(char *Args)
{	
	struct atbmwifi_common *hw_priv = &g_hw_prv;
	struct atbmwifi_vif	*priv = ATBM_NULL;
	char * str;
	if(!memcmp("IFNAME",Args,strlen("IFNAME"))){
		/*
		*pass IFNAME
		*/
		str = CmdLine_GetToken(&Args);
		/*
		*wlan0 or p2p0
		*/
		str = CmdLine_GetToken(&Args);
		priv = atbmwifi_iee80211_getvif_by_name(hw_priv,str);
	}
	if(priv == ATBM_NULL){
		wifi_printk(WIFI_ATCMD,"make sure IFNAME ???\n");
		return;
	}
	/*
	if((priv->iftype != ATBM_NL80211_IFTYPE_STATION)&&(priv->iftype !=ATBM_NL80211_IFTYPE_P2P_CLIENT)) {	
		iot_printf("not support scan in AP mode!\n");
		return;		
	}*/
	atbmwifi_scan_process(priv);
	return 0;
}

#endif

