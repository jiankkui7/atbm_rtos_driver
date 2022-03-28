/**************************************************************************************************************
 * altobeam RTOS
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "atbm_hal.h"

#ifdef CONFIG_WPS
#include "wpa_supplicant_i.h"
#include "includes.h"
#endif

extern int g_ProductTestGlobal;

extern struct atbmwifi_common g_hw_prv;
extern 	struct atbmwifi_ieee80211_supported_band atbmwifi_band_2ghz;

FLASH_FUNC atbm_void smartconfig_start_timer_func(atbm_void *arg);
FLASH_FUNC int smartconfig_magic_scan_done(struct atbmwifi_common *hw_priv);
atbm_void atbmwifi_stop_smartconfig(struct atbmwifi_common *hw_priv );

static ATBM_BOOL wmm_flag = 0;
FLASH_FUNC ATBM_BOOL atbm_wmm_status_get(atbm_void)
{
	return wmm_flag;
}
FLASH_FUNC  atbm_void atbm_wmm_status_set(ATBM_BOOL flag)
{
	wmm_flag = flag;
	wifi_printk(WIFI_ALWAYS,"ATBM: wmm is %s\n", wmm_flag?"Support":"not Suppport");
	return;
}


FLASH_FUNC atbm_void atbmwifi_enable_sta_filter_retry(struct atbmwifi_vif *priv)
{
	priv->link_id_db[ATBMWIFI__MAX_STA_IN_AP_MODE].status = ATBMWIFI__LINK_HARD;
	atbm_memset(&priv->link_id_db[ATBMWIFI__MAX_STA_IN_AP_MODE].sta_retry,0xff,sizeof(priv->link_id_db[ATBMWIFI__MAX_STA_IN_AP_MODE].sta_retry.last_rx_seq));
	return;
}
FLASH_FUNC atbm_void atbmwifi_disable_sta_filter_retry(struct atbmwifi_vif *priv)
{
	priv->link_id_db[ATBMWIFI__MAX_STA_IN_AP_MODE].status = ATBMWIFI__LINK_OFF;
	atbm_memset(&priv->link_id_db[ATBMWIFI__MAX_STA_IN_AP_MODE].sta_retry,0xff,sizeof(priv->link_id_db[ATBMWIFI__MAX_STA_IN_AP_MODE].sta_retry.last_rx_seq));
	return;
}

int atbm_join_work(struct atbm_work_struct *work)
{
	struct atbmwifi_vif *priv=(struct atbmwifi_vif *)work;
	/*先发送join ,再发送auth 认证报文*/
	atbmwifi_join_start(priv);
	return 0;
}
int atbm_event_handler(struct atbm_work_struct *work)
{
	return 0;

}
atbm_void atbm_sta_set_tim_work(struct atbm_work_struct *work)
{
	return;
}

FLASH_FUNC int atbmwifi_scan_start(struct atbmwifi_vif *priv)
{
//for compile

	int ret;
	int i;
#ifdef CONFIG_WPS
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)priv->appdata;
#endif
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_ssid ssids;
    struct wsm_scan scan;
#ifdef CONFIG_P2P
	atbm_uint8 p2p_channel[3] = {1, 6, 11};
#endif

	atbm_memset(&ssids, 0, sizeof(struct wsm_ssid));
	atbm_memset(&scan, 0, sizeof(struct wsm_scan));

	if (!priv)
	{
		wifi_printk(WIFI_SCAN,"atbm_scan_work");
	}
	scan.scanType = WSM_SCAN_TYPE_FOREGROUND;
	scan.scanFlags =0;
	scan.numOfProbeRequests = 3;
	scan.probeDelay = 10;
	scan.numOfChannels = atbmwifi_band_2ghz.n_channels;
	hw_priv->scan.status = 0;
	hw_priv->scan.if_id = priv->if_id;
	hw_priv->scan.in_progress = 1;
	scan.maxTransmitRate = WSM_TRANSMIT_RATE_1;

	
	if (hw_priv->scan.direct_probe)
		scan.maxTransmitRate = WSM_TRANSMIT_RATE_6;
	//else
	//	scan.maxTransmitRate = test_config_txrx.Rate;
#ifdef CONFIG_P2P
	if (priv->p2p_scan){
		scan.maxTransmitRate = WSM_TRANSMIT_RATE_6;
	}
#endif

	scan.band =  WSM_PHY_BAND_2_4G;
	if (priv->join_status == ATBMWIFI__JOIN_STATUS_STA) {
		scan.scanType = WSM_SCAN_TYPE_BACKGROUND;
		scan.scanFlags = WSM_SCAN_FLAG_FORCE_BACKGROUND;
		if (priv->if_id)
			scan.scanFlags |= WSM_FLAG_MAC_INSTANCE_1;
		else
			scan.scanFlags &= ~WSM_FLAG_MAC_INSTANCE_1;
	}
	scan.autoScanInterval = (0x9c << 24)|(120 * 1024); /* 30 seconds, -70 rssi */
	scan.numOfSSIDs = 1;
	//scan.numOfChannels = 1;
	//scan.probeDelay = 100;	
	scan.ssids = &ssids;
#ifndef CONFIG_P2P
	if(priv->scan_no_connect
#ifdef CONFIG_WPS
		|| wpa_s->wps_mode != WPS_MODE_UNKNOWN
#endif
		){
		scan.ssids->length = 0;
		scan.numOfSSIDs = 0;
	}
	else 
#endif
	{
		atbm_memcpy(ssids.ssid ,&priv->ssid[0], priv->ssid_length);
		scan.ssids->length = priv->ssid_length;
	}
	scan.ch = atbm_kmalloc(sizeof(struct wsm_scan_ch)*scan.numOfChannels,GFP_KERNEL);
	if (!scan.ch) {
		hw_priv->scan.status = -ATBM_ENOMEM;
		wifi_printk(WIFI_SCAN,"%s zalloc fail %d\n",__FUNCTION__,sizeof(struct wsm_scan_ch)*scan.numOfChannels);
		return 0;
	}

	//if scan_smartconfig scan not send probereq frame
	if(hw_priv->scan.scan_smartconfig){
		scan.numOfProbeRequests = 0; 
		scan.scanFlags |= WSM_FLAG_START_SMARTCONFIG; 
		wifi_printk(WIFI_DBG_ANY,"START_SMARTCONFIG scan\n");
		
	}

#ifdef CONFIG_P2P
	if(priv->p2p_scan){
		scan.numOfChannels = 3;
	}
#endif

	for (i = 0; i < scan.numOfChannels; i++) {
		if(hw_priv->scan.scan_smartconfig){
			scan.ch[i].minChannelTime = hw_priv->st_cfg.magic_time;
			scan.ch[i].maxChannelTime = hw_priv->st_cfg.magic_time+5;
		}
		else {
			scan.ch[i].minChannelTime = 45;
			scan.ch[i].maxChannelTime = 75;
		}
#ifdef CONFIG_P2P
		if(priv->p2p_scan){
			scan.ch[i].number = atbmwifi_band_2ghz.channels[p2p_channel[i] - 1].hw_value;
			scan.ch[i].txPowerLevel = atbmwifi_band_2ghz.channels[p2p_channel[i] - 1].max_power;
			scan.ch[i].minChannelTime = 55;
			scan.ch[i].maxChannelTime= 105;
		}else
#endif
		{
		scan.ch[i].number = atbmwifi_band_2ghz.channels[i].hw_value;
		scan.ch[i].txPowerLevel = atbmwifi_band_2ghz.channels[i].max_power;
		}
#ifdef CONFIG_P2P
		if(priv->p2p_join){
			scan.ch[i].minChannelTime = 65;
			scan.ch[i].maxChannelTime = 100;
		}
#endif
#if FAST_CONNECT_MODE
		if(priv->fast_connect && priv->fast_channel && ((scan.ch[i]).number == priv->fast_channel)){
			scan.numOfChannels = 1;
			scan.ch[0].number = atbmwifi_band_2ghz.channels[i].hw_value;
			scan.ch[0].txPowerLevel = atbmwifi_band_2ghz.channels[i].max_power;
			scan.ch[0].minChannelTime = 45;
			scan.ch[0].maxChannelTime = 75;
			priv->fast_connect = 0;
			break;
		}
#endif
	}
	wifi_printk(WIFI_SCAN,"atbm_scan_work if_id(%d),numOfChannels(%d),numOfSSIDs(%d)\n",priv->if_id,
		scan.numOfChannels,scan.numOfSSIDs);
	ret = wsm_scan(hw_priv, &scan, priv->if_id);
	atbm_kfree(scan.ch);

	if(ret){
		hw_priv->scan.in_progress = 0;
		wifi_printk(WIFI_SCAN,"%s fail \n",__FUNCTION__);
	}
	atbmwifi_event_uplayer(priv,ATBM_WIFI_SCANSTART_EVENT,0);
	return ret;

}

FLASH_FUNC int atbmwifi_scan_start_etf(struct atbmwifi_vif *priv)
{
	int ret;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_ssid ssids; 
	struct wsm_scan_ch	ch[2];	
	struct wsm_scan scan = {
		.scanType = WSM_SCAN_TYPE_FOREGROUND,
		.scanFlags =0,
		.numOfProbeRequests = 1,
		.probeDelay = 0,
		.numOfChannels = atbmwifi_band_2ghz.n_channels, 	
	};
	
	hw_priv->scan.status = 0;
	hw_priv->scan.if_id = priv->if_id;
	hw_priv->scan.in_progress = 1;
	
	scan.maxTransmitRate = hw_priv->etf_rate;
	scan.band =  WSM_PHY_BAND_2_4G;
	if (priv->join_status == ATBMWIFI__JOIN_STATUS_STA) {
		scan.scanType = WSM_SCAN_TYPE_BACKGROUND;
		scan.scanFlags = WSM_SCAN_FLAG_FORCE_BACKGROUND;
		if (priv->if_id)
			scan.scanFlags |= WSM_FLAG_MAC_INSTANCE_1;
		else
			scan.scanFlags &= ~WSM_FLAG_MAC_INSTANCE_1;
	}
	scan.autoScanInterval = (0xba << 24)|(120 * 1024); /* 30 seconds, -70 rssi */
	scan.numOfProbeRequests = 50;
	scan.numOfChannels =1;
	scan.numOfSSIDs = 1;
	scan.probeDelay = 5;
	scan.scanFlags = 0; /* bit 0 set => forced background scan */
	scan.scanType =WSM_SCAN_TYPE_FOREGROUND;


	scan.ssids = &ssids;
	scan.ssids->length = 0;
	memcpy(ssids.ssid,"tttttttt",8);
	scan.ssids = &ssids;
	if(priv->scan_no_connect){
		scan.ssids->length = 0;
	}

	scan.ch = &ch[0];
	scan.ch[0].number = hw_priv->etf_channel;
	scan.ch[0].minChannelTime= 5;
	scan.ch[0].maxChannelTime= 100;
	scan.ch[0].txPowerLevel= 3;

	ret = wsm_scan(hw_priv, &scan, priv->if_id);
	if(ret){
		wifi_printk(WIFI_SCAN,"%s fail \n",__func__);
	}

	//atbmwifi_event_uplayer(priv,ATBM_WIFI_SCANSTART_EVENT,0);
	return ret;
}

FLASH_FUNC int atbm_scan_work(struct atbm_work_struct *work)
{
	struct atbmwifi_vif *priv;
	struct atbmwifi_common *hw_priv =(struct atbmwifi_common *)work;
	
	priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv, hw_priv->scan.if_id);
	if(!hw_priv->scan.in_progress)
	{
		if(g_ProductTestGlobal == 1)
		{
			wifi_printk(WIFI_DBG_ERROR,"[%s]:atbmwifi_scan_start_etf \n",__FUNCTION__);
			atbmwifi_scan_start_etf(priv);
		}
		else
		{
			wifi_printk(WIFI_DBG_ERROR,"[%s] atbmwifi_scan_start \n",__FUNCTION__);
			atbmwifi_scan_start(priv);
		}
	}
	return 0;

}
FLASH_FUNC atbm_void sta_scan_start_timer_func(TIMER_1ST_PARAM atbm_void * arg)
{
	struct atbmwifi_vif *priv=(struct atbmwifi_vif *)arg;
	
	atbmwifi_wpa_event_queue((atbm_void*)priv->hw_priv,(atbm_void*)0,ATBM_NULL,
		WPA_EVENT__SUPPLICANT_SCAN_END,ATBM_WPA_EVENT_NOACK);	
}
atbm_void atbmwifi_scan_comlete(struct atbmwifi_common *hw_priv)
{
	//hw_priv->scan.if_id = 0;
	struct atbmwifi_vif *priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv,
					hw_priv->scan.if_id);

#ifdef CONFIG_WPS
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)priv->appdata;
#endif
	if(priv == ATBM_NULL)
		wifi_printk(WIFI_DBG_ERROR,"atbm: atbmwifi_scan_comlete(), priv is ATBM_NULL.\n");

#ifdef CONFIG_WPS
	if(priv->pin)
		wpa_s->scan_runs++;
#endif

	hw_priv->scan.in_progress = 0;
	// hw_priv->scan.status = -ETIMEDOUT;
	//ATBM_WARN_ON_FUNC(wsm_stop_scan(hw_priv,hw_priv->scan.if_id));
	if(!priv->enabled){
		wifi_printk(WIFI_DBG_MSG,"atbm: atbmwifi_scan_comlete(), priv disabled.\n");
		return ;
	}

	if(hw_priv->bStartTx)
	{
		if(hw_priv->bStartTxWantCancel == 0)
		{
			wifi_printk(WIFI_SCAN,"## wsm_start_scan_etf ##\n");
			//wsm_start_scan_etf(hw_priv, priv);
		}
		else
		{
			hw_priv->bStartTx = 0;
			hw_priv->bStartTxWantCancel = 0;
			if(hw_priv->etf_test_v2){
				hw_priv->etf_test_v2 = 0;
				wifi_printk(WIFI_SCAN,"## start timer etf_tx_end_work ##\n");
				etf_v2_scan_end(hw_priv,priv);
			}
		}
		return;
	}

#ifdef CONFIG_P2P
	if(priv->p2p_scan)
		p2p_scan_result();
#endif

    atbm_CancelTimer(&priv->scan_expire_timer);
	if(hw_priv->scan.status != ATBMWIFI_SCAN_CONNECT_AP_SUCCESS){
		wifi_printk(WIFI_SCAN,"scan fail again [%d]s, scan_no_connect=%d\n",priv->scan_expire, priv->scan_no_connect);
		if(priv->scan_no_connect){
			goto __end;
		}
		//atbm_queue_work(hw_priv,hw_priv->scan.scan_work);	
#ifdef CONFIG_P2P
		if(priv->p2p_scan || priv->p2p_join){
			atbm_StartTimer(&priv->scan_expire_timer,200);
		}else
#endif
		{
			atbm_StartTimer(&priv->scan_expire_timer,priv->scan_expire*1000);
		}
	}
	else {
		if(priv->scan_no_connect == 0){
			//if the first scan success,
			if(priv->connect_expire==0){
				priv->scan_expire = 5;
				priv->connect_expire = 1;
			}
			wifi_printk(WIFI_SCAN|WIFI_CONNECT,"sta_join_work  \n");
#ifdef CONFIG_WPS
			if(wpa_s->wps_mode != WPS_MODE_UNKNOWN){
				wifi_printk(WIFI_WPS|WIFI_CONNECT, "WPS: scan end\n");
				if(wpa_s->wps_ap_cnt == 0){
					wifi_printk(WIFI_WPS, "WPS: not found AP.scan again\n");
					goto __end;
				}

				if(wpa_s->wps_ap_cnt > 1){
					wifi_printk(WIFI_WPS, "WPS: overlap(%d)\n", wpa_s->wps_ap_cnt);
					atbmwps_cancel(priv);
					goto __end;
				}
			}
#endif
			atbm_queue_work(hw_priv,priv->join_work);	
		}
	}
__end:
	atbmwifi_event_uplayer(priv,ATBM_WIFI_SCANDONE_EVENT,0);
	priv->scan_no_connect=priv->scan_no_connect_back;
	if(hw_priv->scan.scan_smartconfig){
		wifi_printk(WIFI_DBG_MSG,"atbm: atbmwifi_scan_comlete() ssc.\n");
		smartconfig_magic_scan_done(hw_priv);
	}
	wifi_printk(WIFI_DBG_MSG,"atbm: atbmwifi_scan_comlete() <===\n");

	return;
}
extern struct atbmwifi_cfg hmac_cfg;
static FLASH_FUNC int __atbmwifi_autoconnect(struct atbmwifi_vif *priv)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	if(hw_priv->scan.scan_smartconfig){
		return WIFI_ERROR;
	}
	priv->auto_connect_when_lost = 0;
	wifi_printk(WIFI_ALWAYS,"autoconnect\n");
	if(priv->join_status == ATBMWIFI__JOIN_STATUS_STA){
		wifi_printk(WIFI_ALWAYS,"__atbmwifi_autoconnect() ---deauth\n");
		sta_deauth(priv);
	}
	priv->scan_no_connect=0;
	priv->scan_expire = 5;
	priv->assoc_ok = 0; 
	wpa_connect_ap(priv,hmac_cfg.ssid,hmac_cfg.ssid_len,hmac_cfg.password,hmac_cfg.password_len,hmac_cfg.key_mgmt,hmac_cfg.key_id);
	atbm_StartTimer(&priv->scan_expire_timer,priv->scan_expire*1000);
	return WIFI_OK;
}

FLASH_FUNC int atbmwifi_autoconnect(struct atbmwifi_vif *priv)
{
	atbmwifi_wpa_event_queue((atbm_void*)priv,ATBM_NULL,ATBM_NULL,WPA_EVENT__SUPPLICANT_CONNECT_FAIL,ATBM_WPA_EVENT_NOACK);
	return 0;
}

FLASH_FUNC void atbmwifi_wpa_event_connect_fail(struct atbmwifi_vif *priv)
{
	__atbmwifi_autoconnect(priv);
}

FLASH_FUNC atbm_void atbmwifi_wpa_event_process_scan_end(struct atbmwifi_common *hw_priv,
				atbm_uint32 scan_status)
{
	struct atbmwifi_vif *priv = ATBM_NULL;
	priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv,
					hw_priv->scan.if_id);
	if(priv == ATBM_NULL){
		wifi_printk(WIFI_WPA,"scan_end priv err\n");
		return;
	}
	if(scan_status == 0){
		wifi_printk(WIFI_WPA,"scan timeout\n");
		ATBM_WARN_ON(wsm_stop_scan(hw_priv,hw_priv->scan.if_id ? 1 : 0));
		if(hw_priv->scan.in_progress){
			hw_priv->scan.status = -ATBM_ETIMEDOUT;
			wifi_printk(WIFI_DBG_MSG,"atbm: sta_scan_start_timer_func(), timeout\n");
		}
	}

	if(scan_status == 1){
		atbmwifi_scan_comlete(hw_priv);
	}

	if(scan_status == 0){
		priv->scan_expire+=3;
		if(priv->scan_expire > 30){
			priv->scan_expire = 10;
		}
		if(!hw_priv->scan.in_progress)
			sta_scan(priv);
	}
}

FLASH_FUNC atbm_void atbmwifi_scan_complete_cb(struct atbmwifi_common *hw_priv,
				struct wsm_scan_complete *arg)
{
	atbmwifi_wpa_event_queue((atbm_void*)hw_priv,(atbm_void*)1,ATBM_NULL,
							WPA_EVENT__SUPPLICANT_SCAN_END,ATBM_WPA_EVENT_NOACK);
}

FLASH_FUNC int sta_scan(struct atbmwifi_vif *priv)
{	
	int ret;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);	
	struct wsm_template_frame frame;
	frame.frame_type = WSM_FRAME_TYPE_PROBE_REQUEST;	
	frame.disable =0; 
	frame.rate=0;

	//const atbm_uint32 ProbeRequestTime  = 2;
	//const atbm_uint32 ChannelRemainTime = 15;
	//atbm_uint32 maxChannelTime;
	
	wifi_printk(WIFI_SCAN,"hmac:sta_scan ++ scan_expire %ds\n",priv->scan_expire);
	if (priv->join_status == ATBMWIFI__JOIN_STATUS_AP)
		return -ATBM_EOPNOTSUPP;
	frame.skb = atbmwifi_ieee80211_send_probe_req(priv,ATBM_NULL,priv->extra_ie,priv->extra_ie_len,0);

	if (!frame.skb)
		return -ATBM_ENOMEM;

	ret = wsm_set_template_frame(hw_priv, &frame,
			priv->if_id);
	hw_priv->scan.if_id = priv->if_id;
	
	atbm_queue_work(hw_priv,hw_priv->scan.scan_work);
	atbm_dev_kfree_skb(frame.skb);

	return ret;
}
FLASH_FUNC atbm_void atbmwifi_join_complete(struct atbmwifi_vif *priv)
{	
	if(!priv->enabled){
		return ;
	}

	wifi_printk(WIFI_ALWAYS,"sta_join_ ATBM_IEEE80211_STYPE_AUTH\n");

	atbmwifi_enable_sta_filter_retry(priv);
	wpa_prepare_auth(priv);

	return;
}

FLASH_FUNC atbm_void atbmwifi_join_start(struct atbmwifi_vif *priv)
{
	int ret;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_operational_mode mode ;
	struct wsm_join join ;
	if(atbmwifi_iee80211_check_combination(priv,(atbm_uint8)priv->bss.channel_num) == ATBM_FALSE){
		wifi_printk(WIFI_ALWAYS,"atbmwifi_join_start:in combination must make sure the all of priv have the same channel\n");
		wifi_printk(WIFI_ALWAYS,"atbmwifi_join_start:cunrrent obtain channel(%d),needed channel(%d)\n",hw_priv->channel_idex,
			priv->bss.channel_num);
		return;
	}
	mode.power_mode = wsm_power_mode_quiescent;
	mode.disableMoreFlagUsage = ATBM_TRUE;

	atbm_memset(&join, 0, sizeof(join));
	
	join.mode = WSM_JOIN_MODE_BSS;
	join.preambleType = WSM_JOIN_PREAMBLE_SHORT;
	join.probeForJoin = 0;
	/* dtimPeriod will be updated after association */
	join.dtimPeriod = 1;
	join.beaconInterval = priv->bss.beacon_interval;
	join.channelNumber = priv->bss.channel_num;
	join.channel_type= priv->bss.channel_type;
	priv->config.channel_index = priv->bss.channel_num;
	hw_priv->channel_idex = priv->bss.channel_num;
	if (priv->if_id)
		join.flags |= WSM_FLAG_MAC_INSTANCE_1;
	else
		join.flags &= ~WSM_FLAG_MAC_INSTANCE_1;
	
	join.flags |= WSM_FLAG_JOIN_F_FORCE_JOIN;
	join.band = WSM_PHY_BAND_2_4G;
	join.basicRateSet = 7; /*1, 2, 5.5 mbps*/

	atbm_memcpy(&join.bssid[0], priv->bssid, sizeof(priv->bssid));
	
	join.ssidLength = priv->ssid_length;
	atbm_memcpy(&join.ssid[0], priv->ssid, join.ssidLength);

	
	wsm_set_operational_mode(hw_priv, &mode, priv->if_id);
	//wifi_printk(WIFI_CONNECT,"wsm_set_block_ack_policy\n");
	wsm_set_block_ack_policy(hw_priv,
			ATBMWIFI__TX_BLOCK_ACK_ENABLED_FOR_ALL_TID,
			ATBMWIFI__RX_BLOCK_ACK_ENABLED_FOR_ALL_TID,
			priv->if_id);

	wifi_printk(WIFI_CONNECT,"wsm_join\n");
	ret=wsm_join(hw_priv, &join, priv->if_id);

	if(ret == 0){
#ifdef FAST_CONNECT_NO_SCAN
		if(priv->fast_conn_noscan){
//			atbmwifi_ieee80211_tx_mgmt_deauth(priv,priv->bss.bssid,priv->bss.bssid,ATBM_WLAN_REASON_UNSPECIFIED);
			priv->fast_conn_noscan = 0;
		}
#endif
		priv->join_status = ATBMWIFI__JOIN_STATUS_STA;
		priv->disable_beacon_filter = ATBM_TRUE;
		atbmwifi_join_complete(priv);
		//start connect timeout
		atbm_StartTimer(&priv->connect_expire_timer,ATBM_WIFI_AUTH_TIMEOUT);

	}
	//atbmwifi_update_filtering(priv);
	return;
}

FLASH_FUNC atbm_void atbmwifi_sta_join_timeout(TIMER_1ST_PARAM atbm_void * arg)
{	
	wifi_printk(WIFI_DBG_ERROR,"atbmwifi_sta_join_timeout() \n");
	struct atbmwifi_vif *priv=(struct atbmwifi_vif *)arg;
	if(priv->auto_connect_when_lost)
		atbmwifi_autoconnect(priv);
}

FLASH_FUNC atbm_uint32 atbmwifi_rate_mask_to_wsm(struct atbmwifi_common *hw_priv, atbm_uint32 rates)
{
	atbm_uint32 ret = 0;
	int i;
	struct atbmwifi_ieee80211_rate * bitrates =
		atbmwifi_band_2ghz.bitrates;
	for (i = 0; i < 32; ++i) {
		if (rates & BIT(i))
			ret |= BIT(bitrates[i].hw_value);
	}
	return ret;
}
FLASH_FUNC int atbmwifi_rx_assoc_rsp(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{
	struct atbmwifi_ieee80211_mgmt *mgmt;
//	atbm_uint16 capab_info, aid;
	atbm_uint16 status_code;
	struct atbmwifi_ieee802_11_elems elems;
#ifdef CONFIG_WPS
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)priv->appdata;
#endif
	atbm_uint8 *pos;
	mgmt = (struct atbmwifi_ieee80211_mgmt *) ATBM_OS_SKB_DATA(skb);
	wifi_printk(WIFI_CONNECT,"atbmwifi_rx_assoc_rsp\n");

//	capab_info = atbm_le16_to_cpu(mgmt->u.assoc_resp.capab_info);
	status_code = atbm_le16_to_cpu(mgmt->u.assoc_resp.status_code);
//	aid = atbm_le16_to_cpu(mgmt->u.assoc_resp.aid);
	pos = mgmt->u.assoc_resp.variable;
	atbm_ieee802_11_parse_elems(pos, skb->dlen - (pos - (atbm_uint8 *) mgmt), &elems);
	if (status_code == ATBM_WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY &&
			    elems.timeout_int && elems.timeout_int_len == 5 &&
			    elems.timeout_int[0] == ATBM_WLAN_TIMEOUT_ASSOC_COMEBACK) {
		atbm_uint32 tu, ms;
		tu = get_unaligned_le32(elems.timeout_int + 1);
		ms = tu * 1024 / 1000;
		wifi_printk(WIFI_CONNECT,"%pM rejected association temporarily; "
		       "comeback duration %u TU (%u ms)\n", mgmt->sa, tu, ms);
		if (ms > 5)
			//
		return 0;
	}
	if (status_code != ATBM_WLAN_STATUS_SUCCESS){
		wifi_printk(WIFI_CONNECT,"%pM denied association (code=%d)\n", mgmt->sa, status_code);
	}
#ifdef CONFIG_WPS
	else{
		atbm_memcpy(wpa_s->bssid, mgmt->bssid, ATBM_ETH_ALEN);
	}
#endif
	return 0;
}
/*success return 0. fail return -1*/
FLASH_FUNC int atbmwifi_assoc_success(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{	
	struct atbmwifi_ieee80211_mgmt *mgmt;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);	
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);

	struct wsm_association_mode	association_mode;
	struct wsm_set_bss_params	bss_params;

#ifdef CONFIG_WPS
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)priv->appdata;
#endif
	struct atbmwifi_ieee802_11_elems elems;
	struct atbmwifi_ieee80211_supported_band *sband;
	atbm_uint16 capab_info, status_code, aid;
	int ret = 0;
	atbm_uint8 *pos;
	atbm_uint32 rates, basic_rates;
	int i,j;
	ATBM_BOOL have_higher_than_11mbit = ATBM_FALSE;
	int min_rate = 30;// int min_rate_index = -1;
	atbm_uint16 ap_ht_cap_flags;

	mgmt =(struct atbmwifi_ieee80211_mgmt *)ATBM_OS_SKB_DATA(skb);
	capab_info = atbm_le16_to_cpu(mgmt->u.assoc_resp.capab_info);
	status_code = atbm_le16_to_cpu(mgmt->u.assoc_resp.status_code);
	aid = atbm_le16_to_cpu(mgmt->u.assoc_resp.aid);
	priv->bss.aid = aid;
	wifi_printk(WIFI_CONNECT, "RX AssocRsp (capab=0x%x "
	     "status=%d aid=%d)\n", 
	       capab_info, status_code, (atbm_uint16)(aid & ~(BIT(15) | BIT(14))));
	

	pos = mgmt->u.assoc_resp.variable;
	atbm_ieee802_11_parse_elems(pos, skb->dlen - (pos - (atbm_uint8 *) mgmt), &elems);
	sband=&atbmwifi_band_2ghz;
	
	rates = 0;
	basic_rates = 0;
	for (i = 0; i < elems.supp_rates_len; i++) {
		int rate = (elems.supp_rates[i] & 0x7f) * 5;
		ATBM_BOOL is_basic = !!(elems.supp_rates[i] & 0x80);

		if (rate > 110)
			have_higher_than_11mbit = ATBM_TRUE;

		for (j = 0; j < sband->n_bitrates; j++) {
			if (sband->bitrates[j].bitrate == rate) {
				rates |= BIT(j);
				if (is_basic)
					basic_rates |= BIT(j);
				if (rate < min_rate) {
					min_rate = rate;
//					min_rate_index = j;
				}
				break;
			}
		}
	}
	for (i = 0; i < elems.ext_supp_rates_len; i++) {
		int rate = (elems.ext_supp_rates[i] & 0x7f) * 5;
		ATBM_BOOL is_basic = !!(elems.ext_supp_rates[i] & 0x80);

		if (rate > 110)
			have_higher_than_11mbit = ATBM_TRUE;

		for (j = 0; j < sband->n_bitrates; j++) {
			if (sband->bitrates[j].bitrate == rate) {
				rates |= BIT(j);
				if (is_basic)
					basic_rates |= BIT(j);
				if (rate < min_rate) {
					min_rate = rate;
//					min_rate_index = j;
				}
				break;
			}
		}
	}
	/* cf. IEEE 802.11 9.2.12 */
	if (sband->band == ATBM_IEEE80211_BAND_2GHZ &&
	    have_higher_than_11mbit)
		priv->bss.rate_11g=ATBM_TRUE;
	
	if (elems.ht_cap_elem && !(config->flags & ATBM_IEEE80211_STA_DISABLE_11N))
		atbmwifi_ieee80211_ht_cap_ie_to_sta_ht_cap(sband,
				elems.ht_cap_elem, &priv->bss.rate.ht_cap);
	
	ap_ht_cap_flags = priv->bss.rate.ht_cap.cap;
	if (elems.ht_info_elem &&
	    !(config->flags  & ATBM_IEEE80211_STA_DISABLE_11N)){
		atbmwifi_ieee80211_enable_ht(elems.ht_info_elem,
					       priv, ap_ht_cap_flags,
					       ATBM_FALSE);
	}
	if (elems.wmm_param){
		//atbmwifi_ieee80211_sta_wmm_params(priv,elems.wmm_param,
		//		 elems.wmm_param_len);
		atbm_wmm_status_set(1);
	}else{
		//atbmwifi_ieee80211_set_wmm_default(priv);	
		atbm_wmm_status_set(0);
	}
	if(priv->bss.rc_priv == ATBM_NULL){
		priv->bss.rc_priv = mac80211_ratectrl->alloc_sta();
	}
	priv->bss.rate.ht = atbm_is_ht(priv->bss.channel_type);
	priv->bss.rate.channel_type = priv->bss.channel_type;
	mac80211_ratectrl->sta_rate_init(&priv->bss.rate,priv->bss.rc_priv);
	//wifi_printk(WIFI_CONNECT,"bss->tx_40M=%d,rate.ht=%d\n",priv->bss.ht_40M,priv->bss.rate.ht);
#if 1
        priv->assoc_ok = 1;
        if((config->key_mgmt == ATBM_WPA_KEY_MGMT_NONE)||
                (config->key_mgmt ==ATBM_WPA_KEY_MGMT_WEP)){
               // atbmwifi_event_uplayer(priv,ATBM_WIFI_JOIN_EVENT,priv->mac_addr);
                priv->connect_ok = 1;
                priv->scan_expire = 2;
        }
       	atbmwifi_event_uplayer(priv,ATBM_WIFI_ASSOC_EVENT,(atbm_uint8*)skb);
#endif
        //cancel connect timeout
        atbm_CancelTimer(&priv->connect_expire_timer);
	association_mode.greenfieldMode = MODE_11N_MIXED;
	association_mode.flags =
		WSM_ASSOCIATION_MODE_SNOOP_ASSOC_FRAMES |
		WSM_ASSOCIATION_MODE_USE_PREAMBLE_TYPE |
		WSM_ASSOCIATION_MODE_USE_HT_MODE |
		WSM_ASSOCIATION_MODE_USE_BASIC_RATE_SET |
		WSM_ASSOCIATION_MODE_USE_MPDU_START_SPACING;
	association_mode.preambleType =
		priv->bss.short_preamble ?
		WSM_JOIN_PREAMBLE_SHORT :
		WSM_JOIN_PREAMBLE_LONG;
		association_mode.basicRateSet = atbm_cpu_to_le32(
		atbmwifi_rate_mask_to_wsm(hw_priv,
		priv->bss.rate.basic_rates));
	association_mode.mpduStartSpacing = 0;

	if(wsm_set_association_mode(hw_priv,
			&association_mode, priv->if_id)){
		ret = -1;
		goto __error;
	}
	if(wsm_keep_alive_period(hw_priv,
			ATBMWIFI__KEEP_ALIVE_PERIOD /* sec */,
			priv->if_id)){
		ret = -2;
		goto __error;
	}
	bss_params.operationalRateSet =
				atbm_cpu_to_le32(
				atbmwifi_rate_mask_to_wsm(hw_priv,priv->bss.rate.support_rates));
	
		bss_params.beaconLostCount = DEFAULT_BEACON_LOSS_CNT;
	
	bss_params.aid = priv->bss.aid;
	if(wsm_set_bss_params(hw_priv, &bss_params,
			priv->if_id)){
		ret = -3;
		goto __error;
	}
	if(wsm_set_beacon_wakeup_period(hw_priv,
				 priv->bss.beacon_interval * priv->bss.dtim_period >
				MAX_BEACON_SKIP_TIME_MS ? 1 :
				priv->bss.dtim_period, 0, priv->if_id)){
		ret = -4;
		goto __error;
	}
	if (priv->bss.rate.ht) {
		/* Statically enabling block ack for TX/RX */
		wsm_set_block_ack_policy(hw_priv,
			hw_priv->ba_tid_tx_mask, hw_priv->ba_tid_rx_mask,priv->if_id);
	}		
#if 0
	priv->assoc_ok = 1; 

	if((config->key_mgmt == ATBM_WPA_KEY_MGMT_NONE)||
		(config->key_mgmt ==ATBM_WPA_KEY_MGMT_WEP)){
		atbmwifi_event_uplayer(priv,ATBM_WIFI_JOIN_EVENT,priv->mac_addr);
		priv->connect_ok = 1;
		priv->scan_expire = 2;
	}else{
		atbmwifi_event_uplayer(priv,ATBM_WIFI_ASSOC_EVENT,(atbm_uint8*)skb);
	}
	//cancel connect timeout
	atbm_CancelTimer(&priv->connect_expire_timer);	
#endif
#ifdef CONFIG_WPS
extern int wpa_wsc_tx_process(atbm_void *ctx, int type, const atbm_uint8 *buf, atbm_size_t len);
	if(wpa_s->wps_mode != WPS_MODE_UNKNOWN){
		if(wpa_wsc_tx_process(wpa_s, ATBM_IEEE802_1X_TYPE_EAPOL_START, ATBM_NULL, 0) < 0)
			wifi_printk(WIFI_WPS, "WPS: eapol start failed.\n");
	}
#endif
__error:
	wifi_printk(WIFI_CONNECT|WIFI_DBG_ERROR,"connectap %s ret=%d \n",ret?"error":"success",ret);
	return status_code;
}


/*SUCCESS return linkid;fail return 0*/
FLASH_FUNC int sta_add_linkid(struct atbmwifi_vif *priv,
		  atbm_uint8 *sta_mac)
{
	int link_id = 0;
/*

	link_id = sta_alloc_linkid(priv, sta_mac);	
	if(link_id ==0){
		wifi_printk(WIFI_CONNECT,"%s Error \n",__FUNCTION__);
		return 0;
	}
	
	priv->link_id_db[link_id-1].status = ATBMWIFI__LINK_HARD;

	atbmwifi_link_id_lmac(priv,link_id);
*/
	/*STA mode not need to add linkid, in lmac LMC_ActivateInterface TxLinkEnabled = 0x8001;*/
	return link_id;
}

FLASH_FUNC int sta_del_linkid(struct atbmwifi_vif *priv,
		 atbm_uint8 * staMacAddr)
{

//	int link_id =0;
/*
	wifi_printk(WIFI_DBG_MSG,"[sta]:%s++\n",__FUNCTION__);

	link_id = atbmwifi_find_link_id(priv, staMacAddr);

	if((link_id <= ATBMWIFI__MAX_STA_IN_AP_MODE) && link_id>0){
		_atbmwifi_unmap_link(priv, link_id);
		priv->link_id_db[link_id-1].status = ATBMWIFI__LINK_OFF;
		wifi_printk(WIFI_DBG_MSG,"[sta]:%d link_id %d\n",__FUNCTION__,link_id);
	}
	*/
	return 0;
}

FLASH_FUNC atbm_void sta_connect_complete(struct atbmwifi_vif *priv)
{
	return;
}

atbm_void sta_deauth(struct atbmwifi_vif *priv)
{	
	
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	struct wsm_reset reset={0};
	
	tcp_opt->net_disable(priv->ndev);
	//dhcp_stop(priv->ndev);
	
	priv->join_status = ATBMWIFI__JOIN_STATUS_PASSIVE;
	if(priv->bss.information_elements){		
		atbm_kfree(priv->bss.information_elements);
		priv->bss.information_elements = ATBM_NULL;
		priv->bss.len_information_elements = 0;
	}
	priv->assoc_ok = 0;
	priv->connect_ok = 0;
	//tcp_opt->net_disable(priv->ndev);
	if(priv->bss.rc_priv){
		mac80211_ratectrl->free_sta(priv->bss.rc_priv);
		priv->bss.rc_priv = ATBM_NULL;
	}
	atbm_memset(config,0,sizeof(struct atbmwifi_cfg));
	priv->connect.encrype = 0;
	atbmwifi_del_key(priv,1,0);	
	atbmwifi_del_key(priv,0,0);	
	reset.link_id = 0;
	wifi_printk(WIFI_ALWAYS,"sta_deauth:reset+++++++\n");
	wsm_reset(priv->hw_priv, &reset, priv->if_id);	
	wifi_printk(WIFI_ALWAYS,"sta_deauth:reset-------\n");
	//void wpa_supplicant_event_disassoc(struct atbmwifi_vif *priv);
	atbmwifi_disable_sta_filter_retry(priv);
	wpa_supplicant_event_disassoc(priv);	
#if ATBM_PKG_REORDER
	wifi_printk(WIFI_CONNECT,"atbm_reorder_func_reset.\n");
	atbm_reorder_func_reset(priv,0xff);
#endif

	if(priv->auto_connect_when_lost){
		atbmwifi_autoconnect(priv);
	}
	
	return;
}
/*
ps_enabled[0~1]  power save mode ,1 power save ,0 ACTIVE
dynamic_ps_timeout [0~127 ms] fast_ps timeout;
*/
FLASH_FUNC atbm_void atbmwifi_set_pm(struct atbmwifi_vif *priv,ATBM_BOOL ps_enabled,atbm_uint8 dynamic_ps_timeout)
{	
	if (ps_enabled == ATBM_FALSE)
		priv->powersave_mode.pmMode = WSM_PSM_ACTIVE;
	else if (dynamic_ps_timeout <= 0)
		priv->powersave_mode.pmMode = WSM_PSM_PS;
	else
		priv->powersave_mode.pmMode = WSM_PSM_FAST_PS;

	wifi_printk(WIFI_PS, "[STA] Aid: %d, Joined: %s, Powersave: %s\n",
		priv->bss.aid,
		priv->join_status == ATBMWIFI__JOIN_STATUS_STA ? "yes" : "no",
		priv->powersave_mode.pmMode == WSM_PSM_ACTIVE ? "WSM_PSM_ACTIVE" :
		priv->powersave_mode.pmMode == WSM_PSM_PS ? "WSM_PSM_PS" :
		priv->powersave_mode.pmMode == WSM_PSM_FAST_PS ? "WSM_PSM_FAST_PS" :
		"UNKNOWN");

	/* Firmware requires that value for this 1-byte field must
	 * be specified in units of 500us. Values above the 128ms
	 * threshold are not supported. */
	if (dynamic_ps_timeout >= 0x80)
		priv->powersave_mode.fastPsmIdlePeriod = 0xFF;
	else
		priv->powersave_mode.fastPsmIdlePeriod =
				dynamic_ps_timeout << 1;

	if (priv->join_status == ATBMWIFI__JOIN_STATUS_STA 
		&&priv->bss.aid
		&&priv->assoc_ok)
		wsm_set_pm(priv->hw_priv, &priv->powersave_mode,
				priv->if_id);

	return;
}
/*
is ssid in the scan result(hw_priv->scan_ret.info),
if in return  0;
not return  1;
*/
ATBM_BOOL sta_scan_is_valid(struct atbmwifi_common *hw_priv,atbm_uint8 * ie)
{
	int i =0;
	//wifi_printk(WIFI_CONNECT,"scanned:[%s]\n",&ie[2]);
	for(i=0;i<hw_priv->scan_ret.len;i++ ){
		if((ie[1] == hw_priv->scan_ret.info[i].ssidlen)
		&&(atbm_memcmp(&ie[2], hw_priv->scan_ret.info[i].ssid,hw_priv->scan_ret.info[i].ssidlen)==0)){
			return ATBM_FALSE;
		}
	}
	return ATBM_TRUE;
}




int atbm_wifi_free_scaned_list(struct atbmwifi_vif *priv)
{

	return 0;
}
FLASH_FUNC atbm_void atbmwifi_start_station(struct atbmwifi_vif *priv)
{
	priv->appdata = init_wpa_supplicant(priv);
	#ifndef ATBM_COMB_IF
#if (FAST_CONNECT_MODE == 0)
	atbm_wifiScan();
#endif
	//atbm_mdelay(1000);
	//wifi_ConnectAP("wifi_test_ap29",strlen("wifi_test_ap29"),"",0,0);
	#endif	
}
/* TODO: COMBO: Flush only a particular interface specific parts */
int __atbm_flush(struct atbmwifi_common *hw_priv, ATBM_BOOL drop, int if_id)
{
	int i, ret;
	int retry = 0;
	struct atbmwifi_vif *priv =	_atbmwifi_hwpriv_to_vifpriv(hw_priv, if_id);

	if(atbm_bh_is_term(hw_priv)){
		drop = ATBM_TRUE;
	}

	atbmwifi_queue_lock(&hw_priv->tx_queue[0],priv);

	for (;;) {
		/* TODO: correct flush handling is required when dev_stop.
		 * Temporary workaround: 2s
		 */
		if (drop) {
			for (i = 0; i < 4; ++i)
				atbmwifi_queue_clear(&hw_priv->tx_queue[i],if_id);
		}

		ret = 0;		

		wsm_vif_lock_tx(priv);
		if (atbm_unlikely(!atbmwifi_queue_stats_is_empty(
				&hw_priv->tx_queue_stats, -1, if_id))) {
			/* Highly unlekely: WSM requeued frames. */
			wsm_unlock_tx(hw_priv);
			if(retry >= 3 * TEST_DTIM_INTV){
				wifi_printk(WIFI_ALWAYS,"wait tx flush timeout\n");
				drop = ATBM_TRUE;
			}
			wifi_printk(WIFI_ALWAYS,"wait tx flush\n");
			atbm_mdelay(TEST_BEACON_INTV);
			retry++;
			continue;
		}
		break;
	}
	atbmwifi_queue_unlock(&hw_priv->tx_queue[0],priv);
	//atbmwifi_queue_unlock(&hw_priv->tx_queue[1]);
	//atbmwifi_queue_unlock(&hw_priv->tx_queue[2]);
	//atbmwifi_queue_unlock(&hw_priv->tx_queue[3]);
	return ret;
}

FLASH_FUNC atbm_void sta_work_task(struct atbmwifi_vif *priv)
{
	return;
}
atbm_void atbmwifi_stop_sta(struct atbmwifi_vif *priv)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
//	struct wsm_reset reset={0};
	if(!atbmwifi_is_sta_mode(priv->iftype))
		goto sta_off;
	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"atbmwifi_stop_sta drop\n");
		goto sta_off;
	}
	__atbm_flush(hw_priv, ATBM_TRUE, priv->if_id);
	
	priv->enabled = 0;
	atbmwifi_stop_smartconfig(hw_priv);
	if(g_hw_prv.scan_ret.info ){
		atbm_kfree(g_hw_prv.scan_ret.info);
		g_hw_prv.scan_ret.info = ATBM_NULL;
		g_hw_prv.scan_ret.len =0;
	}
	if(priv->extra_ie){
		atbm_kfree(priv->extra_ie);
		priv->extra_ie_len = 0;
		priv->extra_ie = ATBM_NULL;
	}

	atbm_FreeTimer(&priv->scan_expire_timer);
	atbm_FreeTimer(&hw_priv->smartconfig_expire_timer);
	atbm_FreeTimer(&priv->connect_expire_timer);
	priv->connect.crypto_pairwise=0;
	priv->connect.crypto_group=0;

	priv->auto_connect_when_lost =0;
	priv->listening = ATBM_FALSE;
	
	sta_deauth(priv);
	atbmwifi_event_uplayer(priv,ATBM_WIFI_DEAUTH_EVENT,ATBM_NULL);
	atbm_wifi_free_scaned_list(priv);
	priv->join_status = ATBMWIFI__JOIN_STATUS_PASSIVE;
	free_wpa_supplicant(priv);
	priv->appdata =  ATBM_NULL;
	atbm_mdelay(100);
sta_off:
	priv->iftype = ATBM_NUM_NL80211_IFTYPES;
	return;
}
FLASH_FUNC atbm_void atbmwifi_start_sta(struct atbmwifi_vif *priv)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	priv->enabled = 1;
	priv->iftype = ATBM_NL80211_IFTYPE_STATION;
	atbmwifi_set_pm(priv,0,50);
	priv->scan_expire = 2;
	wifi_printk(WIFI_ALWAYS,"atbm: %s priv=%p, hw_priv=%p ===>\n",__func__,priv, hw_priv);
	atbm_InitTimer(&priv->scan_expire_timer,sta_scan_start_timer_func,(atbm_void*)priv);
	atbm_InitTimer(&hw_priv->smartconfig_expire_timer,smartconfig_start_timer_func,(atbm_void*)hw_priv);
	atbm_InitTimer(&priv->connect_expire_timer,atbmwifi_sta_join_timeout,(atbm_void*)priv);
	atbm_InitTimer(&priv->chswitch_timer,atbmwifi_sw_chntimeout,(atbm_void *)priv);

	priv->bss.channel_type = CH_OFF_20;
	atbmwifi_start_station(priv);
	wifi_printk(WIFI_ALWAYS,"atbm: %s <===\n",__func__);
	//eloop_register_timeout(0,100,wpa_atest_timeout,NULL,NULL);
	//eloop_register_timeout(1,0,wpa_atest_timeout1,NULL,NULL);
	return;
}

#ifdef CONFIG_P2P
int atbm_enable_listening(struct atbmwifi_vif *priv, atbm_uint16 chanNum){
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(g_vmac);

	struct wsm_start start = {
#ifdef P2P_MULTIVIF
		.mode = WSM_START_MODE_P2P_DEV | (priv->if_id ? (1 << 4) : 0),
#else
		.mode = WSM_START_MODE_P2P_DEV | (priv->if_id << 4),
#endif
		.band = WSM_PHY_BAND_2_4G,			//0:2.4G,1:5G
		.channelNumber = chanNum,	// channel number
		.beaconInterval = 100,
		.DTIMPeriod = 1,
		.probeDelay = 0,
		.basicRateSet = 0x0F,
	};

	if(priv->if_id == 0)
		start.channel_type = (atbm_uint32)(hw_priv->channel_type);
	else
		start.channel_type = ATBM_NL80211_CHAN_HT20;

	return wsm_start(hw_priv,&start,0);
}

int atbm_disable_listening(struct atbmwifi_vif *priv){
	int ret;
	struct wsm_reset reset = {
		.reset_statistics = ATBM_TRUE,
	};
	priv->join_status = ATBMWIFI__JOIN_STATUS_PASSIVE;
	ret = wsm_reset(priv->hw_priv, &reset, priv->if_id);
	if(priv->p2pdata){
	}
	return ret;
}
#endif

