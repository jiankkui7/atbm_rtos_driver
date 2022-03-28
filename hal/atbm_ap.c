/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "atbm_hal.h"

#define txrx_printk(...)
FLASH_FUNC int atbmwifi_sta_alloc(struct atbmwifi_vif *priv,
		  atbm_uint8 *sta_mac)
{
	int link_id = 0;
	//struct atbmwifi_sta_priv *sta_priv =NULL;

	wifi_printk(WIFI_CONNECT,"[ap]:%s\n",__FUNCTION__);

	if (priv->iftype != ATBM_NL80211_IFTYPE_AP)
		return 0;
	link_id = atbmwifi_find_link_id(priv, sta_mac);	
	if(link_id==0) {
		link_id = atbmwifi_alloc_link_id(priv, sta_mac);
		if(link_id ==0){
			wifi_printk(WIFI_CONNECT,"%s Err1\n",__FUNCTION__);
			return -1;
		}
	}
	else {
		atbmwifi_sta_del(priv,sta_mac);
		priv->link_id_db[link_id-1].status = ATBMWIFI__LINK_RESERVE;
		atbm_memset(priv->link_id_db[link_id-1].buffered, 0, ATBMWIFI__MAX_TID);
	}

	return link_id;
}

FLASH_FUNC int atbmwifi_sta_add(struct atbmwifi_vif *priv,
		  atbm_uint8 *sta_mac)
{
	int link_id = 0;
	struct atbmwifi_sta_priv *sta_priv = ATBM_NULL;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	//struct atbmwifi_link_entry *entry;
	//struct atbmwifi_common *hw_priv = priv->hw_priv;
	//wifi_printk(WIFI_DBG_MSG,"[ap]:%s++\n",__FUNCTION__);

	if (priv->iftype != ATBM_NL80211_IFTYPE_AP)
		return 0;
	link_id = atbmwifi_find_hard_link_id(priv, sta_mac); 
	if(link_id !=0){
		wifi_printk(WIFI_CONNECT,"sta_add again just drop \n");
		return 0;
	}

	link_id = atbmwifi_find_link_id(priv, sta_mac);	
	if(link_id ==0){
		wifi_printk(WIFI_CONNECT,"sta_add Error \n");
		return -1;
	}
	
	priv->link_id_db[link_id-1].status = ATBMWIFI__LINK_HARD;
	sta_priv = &priv->link_id_db[link_id-1].sta_priv;
	sta_priv->link_id = link_id;
	priv->link_id_db[link_id-1].sta_priv.sta_rc_priv = mac80211_ratectrl->alloc_sta();
	mac80211_ratectrl->sta_rate_init(&sta_priv->rate,sta_priv->sta_rc_priv);
	priv->sta_asleep_mask &= ~BIT(link_id);
	priv->buffered_set_mask &= ~BIT(link_id);

	//if not encrypt
	if(config->key_mgmt == ATBM_WPA_KEY_MGMT_NONE){
		priv->connect_ok = 1;
		atbmwifi_event_uplayer(priv,ATBM_WIFI_JOIN_EVENT,sta_mac);
	}else if(config->key_mgmt == ATBM_WPA_KEY_MGMT_WEP){	
		extern atbm_void atbmwifi_wep_key_work(struct atbmwifi_vif *priv);
		wpa_common_install_wepkey(priv,(char *)config->password,config->group_cipher,config->key_id/*KeyIndex 0...3*/,link_id);
		atbmwifi_wep_key_work(priv);
		priv->connect_ok = 1;
		atbmwifi_event_uplayer(priv,ATBM_WIFI_JOIN_EVENT,sta_mac);
	}
	atbmwifi_link_id_lmac(priv,link_id);
	//wifi_printk(WIFI_CONNECT,"************************** \n");
	wifi_printk(WIFI_CONNECT,"[ap]:assoc OK %d\n",link_id);
	//wifi_printk(WIFI_CONNECT,"************************** \n");

	return 0;
}

FLASH_FUNC int atbmwifi_sta_del(struct atbmwifi_vif *priv,
		 atbm_uint8 * staMacAddr)
{

	int link_id =0;
	wifi_printk(WIFI_CONNECT,"[ap]:atbmwifi_sta_del \n");

	if (priv->iftype != ATBM_NL80211_IFTYPE_AP)
		return 0;


	link_id = atbmwifi_find_link_id(priv, staMacAddr);
	if(link_id <= 0 || link_id > ATBMWIFI__MAX_STA_IN_AP_MODE)
		return 0;

	//del hostapd sta priv
	priv->link_id_db[link_id-1].sta_priv.reserved = ATBM_NULL;
	atbmwifi_event_uplayer(priv,ATBM_WIFI_DEAUTH_EVENT,staMacAddr);

	if(priv->link_id_db[link_id-1].sta_priv.sta_rc_priv){
		mac80211_ratectrl->free_sta(priv->link_id_db[link_id-1].sta_priv.sta_rc_priv);
		priv->link_id_db[link_id-1].sta_priv.sta_rc_priv = ATBM_NULL;
	}
	atbmwifi_del_key(priv,1, link_id);
#if ATBM_PKG_REORDER
	atbm_reorder_func_reset(priv,link_id - 1);
#endif	//ATBM_PKG_REORDER		
	_atbmwifi_unmap_link(priv, link_id);
	priv->link_id_db[link_id-1].status = ATBMWIFI__LINK_OFF;
	priv->pspoll_mask &= ~BIT(link_id);
	priv->sta_asleep_mask &= ~BIT(link_id);
	priv->buffered_set_mask &= ~BIT(link_id);
	atbm_memset(&priv->link_id_db[link_id-1].sta_retry,0,sizeof(struct atbmwifi_filter_retry));
	//priv->link_id_db[link_id-1].sta_priv = ;
	wifi_printk(WIFI_DBG_MSG,"[ap]:sta_del link_id %d\n",link_id);

	return 0;
}


FLASH_FUNC struct atbmwifi_sta_priv *atbmwifi_sta_find(struct atbmwifi_vif *priv,const atbm_uint8 *mac)
{	
	int i =0;	
	
	if (priv->iftype != ATBM_NL80211_IFTYPE_AP)
		return ATBM_NULL;
	
	for (i = 0; i < ATBMWIFI__MAX_STA_IN_AP_MODE; ++i) {
		if ((priv->link_id_db[i].status == ATBMWIFI__LINK_HARD) &&
			!atbm_memcmp(mac, priv->link_id_db[i].mac, ATBM_ETH_ALEN)){
				return &priv->link_id_db[i].sta_priv;
		}
	}
	return ATBM_NULL;
}
FLASH_FUNC struct atbmwifi_sta_priv *atbmwifi_sta_find_form_hard_linkid(struct atbmwifi_vif *priv,const atbm_uint8 linkid)
{	

	if (priv->iftype != ATBM_NL80211_IFTYPE_AP)
		return ATBM_NULL;
	
	if(linkid > ATBMWIFI__MAX_STA_IN_AP_MODE)
		return ATBM_NULL;
	if(linkid == 0)
		return ATBM_NULL;
	
	if(priv->link_id_db[linkid-1].status == ATBMWIFI__LINK_HARD)
		return &priv->link_id_db[linkid-1].sta_priv;
	else 
		return ATBM_NULL;
}

FLASH_FUNC struct atbmwifi_sta_priv *atbmwifi_sta_find_form_linkid(struct atbmwifi_vif *priv,const atbm_uint8 linkid)
{	

	if (priv->iftype != ATBM_NL80211_IFTYPE_AP)
		return ATBM_NULL;
	
	if(linkid > ATBMWIFI__MAX_STA_IN_AP_MODE)
		return ATBM_NULL;
	if(linkid == 0)
		return ATBM_NULL;
	
	if(priv->link_id_db[linkid-1].status != ATBMWIFI__LINK_OFF)
		return &priv->link_id_db[linkid-1].sta_priv;
	else 
		return ATBM_NULL;
}

static atbm_void __atbm_sta_notify(struct atbmwifi_vif *priv,
				enum sta_notify_cmd notify_cmd,
				int link_id)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	atbm_uint32 bit, prev;

	/* Zero link id means "for all link IDs" */
	if (link_id){
		bit = BIT(link_id);
	}
	else if (ATBM_WARN_ON(notify_cmd != STA_NOTIFY_AWAKE)){
		bit = 0;
	}
	else{
		bit = priv->link_id_map;
	}
	prev = priv->sta_asleep_mask & bit;
	//iot_printf("sta_notify ps cmd %d link_id %d sta_asleep_mask %d\n",notify_cmd,link_id,priv->sta_asleep_mask);
	switch (notify_cmd) {
	case STA_NOTIFY_SLEEP:
		if (!prev) {
			if (priv->buffered_multicasts &&
					!priv->sta_asleep_mask)
				atbm_queue_work(priv->hw_priv, priv->set_tim_work);
			priv->sta_asleep_mask |= bit;
			wifi_printk(WIFI_PS,"STA_NOTIFY_SLEEP--->sta_asleep_mask %x\n",priv->sta_asleep_mask);
		}
		break;
	case STA_NOTIFY_AWAKE:
		if (prev) {
			priv->sta_asleep_mask &= ~bit;
			priv->pspoll_mask &= ~bit;
			priv->link_id_uapsd_mask &= ~bit;
			if (priv->tx_multicast && link_id &&
					!priv->sta_asleep_mask)
				atbm_queue_work(priv->hw_priv, priv->set_tim_work);
			atbm_bh_wakeup(hw_priv);
			wifi_printk(WIFI_PS,"STA_NOTIFY_AWAKE--->sta_asleep_mask %x\n",priv->sta_asleep_mask);
		}
		break;
	}
}


atbm_void atbm_ps_notify(struct atbmwifi_vif *priv,
		      int link_id, ATBM_BOOL ps)
{
	if (link_id > ATBMWIFI__MAX_STA_IN_AP_MODE)
		return;

	wifi_printk(WIFI_PS,"%s for LinkId: %d. STAs asleep: %.8X\n",
			ps ? "Stop" : "Start",
			link_id, priv->sta_asleep_mask);

	/* TODO:COMBO: __atbm_sta_notify changed. */
	__atbm_sta_notify(priv,
		ps ? STA_NOTIFY_SLEEP : STA_NOTIFY_AWAKE, link_id);
}

int atbm_set_tim_impl(struct atbmwifi_vif *priv)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	atbm_uint8 * tim_ie =ATBM_NULL;
	atbm_uint8 * tim_ie_end=ATBM_NULL;
	atbm_uint8 aid0_bit_set;
	struct wsm_update_ie update_ie={0};
	update_ie.what = WSM_UPDATE_IE_BEACON;
	update_ie.count = 1;
	update_ie.length = 0;
	tim_ie = (atbm_uint8 *)atbm_kmalloc(sizeof(struct atbmwifi_ieee80211_tim_ie)+ ATBMWIFI__MAX_STA_IN_AP_MODE/8 + 4,GFP_KERNEL);
	
	atbm_spin_lock(&priv->ps_state_lock);
	aid0_bit_set = priv->buffered_multicasts;
	tim_ie_end = atbmwifi_add_tim(tim_ie,priv,priv->buffered_multicasts);
	atbm_spin_unlock(&priv->ps_state_lock);
	if(aid0_bit_set != priv->aid0_bit_set){
		long tmo=0;
		tmo=hw_priv->DTIMPeriod*(hw_priv->beaconInterval + 20);
		atbm_StartTimer(&priv->mcast_timeout, tmo);
	}

	update_ie.ies = tim_ie;
	update_ie.length = (atbm_uint32)tim_ie_end-(atbm_uint32)tim_ie;
	//ASSERT(update_ie.length  < 256);
	ATBM_WARN_ON_FUNC(wsm_update_ie(hw_priv, &update_ie, priv->if_id));
	priv->aid0_bit_set = aid0_bit_set;

	atbm_kfree(tim_ie);

	return 0;
}

atbm_void atbm_ap_set_tim_work(struct atbm_work_struct *work)
{
	struct atbmwifi_vif *priv=(struct atbmwifi_vif *)work;
	if(atbm_bh_is_term(priv->hw_priv)){
		return;
	}
	atbm_set_tim_impl(priv);
}

int atbm_set_tim(struct atbmwifi_vif *priv, struct atbmwifi_sta_priv  *sta_priv,ATBM_BOOL set)
{
	if(atbm_bh_is_term(priv->hw_priv)){
		return 0;
	}
#ifdef P2P_MULTIVIF
	ATBM_WARN_ON_FUNC(priv->if_id == ATBM_WIFI_GENERIC_IF_ID);
#endif
	ATBM_WARN_ON_FUNC(priv->iftype != ATBM_NL80211_IFTYPE_AP);
	if(atbmwifi_set_tim(priv,sta_priv->link_id,set)){
		atbm_queue_work(priv->hw_priv, priv->set_tim_work);
	}
	return 0;
}
/*if timeout ,must send mulcast frame*/
atbm_void atbmwifi_mcast_timeout(TIMER_1ST_PARAM atbm_void *arg)
{
	struct atbmwifi_vif *priv =	(struct atbmwifi_vif *)arg;	
	atbm_spin_lock(&priv->ps_state_lock);
	priv->tx_multicast = priv->aid0_bit_set && priv->buffered_multicasts;
	if (priv->tx_multicast)
		atbm_os_wakeup_event(&_atbmwifi_vifpriv_to_hwpriv(priv)->bh_wq);
	atbm_spin_unlock(&priv->ps_state_lock);
}

/* ******************************************************************** */
/* WSM callback		 LMACtoUMAC_SuspendResumeTxInd when tx DTIM	*/
atbm_void atbm_suspend_resume(struct atbmwifi_vif *priv,
			   struct wsm_suspend_resume *arg)
{
	struct atbmwifi_common *hw_priv =
		_atbmwifi_vifpriv_to_hwpriv(priv);

	wifi_printk(WIFI_PS, "[AP] %s: %s\n",
			arg->stop ? "stop" : "start",
			arg->multicast ? "broadcast" : "unicast");

	if (arg->multicast) {
		ATBM_BOOL cancel_tmo = ATBM_FALSE;
		atbm_spin_lock(&priv->ps_state_lock);
		if (arg->stop) {
			priv->tx_multicast = ATBM_FALSE;
		} else {
#if NEW_SUPPORT_PS
			//atbm_uint32 ac,n_frames;
			/* Firmware sends this indication every DTIM if there
			 * is a STA in powersave connected. There is no reason
			 * to suspend, following wakeup will consume much more
			 * power than it could be saved. */	
			 
			 priv->tx_multicast = (priv->aid0_bit_set &&priv->buffered_multicasts);
			 if(priv->tx_multicast)
			 {
			 	cancel_tmo= ATBM_TRUE;
//			 	wifi_printk(WIFI_PS,"--->muticast num n_frames =%d\n",n_frames); 
				atbm_bh_schedule_tx(priv->hw_priv);
			 }			 
#endif
		}
		atbm_spin_unlock(&priv->ps_state_lock);
		if (cancel_tmo)
			atbm_CancelTimer(&priv->mcast_timeout);
	} else {
		/*lmac call here when p2p ps mode*/
		atbm_spin_lock(&priv->ps_state_lock);
		atbm_ps_notify(priv, arg->link_id, arg->stop);
		atbm_spin_unlock(&priv->ps_state_lock);
		if (!arg->stop)
			atbm_bh_wakeup(hw_priv);
	}
	return;
}

FLASH_FUNC int atbmwifi_ap_deauth(struct atbmwifi_vif *priv,atbm_uint8 *staMacAddr)
{
	int 		link_id = atbmwifi_find_link_id(priv, staMacAddr);
	//priv->join_status = ATBMWIFI__JOIN_STATUS_PASSIVE;
	wifi_printk(WIFI_ALWAYS,"%s\n",__FUNCTION__);
	if((link_id > ATBMWIFI__MAX_STA_IN_AP_MODE) || ( link_id<=0)){
		return -1;
	}

	//atbmwifi_del_key(priv,0,0);
	//atbmwifi_del_key(priv,1,link_id);
	atbmwifi_sta_del(priv,staMacAddr);
	//if(priv->bss.information_elements){		
	//	free(priv->bss.information_elements);
	//	priv->bss.information_elements = NULL;
	//	priv->bss.len_information_elements = 0;
	//}
	//tcp_opt->net_disable(priv->ndev);
	//if(priv->bss.rc_priv){
		//for compile
	//	mac80211_ratectrl.free_sta(priv->bss.rc_priv);
	//	priv->bss.rc_priv = NULL;
	//}
	//priv->assoc_ok = 0;
	//priv->connect_ok = 0;
	//priv->connect.encrype = 0;

	return 1;
}

FLASH_FUNC int atbmwifi_ap_start_proberesp(struct atbmwifi_vif *priv)
{	
	int ret;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_template_frame frame={0};
	frame.frame_type = WSM_FRAME_TYPE_PROBE_RESPONSE;
	frame.disable =0; 
	//frame.rate = test_config_txrx.Rate;
	frame.rate = 0;//test_config_txrx.Rate;
	frame.skb = atbmwifi_ieee80211_send_proberesp(priv,priv->extra_ie,priv->extra_ie_len);
	if (ATBM_WARN_ON(!frame.skb))
		return 0;
	ret = wsm_set_template_frame(hw_priv, &frame, priv->if_id);
	atbm_dev_kfree_skb(frame.skb);

	return ret;
}
FLASH_FUNC int  atbmwifi_ap_start_beacon(struct atbmwifi_vif *priv)
{
	int ret = 0;
	struct atbmwifi_common *hw_priv =_atbmwifi_vifpriv_to_hwpriv(priv);	
	struct wsm_template_frame frame={0};
	frame.frame_type = WSM_FRAME_TYPE_BEACON;	
	frame.disable =0; 

	//frame.rate = test_config_txrx.Rate;
	frame.rate=0;
	frame.skb = atbmwifi_ieee80211_send_beacon(priv,priv->extra_ie,priv->extra_ie_len);
	if (ATBM_WARN_ON(!frame.skb))
		return 0;
	
	ret = wsm_set_template_frame(hw_priv, &frame, priv->if_id);
	if (!ret)
	{
		atbmwifi_ap_start_proberesp(priv);
	}
	
	atbm_dev_kfree_skb(frame.skb);

	return ret;	
}

FLASH_FUNC int atbm_start_ap(struct atbmwifi_vif *priv)
{
	int ret;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_start start={0};
	struct wsm_inactivity inactivity={0} ;
	struct wsm_operational_mode mode={0};
	start.mode =  WSM_START_MODE_AP;
	start.band =  WSM_PHY_BAND_2_4G;
	start.channelNumber =  hw_priv->channel_idex;
	start.beaconInterval = hw_priv->beaconInterval;
	start.DTIMPeriod 	= hw_priv->DTIMPeriod;
	start.preambleType 	= hw_priv->preambleType;
	start.probeDelay 	= 100;
	start.basicRateSet 	= hw_priv->basicRateSet;
	start.channel_type = hw_priv->channel_type;

	inactivity.min_inactivity = 39;
	inactivity.max_inactivity = 1;

	mode.power_mode = wsm_power_mode_active;
	mode.disableMoreFlagUsage = ATBM_TRUE;
	
	if (priv->if_id)
		start.mode |= WSM_FLAG_MAC_INSTANCE_1;
	else
		start.mode &= ~WSM_FLAG_MAC_INSTANCE_1;

	hw_priv->connected_sta_cnt = 0;
	if(priv->hw_priv->channel_type	== ATBM_NL80211_CHAN_HT40PLUS){
		config->secondary_channel=1;//above bandwidth
	}else{
		config->secondary_channel=-1;//below bandwidth
	}
	atbmwifi_ap_start_beacon(priv);

	priv->tx_multicast = ATBM_FALSE;
	priv->aid0_bit_set = ATBM_FALSE;
	priv->buffered_multicasts = ATBM_FALSE;
	priv->pspoll_mask = 0;
	priv->link_id_uapsd_mask=0;
	atbm_InitTimer(&priv->mcast_timeout,atbmwifi_mcast_timeout,(atbm_void*)priv);

	//priv->beacon_int = hw_priv->beaconInterval;
	//priv->join_dtim_period = hw_priv->DTIMPeriod;
	start.ssidLength = priv->ssid_length;

	atbm_memcpy(&start.ssid[0], priv->ssid, start.ssidLength);
	atbm_memset(&priv->link_id_db, 0, sizeof(priv->link_id_db));

	wifi_printk(WIFI_CONNECT, "[AP] ch: %d(%d), bcn: %d(%d), "
		"brt: 0x%x, ssid: %s.\n",
		start.channelNumber, start.band,
		start.beaconInterval, start.DTIMPeriod,
		start.basicRateSet,
		start.ssid);
	
	ret = wsm_start(hw_priv, &start, priv->if_id);
	wsm_set_inactivity(hw_priv, &inactivity, priv->if_id);
	if (!ret) {		
		priv->join_status = ATBMWIFI__JOIN_STATUS_AP;
		tcp_opt->net_enable(priv->ndev);
	}

	wsm_set_block_ack_policy(hw_priv,
		hw_priv->ba_tid_tx_mask,
		hw_priv->ba_tid_rx_mask,
		priv->if_id);
	wsm_set_operational_mode(hw_priv, &mode, priv->if_id);
	return ret;
}

atbm_void atbmwifi_ap_deauth_sta(struct atbmwifi_vif *priv,atbm_uint8 link_id,int reason_code)
{

	struct atbmwifi_sta_priv * sta_priv = atbmwifi_sta_find_form_hard_linkid(priv,priv->connect_timer_linkid);
	if(sta_priv){		
		wifi_printk(WIFI_ALWAYS,"atbmwifi_ap_deauth_sta\n");
		atbmwifi_ieee80211_tx_mgmt_deauth(priv,sta_priv->mac,priv->bssid,reason_code);
		if(atbmwifi_ap_deauth(priv,sta_priv->mac) < 0){	
			atbmwifi_event_uplayer(priv,ATBM_WIFI_DEAUTH_EVENT,sta_priv->mac);
		}
	}
}
FLASH_FUNC atbm_void atbmwifi_ap_join_timeout(TIMER_1ST_PARAM atbm_void *arg)
{	
	//atbmwifi_autoconnect(priv);
	struct atbmwifi_vif *priv=(struct atbmwifi_vif *)arg;
	wifi_printk(WIFI_WPA,"atbm: atbmwifi_ap_join_timeout(), ms=%d\n", atbm_GetOsTimeMs());
	atbmwifi_ap_deauth_sta(priv,priv->connect_timer_linkid,ATBM_WLAN_REASON_DISASSOC_STA_HAS_LEFT);
}
FLASH_FUNC atbm_void atbmwifi_ap_deauth_all(struct atbmwifi_vif *priv)
{
	//del group key
	atbmwifi_del_key(priv,0,1);
	if(priv->bss.information_elements){		
		atbm_kfree(priv->bss.information_elements);
		priv->bss.information_elements = ATBM_NULL;
		priv->bss.len_information_elements = 0;
	}
	tcp_opt->net_disable(priv->ndev);
	priv->assoc_ok = 0;
	priv->connect_ok = 0;

	wifi_printk(WIFI_ALWAYS,"atbmwifi_ap_deauth_all\n");
	atbmwifi_event_uplayer(priv,ATBM_WIFI_DEAUTH_EVENT,atbm_broadcast_ether_addr);
	//priv->connect.encrype = 0;
#if ATBM_PKG_REORDER
	atbm_reorder_func_reset(priv,0xff);
#endif

}

atbm_void atbmwifi_stop_ap(struct atbmwifi_vif *priv)
{
	atbm_uint8 cnt;
	atbm_uint32 link_id_map = 0;
	int i;
	struct wsm_reset reset={0};
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_operational_mode mode={0};
	{
		reset.reset_statistics = ATBM_TRUE;
	};

	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"atbmwifi_stop_ap drop\n");
		goto ap_off;
	}
	wifi_printk(WIFI_ALWAYS,"%s\n",__FUNCTION__);

	if(!atbmwifi_is_ap_mode(priv->iftype)){
		goto ap_off;
	}

	link_id_map = priv->link_id_map;
	for (i = 0; link_id_map; ++i) {
		if (priv->link_id_map & BIT(i)) {
			if(i > 0){
				cnt = 0;
				while(cnt++ < 3){
					atbmwifi_ieee80211_tx_mgmt_deauth(priv, priv->link_id_db[i-1].mac, priv->bssid, ATBM_WLAN_REASON_DISASSOC_AP_BUSY);
					atbmwifi_ieee80211_send_deauth_disassoc(priv, priv->link_id_db[i-1].mac,priv->bssid,
							   ATBM_IEEE80211_STYPE_DISASSOC,
							   ATBM_WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY,
							   ATBM_NULL, ATBM_TRUE);
				}
			}
			link_id_map &= ~BIT(i);
		}
	}
	__atbm_flush(hw_priv, ATBM_FALSE, priv->if_id);
	mode.power_mode = wsm_power_mode_quiescent;
	mode.disableMoreFlagUsage = ATBM_TRUE;

	for (i = 0; priv->link_id_map; ++i) {
		if (priv->link_id_map & BIT(i)) {
			if(i > 0){
				atbmwifi_ap_deauth(priv, priv->link_id_db[i-1].mac);
			}
			priv->link_id_map &= ~BIT(i);
		}
	}
	atbmwifi_ap_deauth_all(priv);
	priv->enabled = 0;
	atbm_memset(priv->link_id_db, 0,sizeof(priv->link_id_db));
	priv->sta_asleep_mask = 0;
	priv->buffered_set_mask = 0;
	priv->enable_beacon = ATBM_FALSE;
	atbm_CancelTimer(&priv->mcast_timeout);
	atbm_CancelTimer(&priv->connect_expire_timer);
	priv->tx_multicast = ATBM_FALSE;
	priv->aid0_bit_set = ATBM_FALSE;
	priv->buffered_multicasts = ATBM_FALSE;
	priv->pspoll_mask = 0;
	reset.link_id = 0;
	wsm_reset(priv->hw_priv, &reset, priv->if_id);
	ATBM_WARN_ON_FUNC(wsm_set_operational_mode(priv->hw_priv, &mode, priv->if_id));
	priv->connect.crypto_pairwise=0;
	priv->connect.crypto_group=0;

	priv->join_status = ATBMWIFI__JOIN_STATUS_PASSIVE;
	priv->assoc_ok = 0;
	priv->connect_ok = 0;
	tcp_opt->net_disable(priv->ndev);

	priv->connect.encrype = 0;

	if(priv->extra_ie){
		atbm_kfree(priv->extra_ie);
		priv->extra_ie = ATBM_NULL;
	}
	free_hostapd(priv);
	priv->appdata = ATBM_NULL;
	atbm_mdelay(100);
ap_off:
	priv->iftype = ATBM_NUM_NL80211_IFTYPES;
}



FLASH_FUNC atbm_void atbmwifi_start_hostapd(struct atbmwifi_vif *priv)
{
	priv->appdata = init_hostapd(priv);
}

FLASH_FUNC atbm_void atbmwifi_start_ap(struct atbmwifi_vif *priv)
{
//	struct atbmwifi_common * hw_priv = priv->hw_priv;
/*
	struct atbmwifi_common * hw_priv = priv->hw_priv;
	atbm_memcpy(priv->bssid,default_macaddr,6);
	atbm_memcpy(hw_priv->config->bssid,priv->bssid,6);
*/
	wifi_printk(WIFI_ALWAYS,"atbmwifi_start_ap++\n");
    priv->iftype = ATBM_NL80211_IFTYPE_AP;
	atbm_memcpy(priv->bssid ,priv->mac_addr,ATBM_ETH_ALEN);
	atbm_memcpy(priv->config.bssid,priv->bssid,6);
	priv->enabled = 1;
	atbmwifi_start_hostapd(priv);
	atbm_InitTimer(&priv->connect_expire_timer,atbmwifi_ap_join_timeout,(atbm_void*)priv);
	#ifndef ATBM_COMB_IF
	//wifi_StartAP("TESTAP",6,"12345678",8,priv->hw_priv->channel_idex,KEY_WPA2);
	#endif
	//wifi_StartAP("TESTAP",6,"",0,KEY_NONE);
	//wifi_StartAP("TTTTAP",6,"",0,priv->hw_priv->channel_idex,KEY_NONE,0);
	//wifi_StartAP("TTTTAP",6,"12345678",8,priv->hw_priv->channel_idex,KEY_WPA2,0);
}
int atbmwifi_ap_scan_start(struct atbm_work_struct *work)
{
	struct atbmwifi_vif *priv;
	struct atbmwifi_common *hw_priv =(struct atbmwifi_common *)work;
	priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv, 0);
	wifi_printk(WIFI_ALWAYS," start %s \n",__FUNCTION__);
	int ret;
	int i;
	struct wsm_ssid ssids;
    struct wsm_scan scan;

	atbm_memset(&ssids, 0, sizeof(struct wsm_ssid));
	atbm_memset(&scan, 0, sizeof(struct wsm_scan));

	scan.scanType = WSM_SCAN_TYPE_FOREGROUND;
	scan.numOfProbeRequests = 3;
	scan.numOfChannels = atbmwifi_band_2ghz.n_channels;
	hw_priv->scan.status = 0;
	hw_priv->ApScan_in_process=1;
	scan.maxTransmitRate = WSM_TRANSMIT_RATE_1;
	scan.band =  WSM_PHY_BAND_2_4G;
	scan.scanType = WSM_SCAN_TYPE_BACKGROUND;
	scan.scanFlags = WSM_FLAG_AP_BEST_CHANNEL;
	if (priv->if_id){
		scan.scanFlags |= WSM_FLAG_MAC_INSTANCE_1;
	}else{
		scan.scanFlags &= ~WSM_FLAG_MAC_INSTANCE_1;
	}
	/*There is no need set the scanThreshold & scan Auto intervel 120s*/
	scan.autoScanInterval = (0 << 24)|(120 * 1024); 
	scan.probeDelay = 20;	
	scan.ssids = &ssids;
	scan.ssids->length = 0;
	scan.numOfSSIDs = 0;
	scan.ch = atbm_kmalloc(sizeof(struct wsm_scan_ch)*scan.numOfChannels,GFP_KERNEL);
	if (!scan.ch) {
		hw_priv->scan.status = -ATBM_ENOMEM;
		wifi_printk(WIFI_SCAN,"%s zalloc fail %d\n",__FUNCTION__,sizeof(struct wsm_scan_ch)*scan.numOfChannels);
		return 0;
	}
	for (i = 0; i < scan.numOfChannels; i++) {
		scan.ch[i].minChannelTime = 300;
		scan.ch[i].maxChannelTime = 300;
		scan.ch[i].number = atbmwifi_band_2ghz.channels[i].hw_value;
		scan.ch[i].txPowerLevel = atbmwifi_band_2ghz.channels[i].max_power;
	}
	ret = wsm_scan(hw_priv, &scan, priv->if_id);
	atbm_kfree(scan.ch);
	if(ret){
		wifi_printk(WIFI_SCAN,"%s fail \n",__FUNCTION__);
	}
	wifi_printk(WIFI_ALWAYS," leave %s \n",__FUNCTION__);
	return ret;
}

int ap_scan(struct atbmwifi_vif *priv)
{	
	wifi_printk(WIFI_ALWAYS,"%s \n",__FUNCTION__);
	int ret;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);	
	struct wsm_template_frame frame;
	frame.frame_type = WSM_FRAME_TYPE_PROBE_REQUEST;	
	frame.disable =0; 
	frame.rate=0;
	frame.skb = atbmwifi_ieee80211_send_probe_req(priv,ATBM_NULL,priv->extra_ie,priv->extra_ie_len,0);
	if (!frame.skb)
		return -ATBM_ENOMEM;

	ret = wsm_set_template_frame(hw_priv, &frame,
			priv->if_id);
	hw_priv->scan.if_id = priv->if_id;
	
	atbm_queue_work(hw_priv,hw_priv->scan.ap_scan_work);
	
	atbm_dev_kfree_skb(frame.skb);

	return ret;
}

int atbmwifi_ap_auto_process(struct atbmwifi_vif *priv)
{
	struct atbmwifi_common *hw_priv = priv->hw_priv;
	wifi_printk(WIFI_ALWAYS,"%s ApScan_in_process=%d\n",__FUNCTION__,hw_priv->ApScan_in_process);
	if(!hw_priv->ApScan_in_process){
		if(hw_priv->scan_ret.info==ATBM_NULL){
			hw_priv->scan_ret.info = (struct atbmwifi_scan_result_info *)atbm_kmalloc(sizeof(struct atbmwifi_scan_result_info) * MAX_SCAN_INFO_NUM,GFP_KERNEL);
			if(hw_priv->scan_ret.info ==ATBM_NULL){
				wifi_printk(WIFI_ALWAYS,"scan malloc fail!");
				return -1;
			}
		}
		hw_priv->scan_ret.len = 0;
		hw_priv->scan.if_id = priv->if_id;
		priv->scan_no_connect = 1;
		return ap_scan(priv);
	}
	else {
		wifi_printk(WIFI_ALWAYS,"scan busy!please try later!");
		return -2;
	}
}
static int WEIGHT(int x){
	if((x)<=-75){ 
		return 0; 
	}else if((x)<=-65){ 
		return 1; 
	}else if((x)<=-50){
		return 2;
	}else{
		return 3;
	}
}

#define NUM_AP_CHNN 13
#define WAIT_CMP(x) \
		while(1){ \
			atbm_mdelay(100); \
			if(!x){ \
				break; \
			} \
		}

/*
static void AtbmSwap(atbm_uint8 *pa, atbm_uint8 *pb)
{
    atbm_uint8 tmp = *pa;
    *pa = *pb;
    *pb = tmp;
}

static atbm_uint8 ReturnMin_InSort(atbm_uint8 * Array,atbm_uint8 bgn,atbm_uint8 end)
{
	atbm_uint8 i,j;
	atbm_uint8 minIndex = 0;
	wifi_printk(WIFI_ALWAYS,"ReturnMin_InSort\n");
	for(i=bgn;i<end;++i){
		minIndex = i;
		for(j=i+1;j<end;++j){
			if(Array[j]<Array[minIndex])
				minIndex=j;
		}
		if(minIndex!=i)
	        AtbmSwap(&Array[i], &Array[minIndex]);
		wifi_printk(WIFI_ALWAYS,"Array[%d] %d\n",i,Array[i]);
	}
	
	wifi_printk(WIFI_ALWAYS,"ReturnMin_InSort %d\n",minIndex);
	return minIndex;
}
*/

static atbm_uint8 ReturnMin_InSort_1(atbm_uint8 * aCHList,atbm_uint8 *ChanArray,atbm_uint8 index,atbm_uint8 offset)
{
	atbm_uint8 i,j;
	atbm_uint8 minIndex;
#ifdef DEBUG
	wifi_printk(WIFI_ALWAYS,"ReturnMin_InSort_1 index =%d,offset=%d\n",index,offset);
		////test/////
	for(i=0;i<13;i++){
		wifi_printk(WIFI_ALWAYS,"aCHList[%d] =%d\n",i,aCHList[i]);
	}
	for(i=0;i<index;i++){
		wifi_printk(WIFI_ALWAYS,"ChanArray[%d] =%d\n",i,ChanArray[i]);
	}
	//////end/////
#endif
	//for(i=0;i<index;i++){
		minIndex=i=0;
		for(j=i+1;j<index;++j){
			if(aCHList[ChanArray[j]-offset]<aCHList[ChanArray[minIndex]-offset])
				minIndex=j;
			//wifi_printk(WIFI_ALWAYS,"minIndex %d\n",minIndex);
		}
	//	if(minIndex!=i)	
		//	AtbmSwap(&aCHList[ChanArray[i]-offset], &aCHList[ChanArray[minIndex]-offset]);

		//wifi_printk(WIFI_ALWAYS,"Array[ChanArray[%d] %d\n",i,aCHList[ChanArray[i]-offset]);
	//}
	//wifi_printk(WIFI_ALWAYS,"ReturnMin_InSort_1 minIndex=%d: %d\n",minIndex,ChanArray[minIndex]);
	return ChanArray[minIndex];
}	

int	atbm_autoChann_Select(struct atbmwifi_vif *priv,atbm_uint8 *SetChan)
{
	atbm_uint8 chanNum,index=0,ssidNum=0;
	atbm_uint8 aCHList[NUM_AP_CHNN]={0};
	atbm_uint8 MinChanNum[NUM_AP_CHNN]={1,2,3,4,5,6,7,8,9,10,11,12,13};
//	atbm_uint8 ApSet_Chann;
	WLAN_SCAN_RESULT *AutoScanBuf=ATBM_NULL;
	WLAN_BSS_INFO *bss_info;
	struct atbmwifi_scan_result_info *info;
	struct atbmwifi_common *hw_priv =priv->hw_priv;
	/*Do ap auto scan process*/
	WAIT_CMP(!priv->enabled);
	if(atbmwifi_ap_auto_process(priv)){
		return -1;
	}
	wifi_printk(WIFI_ALWAYS," start %s \n",__FUNCTION__);
	/*Wait for scan cmp*/
	WAIT_CMP(hw_priv->ApScan_in_process);
	/*It means No ap in all channl,default channel 11*/
	if(hw_priv->scan_ret.len==0){
		*SetChan=2;
	}else{
		AutoScanBuf=(WLAN_SCAN_RESULT*)atbm_kmalloc(hw_priv->scan_ret.len*sizeof(WLAN_SCAN_RESULT),GFP_KERNEL);
		bss_info =  (WLAN_BSS_INFO *)(&AutoScanBuf->bss_info[0]);
		for(ssidNum=0;ssidNum<hw_priv->scan_ret.len;ssidNum++){
			info = hw_priv->scan_ret.info + ssidNum;
			bss_info->chanspec      = info->channel;
			bss_info->RSSI = info->rssi;
			/*Auto chann select process*/
			switch(bss_info->chanspec){
				case 1:
					if(bss_info->chanspec+1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+2]+=WEIGHT(bss_info->RSSI-4);
					if(bss_info->chanspec+3 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+3]+=WEIGHT(bss_info->RSSI-8);
					break;
				case 2:
					if(bss_info->chanspec-1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+2]+=WEIGHT(bss_info->RSSI-4);
					if(bss_info->chanspec+3 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+3]+=WEIGHT(bss_info->RSSI-8);
					break;
				case 3:
					if(bss_info->chanspec-2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-2]+=WEIGHT(bss_info->RSSI-4);
					if(bss_info->chanspec-1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+2]+=WEIGHT(bss_info->RSSI-4);
					if(bss_info->chanspec+3 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+3]+=WEIGHT(bss_info->RSSI-8);
					break;
				case 4:
				case 5:
				case 6:
				case 7:
				case 8:
				case 9:
				case 10:
					if(bss_info->chanspec-3 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-3]+=WEIGHT(bss_info->RSSI-8);
					if(bss_info->chanspec-2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-2]+=WEIGHT(bss_info->RSSI-4);
					if(bss_info->chanspec-1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+2]+=WEIGHT(bss_info->RSSI-4);
					if(bss_info->chanspec+3 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+3]+=WEIGHT(bss_info->RSSI-8);
					break;
				case 11:
					if(bss_info->chanspec-3 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-3]+=WEIGHT(bss_info->RSSI-8);
					if(bss_info->chanspec-2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-2]+=WEIGHT(bss_info->RSSI-4);
					if(bss_info->chanspec-1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+2]+=WEIGHT(bss_info->RSSI-4);
					break;
				case 12:
					if(bss_info->chanspec-3 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-3]+=WEIGHT(bss_info->RSSI-8);
					if(bss_info->chanspec-2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-2]+=WEIGHT(bss_info->RSSI-4);
					if(bss_info->chanspec-1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-1]+=WEIGHT(bss_info->RSSI-2);
					if(bss_info->chanspec+1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec+1]+=WEIGHT(bss_info->RSSI-2);
					break;
				case 13:
					if(bss_info->chanspec-3 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-3]+=WEIGHT(bss_info->RSSI-8);
					if(bss_info->chanspec-2 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-2]+=WEIGHT(bss_info->RSSI-4);
					if(bss_info->chanspec+1 >= NUM_AP_CHNN) break;
					aCHList[bss_info->chanspec-1]+=WEIGHT(bss_info->RSSI-2);						
					break;
				default:
					wifi_printk(WIFI_ALWAYS,"Channel Num > 13\n");
					break;
				}
			aCHList[bss_info->chanspec]+=WEIGHT(bss_info->RSSI);
			
			//wifi_printk(WIFI_ALWAYS,"ApList %d:%d,rssi=%d\n",bss_info->chanspec,aCHList[bss_info->chanspec],info->rssi);
			bss_info++;
		}	
		
		for(chanNum=1;chanNum<NUM_AP_CHNN+1;chanNum++){
			
			//wifi_printk(WIFI_ALWAYS,"hw_priv->busy_ratio[%d] =%d\n",chanNum,hw_priv->busy_ratio[chanNum]);
			if(hw_priv->busy_ratio[chanNum]<110){
				MinChanNum[index]=chanNum;
				//wifi_printk(WIFI_ALWAYS,"MinChanNum[%d] =%d\n",index,MinChanNum[index]);
				index++;
			}
		}
#ifdef DEBUG
		/////test////
		for(chanNum=1;chanNum<NUM_AP_CHNN+1;chanNum++){
			wifi_printk(WIFI_ALWAYS,"aCHList[%d] =%d\n",chanNum,aCHList[chanNum]);
		}
		////////test end/////
#endif
		/*There is no busy_ratio<60 channl*/
		if(index==0){
			/*Do hw_priv->busy_ratio[chanNum] sort*/
			//*SetChan=ReturnMin_InSort(&hw_priv->busy_ratio[0],0,chanNum);			
			*SetChan=ReturnMin_InSort_1(&hw_priv->busy_ratio[1],&MinChanNum[0],NUM_AP_CHNN,1);
		}else{
			/*Do MinChanNum[index] sort*/
			//*SetChan=ReturnMin_InSort(&aCHList[MinChanNum[0]],MinChanNum[0],MinChanNum[index]);			
			*SetChan=ReturnMin_InSort_1(&aCHList[MinChanNum[0]],&MinChanNum[0],index,MinChanNum[0]);
		}
	}
	wifi_printk(WIFI_ALWAYS,"SetChan =%d\n",*SetChan);
	return 0;
}


