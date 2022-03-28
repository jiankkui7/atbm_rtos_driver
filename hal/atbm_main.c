/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/
#include <string.h>
#include <stdio.h>
#include "atbm_hal.h"
#include "svn_version.h"

#define ATBMWIFI_MAC80211_RC_DEFAULT "minstrel_ht"
FLASH_RDATA atbm_uint8 default_macaddr[6] = {0x00,0x00,0x11,0x32,0x43,0x69};
extern struct tcpip_opt lwip_tcp_opt;
extern PUBLIC atbm_void Hmac_timer_init(atbm_void);
//extern int atbm_wsm_event_work(struct atbm_work_struct *work);
atbm_uint32 AtbmwifiRdy=0;
struct atbmwifi_common *_atbmwifi_vifpriv_to_hwpriv(struct atbmwifi_vif *priv)
{
	return priv->hw_priv;
}
struct atbmwifi_vif *_atbmwifi_hwpriv_to_vifpriv(struct atbmwifi_common *hw_priv,int if_id)
{
	//struct atbmwifi_vif *vif;
	ATBM_WARN_ON_FUNC(-1 == if_id);
	if ((-1 == if_id) || (if_id > ATBM_WIFI_MAX_VIFS)){
		return ATBM_NULL;
	}

	return hw_priv->vif_list[if_id];
}

static  int _atbmwifi_get_nr_hw_ifaces(struct atbmwifi_common *hw_priv)
{
	return 1;
}
/* TODO:COMBO:UAPSD will be supported only on one interface */
FLASH_FUNC int atbmwifi_set_uapsd_param(struct atbmwifi_vif *priv,
				const struct wsm_edca_params *arg)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_uapsd_info		uapsd_info={0};
	int ret;
	atbm_uint16 uapsdFlags = 0;

	/* Here's the mapping AC [queue, bit]
	VO [0,3], VI [1, 2], BE [2, 1], BK [3, 0]*/

	if (arg->params[0].uapsdEnable)
		uapsdFlags |= 1 << 3;

	if (arg->params[1].uapsdEnable)
		uapsdFlags |= 1 << 2;

	if (arg->params[2].uapsdEnable)
		uapsdFlags |= 1 << 1;

	if (arg->params[3].uapsdEnable)
		uapsdFlags |= 1;

	/* Currently pseudo U-APSD operation is not supported, so setting
	* MinAutoTriggerInterval, MaxAutoTriggerInterval and
	* AutoTriggerStep to 0 */

	uapsd_info.uapsdFlags = atbm_cpu_to_le16(uapsdFlags);
	uapsd_info.minAutoTriggerInterval = 0;
	uapsd_info.maxAutoTriggerInterval = 0;
	uapsd_info.autoTriggerStep = 0;
	ret = wsm_set_uapsd_info(hw_priv, &uapsd_info,
				 priv->if_id);
	
	priv->uapsd_info.uapsdFlags=uapsd_info.uapsdFlags;
	return ret;
}
FLASH_FUNC static  atbm_void __atbmwifi_bf_configure(struct atbmwifi_vif *priv,struct wsm_beacon_filter_table *bf_table)
{
	bf_table->numOfIEs = atbm_cpu_to_le32(3);
	bf_table->entry[0].ieId = ATBM_WLAN_EID_VENDOR_SPECIFIC;
	bf_table->entry[0].actionFlags = WSM_BEACON_FILTER_IE_HAS_CHANGED |
					WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
					WSM_BEACON_FILTER_IE_HAS_APPEARED;
	bf_table->entry[0].oui[0] = 0x50;
	bf_table->entry[0].oui[1] = 0x6F;
	bf_table->entry[0].oui[2] = 0x9A;

	bf_table->entry[1].ieId = ATBM_WLAN_EID_ERP_INFO;
	bf_table->entry[1].actionFlags = WSM_BEACON_FILTER_IE_HAS_CHANGED |
					WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
					WSM_BEACON_FILTER_IE_HAS_APPEARED;

	bf_table->entry[2].ieId = ATBM_WLAN_EID_HT_INFORMATION;
	bf_table->entry[2].actionFlags = WSM_BEACON_FILTER_IE_HAS_CHANGED |
					WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
					WSM_BEACON_FILTER_IE_HAS_APPEARED;

}
FLASH_FUNC int atbmwifi_setup_mac(struct atbmwifi_common *hw_priv)
{
	int ret = 0, if_id=0;

	struct wsm_configuration cfg={0};
	cfg.dot11MaxTransmitMsduLifeTime = 512;
	cfg.dot11MaxReceiveLifeTime =512;
	cfg.dot11RtsThreshold =1000;
	cfg.dot11StationId = &hw_priv->mac_addr[0];
	/* Set low-power mode. */
	ret |= (wsm_configuration(hw_priv, &cfg, if_id));
	return 0;
}

FLASH_FUNC int atbmwifi_vif_setup(struct atbmwifi_vif *priv)
{
	struct atbmwifi_common *hw_priv = priv->hw_priv;
	struct wsm_edca_params		edca;
	struct config_edca_params	*wmm_param;
	int ret = 0;
#ifdef CFG_B2B_SIMU
	/* default EDCA */
	WSM_EDCA_SET(&edca, 0, 0x0001, 0x0001, 0x0007,
			47, 0xc8, ATBM_FALSE);
	WSM_EDCA_SET(&edca, 1, 0x0001, 0x0001, 0x000f,
			94, 0xc8, ATBM_FALSE);
		WSM_EDCA_SET(&edca, 2, 0x0001, 0x0001, 0x03ff,
			0, 0xc8, ATBM_FALSE);
	WSM_EDCA_SET(&edca, 3, 0x0001, 0x0001, 0x03ff,
			0, 0xc8, ATBM_FALSE);
#else /*CFG_B2B_FPGA*/
	/* default EDCA */
	//VO
	wmm_param= &priv->wmm_params[ATBM_D11_ACI_AC_VO];
	WSM_EDCA_SET(&edca, ATBM_IEEE80211_AC_VO /*0*/, wmm_param->aifns, wmm_param->cwMin, wmm_param->cwMax,
			wmm_param->txOpLimit, 0xc8, wmm_param->uapsdEnable); 
	//VI
	wmm_param= &priv->wmm_params[ATBM_D11_ACI_AC_VI];
	WSM_EDCA_SET(&edca, ATBM_IEEE80211_AC_VI /*1*/, wmm_param->aifns, wmm_param->cwMin, wmm_param->cwMax,
			wmm_param->txOpLimit, 0xc8, wmm_param->uapsdEnable);
	//BE
	wmm_param= &priv->wmm_params[ATBM_D11_ACI_AC_BE];
	WSM_EDCA_SET(&edca, ATBM_IEEE80211_AC_BE /*2*/, wmm_param->aifns, wmm_param->cwMin, wmm_param->cwMax,
			wmm_param->txOpLimit, 0xc8,  wmm_param->uapsdEnable);
	//BK
	wmm_param= &priv->wmm_params[ATBM_D11_ACI_AC_BK];
	WSM_EDCA_SET(&edca, ATBM_IEEE80211_AC_BK /*3*/, wmm_param->aifns, wmm_param->cwMin, wmm_param->cwMax,
			wmm_param->txOpLimit, 0xc8,  wmm_param->uapsdEnable);

#endif /*CFG_B2B_SIMU*/
	ret = wsm_set_edca_params(hw_priv, &edca, priv->if_id);
	if (ATBM_WARN_ON(ret))
		goto out;

	ret = atbmwifi_set_uapsd_param(priv, &edca);
	if (ATBM_WARN_ON(ret))
		goto out;
	priv->wep_default_key_id = -1;
	priv->bf_control.enabled = WSM_BEACON_FILTER_ENABLE;
out:
	return ret;
}

FLASH_FUNC int atbmwifi_setup_mac_pvif(struct atbmwifi_vif *priv)
{
	int ret = 0;
	/* NOTE: There is a bug in FW: it reports signal
	* as RSSI if RSSI subscription is enabled.
	* It's not enough to set WSM_RCPI_RSSI_USE_RSSI. */
	/* NOTE2: RSSI based reports have been switched to RCPI, since
	* FW has a bug and RSSI reported values are not stable,
	* what can leads to signal level oscilations in user-end applications */
	struct wsm_rcpi_rssi_threshold threshold={0};
	threshold.rssiRcpiMode = WSM_RCPI_RSSI_THRESHOLD_ENABLE | WSM_RCPI_RSSI_DONT_USE_UPPER |WSM_RCPI_RSSI_DONT_USE_LOWER;
	threshold.rollingAverageCount = 16;
	/* Remember the decission here to make sure, we will handle
	 * the RCPI/RSSI value correctly on WSM_EVENT_RCPI_RSS */
	if (threshold.rssiRcpiMode & WSM_RCPI_RSSI_USE_RSSI)
		priv->cqm_use_rssi = ATBM_TRUE;


	/* Configure RSSI/SCPI reporting as RSSI. */
#ifdef P2P_MULTIVIF
	ret = wsm_set_rcpi_rssi_threshold(priv->hw_priv, &threshold,
					priv->if_id ? 1 : 0);
#else
	ret = wsm_set_rcpi_rssi_threshold(priv->hw_priv, &threshold,
					priv->if_id);
#endif
	return ret;
}


FLASH_FUNC atbm_void atbmwifi_update_filtering(struct atbmwifi_vif *priv)
{
	int ret;
	ATBM_BOOL ap_mode = 0;
	ATBM_BOOL bssid_filtering = !priv->rx_filter.bssid;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_beacon_filter_control bf_disabled={0};
	struct wsm_beacon_filter_table bf_table_auto={0};
	struct wsm_beacon_filter_control bf_auto={0};
	bf_disabled.enabled = 0;
	bf_disabled.bcn_count = 1;
	bf_table_auto.numOfIEs = atbm_cpu_to_le32(2);
	bf_table_auto.entry[0].ieId = ATBM_WLAN_EID_VENDOR_SPECIFIC;
	bf_table_auto.entry[0].actionFlags = WSM_BEACON_FILTER_IE_HAS_CHANGED |
				WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
				WSM_BEACON_FILTER_IE_HAS_APPEARED;
	bf_table_auto.entry[0].oui[0] = 0x50;
	bf_table_auto.entry[0].oui[1] = 0x6F;
	bf_table_auto.entry[0].oui[2] = 0x9A;

	bf_table_auto.entry[1].ieId = ATBM_WLAN_EID_HT_INFORMATION;
	bf_table_auto.entry[1].actionFlags = WSM_BEACON_FILTER_IE_HAS_CHANGED |
				WSM_BEACON_FILTER_IE_NO_LONGER_PRESENT |
				WSM_BEACON_FILTER_IE_HAS_APPEARED;
	bf_auto.enabled = WSM_BEACON_FILTER_ENABLE |
		WSM_BEACON_FILTER_AUTO_ERP;
	bf_auto.bcn_count = 1;
	bf_auto.bcn_count = priv->bf_control.bcn_count;

	if (priv->join_status == ATBMWIFI__JOIN_STATUS_PASSIVE)
		return;
	else if (priv->join_status == ATBMWIFI__JOIN_STATUS_MONITOR)
		bssid_filtering = ATBM_FALSE;

	if (priv->iftype == ATBM_NL80211_IFTYPE_AP)
		ap_mode = ATBM_TRUE;
	/*
	* When acting as p2p client being connected to p2p GO, in order to
	* receive frames from a different p2p device, turn off bssid filter.
	*
	* WARNING: FW dependency!
	* This can only be used with FW WSM371 and its successors.
	* In that FW version even with bssid filter turned off,
	* device will block most of the unwanted frames.
	*/
	//if (priv->vif && priv->vif->p2p)
		//bssid_filtering = ATBM_FALSE;

	ret = wsm_set_rx_filter(hw_priv, &priv->rx_filter, priv->if_id);
	if (!ret && !ap_mode) {
		if (ATBM_NL80211_IFTYPE_STATION != priv->iftype){
			__atbmwifi_bf_configure(priv,&bf_table_auto);
		}
		ret = wsm_set_beacon_filter_table(hw_priv, &bf_table_auto,
							priv->if_id);
		
	}
	if (!ret && !ap_mode) {
		if (priv->disable_beacon_filter)
			ret = wsm_beacon_filter_control(hw_priv,
					&bf_disabled, priv->if_id);
		else {
			if (ATBM_NL80211_IFTYPE_STATION != priv->iftype)
				ret = wsm_beacon_filter_control(hw_priv,
					&priv->bf_control, priv->if_id);
			else
				ret = wsm_beacon_filter_control(hw_priv,
					&bf_auto, priv->if_id);
		}
	}

	if (!ret)
		ret = wsm_set_bssid_filtering(hw_priv, bssid_filtering,
					priv->if_id);
	if (ret)
		wifi_printk(WIFI_DBG_ERROR,"%s:fail=%d.\n",
				__FUNCTION__, ret);
	return;
}

FLASH_FUNC int _atbmwifi_unmap_link(struct atbmwifi_vif *priv, int link_id)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_map_link maplink;
	maplink.link_id = link_id;
	maplink.unmap = ATBM_TRUE;
	if (link_id)
		atbm_memcpy(&maplink.mac_addr[0],
			priv->link_id_db[link_id - 1].mac, ATBM_ETH_ALEN);
	return wsm_map_link(hw_priv, &maplink, priv->if_id);
}
FLASH_FUNC atbm_void atbmwifi_link_id_lmac(struct atbmwifi_vif *priv,int link_id )
{
	ATBM_BOOL need_reset;
	atbm_uint32 mask;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_map_link map_link;
	map_link.link_id = 0;
	map_link.unmap = 0;
	//int i=0;
	if (priv->join_status != ATBMWIFI__JOIN_STATUS_AP)
		return;

	//wsm_lock_tx(hw_priv);
	atbm_spin_lock(&priv->ps_state_lock);
	//for (i = 0; i < ATBMWIFI__MAX_STA_IN_AP_MODE; ++i) {
		need_reset = ATBM_FALSE;
		mask = BIT(link_id);
		if(priv->link_id_db[link_id-1].status == ATBMWIFI__LINK_HARD) {
			if (priv->link_id_map & mask) {
				priv->sta_asleep_mask &= ~mask;
				priv->pspoll_mask &= ~mask;
				need_reset = ATBM_TRUE;
			}
			priv->link_id_map |= mask;
			
			atbm_memcpy(map_link.mac_addr, priv->link_id_db[link_id-1].mac,ATBM_ETH_ALEN);
			if (need_reset) {
				_atbmwifi_unmap_link(priv, link_id);
			}
			map_link.link_id = link_id;
			wsm_map_link(hw_priv, &map_link, priv->if_id);
		} 	
	atbm_spin_unlock(&priv->ps_state_lock);
	//}

}

FLASH_FUNC int atbmwifi_alloc_link_id(struct atbmwifi_vif *priv, const atbm_uint8 *mac)
{
	int i, ret = 0;
	for (i = 0; i < ATBMWIFI__MAX_STA_IN_AP_MODE; ++i) {
		if (!priv->link_id_db[i].status) {
			ret = i + 1;
			break;
		}
	}
	ATBM_WARN_ON_FUNC(ret>ATBMWIFI__MAX_STA_IN_AP_MODE);
	ATBM_WARN_ON_FUNC(ret==0);
	
	if (ret) {
		struct atbmwifi_link_entry *entry = &priv->link_id_db[ret - 1];
		wifi_printk(WIFI_ALWAYS,"[AP] STA added, link_id: %d\n",ret);
		entry->status = ATBMWIFI__LINK_RESERVE;
		atbm_memcpy(&entry->mac, mac, ATBM_ETH_ALEN);
		atbm_memset(&entry->buffered, 0, ATBMWIFI__MAX_TID);
		atbm_memcpy(entry->sta_priv.mac, mac, ATBM_ETH_ALEN);
		entry->sta_priv.priv =priv ;
		entry->sta_priv.link_id =ret ;
		entry->sta_priv.flags =0 ;
		entry->sta_priv.driver_buffered_tids =0 ;
	} 

	return ret;
}

/*find hard connected link id ,get sta mac address, and copy together*/
FLASH_FUNC int atbmwifi_get_hard_linked_macs(struct atbmwifi_vif *priv,  atbm_uint8 *mac, atbm_uint32 maccnt)
{
	int i;
	atbm_uint8 *tmp = mac;
	int mac_copyed_len = 0;
	atbm_spin_lock(&priv->ps_state_lock);

	for (i = 0; i <  ATBMWIFI__MAX_STA_IN_AP_MODE; ++i) {
		if ((priv->link_id_db[i].status==ATBMWIFI__LINK_HARD)) {

			atbm_memcpy(tmp, priv->link_id_db[i].mac,  ATBM_ETH_ALEN);
			mac_copyed_len++;
			tmp += ATBM_ETH_ALEN;	
			if(mac_copyed_len >= maccnt)
			{
				break;
			}
		}
	}
	atbm_spin_unlock(&priv->ps_state_lock);
	return mac_copyed_len;
}


/*find link id ,have alloc link id*/
FLASH_FUNC int atbmwifi_find_link_id(struct atbmwifi_vif *priv, const atbm_uint8 *mac)
{
	int i, ret = 0;
	atbm_spin_lock(&priv->ps_state_lock);

	for (i = 0; i < ATBMWIFI__MAX_STA_IN_AP_MODE; ++i) {
		if (!atbm_memcmp(mac, priv->link_id_db[i].mac, ATBM_ETH_ALEN) &&
				priv->link_id_db[i].status) {
			//priv->link_id_db[i].timestamp = atbm_GetOsTimeMs;
			ret = i + 1;
			break;
		}
	}
	atbm_spin_unlock(&priv->ps_state_lock);
	return ret;
}
/*find link id ,have connect link id*/
FLASH_FUNC int atbmwifi_find_hard_link_id(struct atbmwifi_vif *priv, const atbm_uint8 *mac)
{
	int i, ret = 0;
	atbm_spin_lock(&priv->ps_state_lock);

	for (i = 0; i < ATBMWIFI__MAX_STA_IN_AP_MODE; ++i) {
		if (!atbm_memcmp(mac, priv->link_id_db[i].mac, ATBM_ETH_ALEN) &&
				(priv->link_id_db[i].status==ATBMWIFI__LINK_HARD)) {
			//priv->link_id_db[i].timestamp = atbm_GetOsTimeMs;
			ret = i + 1;
			break;
		}
	}
	atbm_spin_unlock(&priv->ps_state_lock);
	return ret;
}



FLASH_FUNC atbm_void atbmwifi_event_handler(struct atbmwifi_vif *priv,atbm_uint32 eventId,atbm_uint32 eventData)
{
	switch (eventId) {
		case WSM_EVENT_ERROR:
			/* I even don't know what is it about.. */
			//STUB();
			break;
		case WSM_EVENT_BSS_LOST:
		{
			wifi_printk(WIFI_CONNECT|WIFI_DBG_ERROR,"[CQM] BSS lost.\n");
			
			atbmwifi_ieee80211_connection_loss(priv);
			if(priv->iftype == ATBM_NL80211_IFTYPE_STATION)
			{
				wifi_printk(WIFI_ALWAYS,"atbmwifi_event_handler() ---deauth\n");
				sta_deauth(priv);
			}
			else
			{
				//atbmwifi_ap_deauth(priv,StaMac);
			}
			break;
		}
		case WSM_EVENT_BSS_REGAINED:
		{
			//sta_printk(KERN_DEBUG "[CQM] BSS regained.\n");
			//priv->delayed_link_loss = 0;
			//atbm_spin_lock(&priv->bss_loss_lock);
			//priv->bss_loss_status = ATBMWIFI__BSS_LOSS_NONE;		
			//atbm_spin_unlock(&priv->bss_loss_lock);
			//cancel_delayed_work_sync(&priv->bss_loss_work);
			//cancel_delayed_work_sync(&priv->connection_loss_work);
			break;
		}
		case WSM_EVENT_RADAR_DETECTED:
			//STUB();
			break;
		case WSM_EVENT_RCPI_RSSI:
		{
			break;
		}
		case WSM_EVENT_BT_INACTIVE:
			//STUB();
			break;
		case WSM_EVENT_BT_ACTIVE:
			//STUB();
			break;
		case WSM_EVENT_INACTIVITY://WSM_EVENT_IND_INACTIVITY
		{
			int link_id = atbm_ffs((atbm_uint32)eventData) - 1;
			struct atbm_buff *skb;
	        struct atbmwifi_ieee80211_mgmt *deauth;
	        struct atbmwifi_link_entry *entry = ATBM_NULL;

			wifi_printk(WIFI_CONNECT|WIFI_DBG_ERROR, "Inactivity Event Rx "
					"link_id %d\n", link_id);
			_atbmwifi_unmap_link(priv, link_id);

			skb = atbm_dev_alloc_skb(sizeof(struct atbmwifi_ieee80211_mgmt));
			//atbm_skb_reserve(skb, 64);
			deauth = (struct atbmwifi_ieee80211_mgmt *)atbm_skb_put(skb, sizeof(struct atbmwifi_ieee80211_mgmt));
            ATBM_WARN_ON_FUNC(!deauth);
            entry = &priv->link_id_db[link_id - 1];
            deauth->duration = 0;	
			atbm_memcpy(deauth->da, priv->mac_addr, ATBM_ETH_ALEN);
            atbm_memcpy(deauth->sa, entry->mac/*priv->link_id_db[i].mac*/, ATBM_ETH_ALEN);
            atbm_memcpy(deauth->bssid,priv->mac_addr, ATBM_ETH_ALEN);
			deauth->frame_control = atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_MGMT |
	                                            ATBM_IEEE80211_STYPE_DEAUTH |
	                                            ATBM_IEEE80211_FCTL_TODS);
            deauth->u.deauth.reason_code = ATBM_WLAN_REASON_DEAUTH_LEAVING;
            deauth->seq_ctrl = 0;
            if(atbmwifi_ieee80211_rx_irqsafe(priv, skb) != 0){
				atbm_dev_kfree_skb(skb);
			}
			//iot_printf(" Inactivity Deauth Frame sent for MAC SA %pM \t and DA %pM\n", deauth->sa, deauth->da);
			atbm_set_tim_impl(priv);
			break;
		}
		case WSM_EVENT_PS_MODE_ERROR:
		{
			/*
			if (priv->user_pm_mode != WSM_PSM_PS)
			{
				struct wsm_set_pm pm = priv->powersave_mode;
				int ret = 0;

				priv->powersave_mode.pmMode = WSM_PSM_ACTIVE;
				ret = atbmwifi_set_pm (priv, &priv->powersave_mode);
				if(ret)
					priv->powersave_mode = pm;
			}
                     break;
                    */
		}
	}
}


struct atbmwifi_common g_hw_prv;
struct atbmwifi_vif *  g_vmac=ATBM_NULL;

/* TODO: use rates and channels from the device */
#define RATETAB_ENT(_rate, _rateid, _flags)		{_rate, _rateid, _flags}

/*
struct atbmwifi_ieee80211_rate {
atbm_uint16 bitrate;
atbm_uint8 hw_value;
atbm_uint8 rate_flag;
};

.bitrate	= (_rate),		\
.hw_value	= (_rateid),		\
.rate_flag	= (_flags),	\
*/

struct atbmwifi_ieee80211_rate atbmwifi_rates[ATBM_WIFI_RATE_SIZE] = {	

	RATETAB_ENT(2,  0,   ATBM_IEEE80211_RT_BASIC|ATBM_IEEE80211_RT_11B),
	RATETAB_ENT(4,  1,   ATBM_IEEE80211_RT_BASIC|ATBM_IEEE80211_RT_11B),
	RATETAB_ENT(11,  2,   ATBM_IEEE80211_RT_BASIC|ATBM_IEEE80211_RT_11B),
	RATETAB_ENT(22, 3,   ATBM_IEEE80211_RT_BASIC|ATBM_IEEE80211_RT_11B),
	RATETAB_ENT(12,  6,   ATBM_IEEE80211_RT_11G),
	RATETAB_ENT(18,  7,  ATBM_IEEE80211_RT_11G),
	RATETAB_ENT(24, 8,  ATBM_IEEE80211_RT_11G),
	RATETAB_ENT(36, 9,  ATBM_IEEE80211_RT_11G),
	RATETAB_ENT(48, 10, ATBM_IEEE80211_RT_11G),
	RATETAB_ENT(72, 11, ATBM_IEEE80211_RT_11G),
	RATETAB_ENT(96, 12, ATBM_IEEE80211_RT_11G),
	RATETAB_ENT(108, 13, ATBM_IEEE80211_RT_11G),
};

//500k  unit
struct atbmwifi_ieee80211_rate atbm_mcs_rates[] = {
	RATETAB_ENT(13,  14, ATBM_IEEE80211_TX_RC_MCS),
	RATETAB_ENT(26, 15, ATBM_IEEE80211_TX_RC_MCS),
	RATETAB_ENT(39, 16, ATBM_IEEE80211_TX_RC_MCS),
	RATETAB_ENT(52, 17, ATBM_IEEE80211_TX_RC_MCS),
	RATETAB_ENT(78, 18, ATBM_IEEE80211_TX_RC_MCS),
	RATETAB_ENT(104, 19, ATBM_IEEE80211_TX_RC_MCS),
	RATETAB_ENT(117, 20, ATBM_IEEE80211_TX_RC_MCS),
	RATETAB_ENT(130, 21, ATBM_IEEE80211_TX_RC_MCS),
	RATETAB_ENT(12 , 22, ATBM_IEEE80211_TX_RC_MCS),
};
#define CHAN2G(_channel, _freq, _flags) {30, _channel, _flags}
	
const static struct atbmwifi_ieee80211_channel atbmwifi_2ghz_chantable_const[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};

struct atbmwifi_ieee80211_channel atbmwifi_2ghz_chantable[14] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
};



struct atbmwifi_ieee80211_supported_band atbmwifi_band_2ghz;
//for compile
atbm_void atbmwifi_band_2ghz_init(atbm_void)
{
	atbm_memset(&atbmwifi_band_2ghz, 0, sizeof(atbmwifi_band_2ghz));
	
	atbmwifi_band_2ghz.channels = atbmwifi_2ghz_chantable;
	atbmwifi_band_2ghz.n_channels = ATBM_ARRAY_SIZE(atbmwifi_2ghz_chantable);
	atbmwifi_band_2ghz.bitrates =atbmwifi_g_rates;
	atbmwifi_band_2ghz.n_bitrates = atbmwifi_g_rates_size;
//	atbmwifi_band_2ghz.ht_cap;
#if BW_40M_SUPPORT
	atbmwifi_band_2ghz.ht_cap.cap = ATBM_IEEE80211_HT_CAP_GRN_FLD| 
									ATBM_IEEE80211_HT_CAP_SGI_20|
									(1 << ATBM_IEEE80211_HT_CAP_RX_STBC_SHIFT)|
									ATBM_IEEE80211_HT_CAP_SUP_WIDTH_20_40|
									ATBM_IEEE80211_HT_CAP_DSSSCCK40|
									ATBM_IEEE80211_HT_CAP_SGI_40;
#else
	atbmwifi_band_2ghz.ht_cap.cap = ATBM_IEEE80211_HT_CAP_SGI_20|
									(1 << ATBM_IEEE80211_HT_CAP_RX_STBC_SHIFT);
#endif  //BW_40M_SUPPORT
	
	atbmwifi_band_2ghz.ht_cap.ht_supported = 1;
	atbmwifi_band_2ghz.ht_cap.ampdu_factor = ATBM_IEEE80211_HT_MAX_AMPDU_32K;
	atbmwifi_band_2ghz.ht_cap.ampdu_density = ATBM_IEEE80211_HT_MPDU_DENSITY_NONE;
	//atbmwifi_band_2ghz.ht_cap.
	atbmwifi_band_2ghz.ht_cap.mcs.rx_mask[0] = 0xFF;
	atbmwifi_band_2ghz.ht_cap.mcs.rx_highest = 0;
	atbmwifi_band_2ghz.ht_cap.mcs.tx_params |= ATBM_IEEE80211_HT_MCS_TX_DEFINED;
}
/*
 * NOTE: Be very careful when changing this function, it must NOT return
 * an error on interface type changes that have been pre-checked, so most
 * checks should be in atbmwifi_ieee80211_check_concurrent_iface.
 */
FLASH_FUNC static int atbmwifi_ieee80211_open(struct atbmwifi_vif *priv)
{
	//struct atbmwifi_vif *priv = netdev_drv_priv(dev);
	wifi_printk(WIFI_ALWAYS,"atbmwifi_ieee80211_open if_id(%d)\n",priv->if_id);
	priv->enabled = 1;
	priv->iftype = ATBM_NUM_NL80211_IFTYPES;
	atbm_inital_common(priv);
	atbm_skb_queue_head_init(&priv->rx_task_skb_list);
	atbmwifi_vif_setup(priv);
	atbmwifi_setup_mac_pvif(priv);
	atbmwifi_update_filtering(priv);
	return 0;
}

FLASH_FUNC static int atbmwifi_ieee80211_stop(struct atbmwifi_vif *priv)
{
	//netif_tx_stop_all_queues(dev);
	return 0;
}

/**
 * atbmwifi_ieee80211_subif_start_xmit - netif start_xmit function for Ethernet-type
 * subinterfaces (wlan#, WDS, and VLAN interfaces)
 * @skb: packet to be sent
 * @dev: incoming interface
 *
 * Returns: 0 on success (and frees skb in this case) or 1 on failure (skb will
 * not be freed, and caller is responsible for either retrying later or freeing
 * skb).
 *
 * This function takes in an Ethernet header and encapsulates it with suitable
 * IEEE 802.11 header based on which interface the packet is coming in. The
 * encapsulated packet will then be passed to master interface, wlan#.11, for
 * transmission (through low-level driver).
 * ****NOTE: all skb need be free at low-level driver
 */
FLASH_FUNC int atbmwifi_ieee80211_subif_start_xmit(struct atbmwifi_vif *priv,struct atbm_buff *skb )
{
	//struct atbmwifi_vif *priv = netdev_drv_priv(dev);

	skb->priority = atbm_cfg80211_classify8021d(skb);
	atbmwifi_tx_start(skb,priv);
	return 0;
}

FLASH_FUNC static int atbmwifi_ieee80211_change_mac(struct atbmwifi_vif *priv, atbm_uint8 *addr)
{
	//struct atbmwifi_vif *priv = netdev_drv_priv(dev);
	//struct sockaddr *sa = addr;
	int ret = 0;

	atbm_memcpy(priv->mac_addr,addr, ATBM_ETH_ALEN);

	return ret;
}
FLASH_RDATA struct atbm_net_device_ops wifi_net_ops;
/*
FLASH_RDATA struct atbm_net_device_ops wifi_net_ops = {
	.ndo_open = atbmwifi_ieee80211_open,
	.ndo_stop = atbmwifi_ieee80211_stop,
	.ndo_start_xmit = atbmwifi_ieee80211_subif_start_xmit,
	.ndo_set_mac_address =atbmwifi_ieee80211_change_mac,
};
*/
static atbm_void net_device_ops_init(atbm_void)
{
	wifi_net_ops.ndo_open = atbmwifi_ieee80211_open;
	wifi_net_ops.ndo_stop = atbmwifi_ieee80211_stop;
	wifi_net_ops.ndo_start_xmit = atbmwifi_ieee80211_subif_start_xmit;
	wifi_net_ops.ndo_set_mac_address =atbmwifi_ieee80211_change_mac;
}


struct tcpip_opt * tcp_opt = ATBM_NULL;

FLASH_FUNC atbm_void Iwip_Init()
{
	extern struct tcpip_opt lwip_tcp_opt;
	tcp_opt =  &lwip_tcp_opt;
	//#ifndef ATBM_COMB_IF
	//tcp_opt->net_init(g_vmac->ndev);
	//#endif
}
FLASH_FUNC atbm_void  atbmwifi_netstack_init(struct atbmwifi_common *hw_priv)
{	//for compile
	atbm_skbbuffer_init();	
	/*Initial iwip net/stack*/
	Iwip_Init();
	wifi_printk(WIFI_ALWAYS,"atbmwifi_netstack_init\n");
	hmac_rc_init(hw_priv,ATBMWIFI_MAC80211_RC_DEFAULT);   //FIXME add minstel 
	/*other inital*/
	wpa_timer_init();
	///TODO;
	wifi_printk(WIFI_ALWAYS,"atbmwifi_netstack_init   END\n");
}
FLASH_FUNC atbm_void atbmwifi_netstack_deinit(atbm_void)
{
	wpa_timer_free();
}

int atbmwifi_disable_listening(struct atbmwifi_vif *priv)
{
	int ret;
	struct wsm_reset reset={0};	
	reset.reset_statistics = ATBM_TRUE;
	
#ifdef P2P_MULTIVIF
	if(priv->if_id != 2) {
		ATBM_WARN_ON_FUNC(priv->join_status > ATBMWIFI__JOIN_STATUS_MONITOR);
		return 0;
	}
#endif //change by wp
	priv->join_status = ATBMWIFI__JOIN_STATUS_PASSIVE;

	ATBM_WARN_ON_FUNC(priv->join_status > ATBMWIFI__JOIN_STATUS_MONITOR);

	//if (priv->hw_priv->roc_if_id == -1)
	//	return 0;

	ret = wsm_reset(priv->hw_priv, &reset, ATBM_WIFI_GENERIC_IF_ID);
	return ret;
}

/*Stop wifi from AP or sta mode, mainly steps
* 1, stop interface related resources
* 2, free queue and stop wifi.
*
*/


atbm_void atbmwifi_stop()
{
		struct atbmwifi_common * hw_priv;
		int i = 0;	
		struct atbmwifi_vif *priv = g_vmac;
		//ATBM_BOOL is_htcapie = ATBM_FALSE;
		//struct wsm_reset reset;
		//struct wsm_operational_mode mode;

		//reset.reset_statistics = ATBM_TRUE;			
	
		//mode.power_mode = wsm_power_mode_quiescent,
		//mode.disableMoreFlagUsage = ATBM_TRUE,
	
		hw_priv = &g_hw_prv;
		
	
		switch (priv->join_status) {
			
			case ATBMWIFI__JOIN_STATUS_STA:
				atbmwifi_stop_sta(priv);
				break;
			case ATBMWIFI__JOIN_STATUS_AP:				
				atbmwifi_stop_ap(priv);				
				break;
			case ATBMWIFI__JOIN_STATUS_MONITOR:
				atbmwifi_disable_listening(priv);
				break;
			default:
				break;
			}	
	
		/* TODO:COMBO: Change Queue Module */
		//if (!__atbm_flush(hw_priv, ATBM_FALSE, priv->if_id))
		//	wsm_unlock_tx(hw_priv);
	
	//	cancel_delayed_work_sync(&priv->bss_loss_work);
		//cancel_delayed_work_sync(&priv->connection_loss_work);
		//cancel_delayed_work_sync(&priv->link_id_gc_work);
		//cancel_delayed_work_sync(&priv->join_timeout);
		//cancel_delayed_work_sync(&priv->set_cts_work);
		//cancel_delayed_work_sync(&priv->pending_offchanneltx_work);
	
		/* TODO:COMBO: May be reset of these variables "delayed_link_loss and
		 * join_status to default can be removed as dev_priv will be freed by
		 * mac80211 */
		//priv->delayed_link_loss = 0;
		priv->join_status = ATBMWIFI__JOIN_STATUS_PASSIVE;
		wsm_unlock_tx(hw_priv);
	
		/*
		if ((priv->if_id ==1) && (priv->iftype == ATBM_NL80211_IFTYPE_AP
			|| priv->iftype == ATBM_NL80211_IFTYPE_P2P_GO)) {
			hw_priv->is_go_thru_go_neg = ATBM_FALSE;
		}*/


		//atbm_spin_lock(&hw_priv->vif_list_lock);
		//atbm_spin_lock(&priv->vif_lock);
		//hw_priv->vif_list[priv->if_id] = NULL;
		//hw_priv->if_id_slot &= (~BIT(priv->if_id));
		//atomic_dec(&hw_priv->num_vifs);
		//if (atbm_atomic_read(&hw_priv->num_vifs) == 0) {
			//atbm_free_keys(hw_priv);
		//	memset(hw_priv->mac_addr, 0, ATBM_ETH_ALEN);
		//}
		//atbm_spin_unlock(&priv->vif_lock);
		//atbm_spin_unlock(&hw_priv->vif_list_lock);
		priv->listening = ATBM_FALSE;
	
		//debugfs_remove_recursive(priv->debug->debugfs_phy);
		//atbm_debug_release_priv(priv);
	
		//atbm_tx_queues_unlock(hw_priv);
		//atbm_os_mutexUnLock(&hw_priv->conf_mutex);
	
	//	if (atbm_atomic_read(&hw_priv->num_vifs) == 0)
		//	atbm_flush_workqueue(hw_priv->workqueue);
		//memset(priv, 0, sizeof(struct atbmwifi_vif));
		//up(&hw_priv->scan.lock);
	
	for (i = 0; i < 4; i++)
		atbmwifi_queue_clear(&hw_priv->tx_queue[i], -1);  //clear all queue

	/* HACK! */
	//if (atomic_xchg(&priv->tx_lock, 1) != 1)
	//	sta_printk(KERN_DEBUG "[STA] TX is force-unlocked "
		//	"due to stop request.\n");
	
		//priv->mode = NL80211_IFTYPE_UNSPECIFIED;
		priv->listening = ATBM_FALSE;
		//priv->delayed_link_loss = 0;
	
}


/****************************************************************************/
extern struct atbmwifi_cfg hmac_cfg; 
FLASH_FUNC int Atbmwifi_halEntry(struct sbus_priv *sbus)
{ 
	int Status;
	int if_id;
	int i;
	int ret =0;
	struct atbm_net_device *ndev = ATBM_NULL;
	struct atbmwifi_vif *priv;
	struct atbmwifi_common * hw_priv;
	struct wsm_operational_mode mode={0};
	
	mode.power_mode = wsm_power_mode_active;
	mode.disableMoreFlagUsage = ATBM_TRUE;
	wifi_printk(WIFI_ALWAYS,"atbm: Atbmwifi_halEntry() <===\n");	
//	wifi_printk(WIFI_ALWAYS,"atbm: SVN Version %d\n", SVN_VERSION);
	/*Init static and global struct */
	atbmwifi_band_2ghz_init();
	net_device_ops_init();

	ndev=atbm_netintf_init();
	if (ndev==ATBM_NULL)
	{
		goto AtbmMain_ERR;
	}
	priv = (struct atbmwifi_vif *)netdev_drv_priv(ndev);
	priv->ndev = ndev;
	priv->if_id =0;
	priv->iftype = ATBM_NUM_NL80211_IFTYPES;
	g_vmac = priv;
	hw_priv = &g_hw_prv;
	atbm_memset(&g_hw_prv,0 ,sizeof(struct atbmwifi_common));
	//priv->config = &hmac_cfg;
#if ATBM_USB_BUS
	hw_priv->sbus_ops = &atbm_usb_sbus_ops;
#else	
	hw_priv->sbus_ops = &atbm_sdio_sbus_ops;
#endif
	hw_priv->sbus_priv = sbus;
	hw_priv->vif_list[priv->if_id] = priv;
	hw_priv->if_id_selected = priv->if_id;
	priv->hw_priv = hw_priv;
	sbus->core = hw_priv;
	///////////////////////hw_priv;////////
	atbm_init_task_work(hw_priv);
	atbm_inital_common(priv);
	atbm_os_mutexLockInit(&hw_priv->wsm_cmd_mux);
	atbm_os_mutexLockInit(&hw_priv->tx_lock);
	ATBM_INIT_LIST_HEAD(&hw_priv->event_queue); 
	ATBM_INIT_LIST_HEAD(&hw_priv->tx_urb_cmp); 												\
	atbm_spin_lock_init(&hw_priv->event_queue_lock); 	
	atbm_spin_lock_init(&hw_priv->tx_com_lock); 	
	atbm_spin_lock_init(&hw_priv->rx_com_lock); 	
	atbm_skb_queue_head_init(&hw_priv->rx_frame_queue);
	atbm_skb_queue_head_init(&hw_priv->rx_frame_free);
	atbm_skb_queue_head_init(&hw_priv->tx_frame_queue);
	atbm_skb_queue_head_init(&hw_priv->tx_frame_free);
	hw_priv->scan.scan_work = atbm_init_work(hw_priv, atbm_scan_work,hw_priv);
	hw_priv->scan.ap_scan_work = atbm_init_work(hw_priv, atbmwifi_ap_scan_start,hw_priv);
	hw_priv->event_work = atbm_init_work(hw_priv, atbm_wsm_event_work,hw_priv);
#if ATBM_SDIO_BUS
	atbm_os_init_waitevent(&hw_priv->wsm_synchanl_done);
	hw_priv->wsm_sync_channl=atbm_init_work(hw_priv, wsm_sync_channl_reset,hw_priv);
#endif
	priv->config.mode  =0;
	priv->config.n_pairwise_cipher  =4;

	atbm_memcpy(hw_priv->mac_addr,default_macaddr,6);
	atbm_memcpy(priv->mac_addr,default_macaddr,6);
	priv->iftype = ATBM_NL80211_IFTYPE_MONITOR;
	/*
	if(priv->config.mode){	 //ap mode
		priv->iftype = ATBM_NL80211_IFTYPE_AP;
		//atbm_memcpy(priv->mac_addr,default_macaddr,6);
		atbm_memcpy(priv->bssid,default_macaddr,6);
		atbm_memcpy(priv->config.bssid,priv->bssid,6);
	}
	else {
		//priv->iftype = ATBM_NL80211_IFTYPE_STATION;
		atbm_memcpy(hw_priv->mac_addr,default_macaddr,6);
		atbm_memcpy(priv->mac_addr,default_macaddr,6);
	}*/
	hw_priv->mcs_rates = atbm_n_rates;
	hw_priv->hw_queues=ATBM_IEEE80211_NUM_ACS;
	hw_priv->band=ATBM_IEEE80211_BAND_2GHZ;
	priv->enabled = 0;
	priv->sta_asleep_mask = 0;
	priv->buffered_set_mask = 0;
	priv->link_id_map = 0;
	priv->extra_ie= ATBM_NULL;
	priv->extra_ie_len= 0;
	hw_priv->vif_list[0] = priv;
	priv->bss.wmm_used = 1;
	priv->bss.uapsd_supported = 1;
	priv->bss.parameter_set_count=1;
	priv->bss.ht = 1;
	
	if(atbmwifi_band_2ghz.ht_cap.cap & ATBM_IEEE80211_HT_CAP_SUP_WIDTH_20_40) {				
		hw_priv->channel_type = ATBM_NL80211_CHAN_HT40PLUS;
	}
	else {
		hw_priv->channel_type = ATBM_NL80211_CHAN_HT20;
	}
	priv->bss.channel_type = ATBM_NL80211_CHAN_HT20;

	
	hw_priv->short_frame_max_tx_count  = TEST_SHORT_RETRY_NUM;
	hw_priv->long_frame_max_tx_count  = TEST_LONG_RETRY_NUM;
	hw_priv->channel_idex = TEST_CHANNEL_VALUE;
	hw_priv->basicRateSet = TEST_BASIC_RATE;

	hw_priv->beaconInterval = TEST_BEACON_INTV; 
	hw_priv->DTIMPeriod = TEST_DTIM_INTV;
	hw_priv->preambleType = TEST_SHORT_PREAMBLE;
	hw_priv->scan_ret.info = ATBM_NULL;
	hw_priv->scan_ret.len = 0;
	hw_priv->scan.scan_smartconfig = 0;

	priv->uapsd_queues=ATBM_IEEE80211_DEFAULT_UAPSD_QUEUES;
	priv->uapsd_max_sp_len=ATBM_IEEE80211_DEFAULT_MAX_SP_LEN;
	hw_priv->ba_tid_tx_mask=0x3f;
	hw_priv->ba_tid_rx_mask=0x3f;
#if ATBM_PKG_REORDER
	hw_priv->ba_tid_tx_mask=0x3f;
	hw_priv->ba_tid_rx_mask=0x3f;
	atbm_reorder_func_init(priv);
#else	
	hw_priv->ba_tid_tx_mask=0;
	hw_priv->ba_tid_rx_mask=0;
#endif

	//init wsm_cbc
	hw_priv->wsm_cbc.scan_complete = atbmwifi_scan_complete_cb;
//	hw_priv->wsm_cbc.tx_confirm = atbmwifi_tx_confirm_cb;
//	hw_priv->wsm_cbc.rx = atbmwifi_rx_cb;
	hw_priv->wsm_cbc.suspend_resume = atbm_suspend_resume;
	/*Queue init*/
	//atbm_skb_queue_head_init(&priv->connect);
	atbm_skb_queue_head_init(&priv->rx_task_skb_list);
	wsm_buf_init(&hw_priv->wsm_cmd_buf);
	atbm_spin_lock_init(&hw_priv->wsm_cmd.lock);
	atbm_os_init_waitevent(&hw_priv->wsm_startup_done);
	/*Register bh*/
	ret=atbm_register_bh(hw_priv);
	if (ret!=0){
		goto AtbmMain_ERR;
	}
	
#if ATBM_SDIO_BUS
	/*Block size set*/
	hw_priv->sbus_ops->lock(hw_priv->sbus_priv);
	ATBM_WARN_ON_FUNC(hw_priv->sbus_ops->set_block_size(hw_priv->sbus_priv,DOWNLOAD_BLOCK_SIZE));
	hw_priv->sbus_ops->unlock(hw_priv->sbus_priv);
#endif
	/*Start download fw*/
	Status=atbm_load_firmware(hw_priv);
	if (Status){
		wifi_printk(WIFI_ALWAYS,"DownLoad FwErr,Pls check\n");
		goto AtbmMain_ERR;
	}
#if ATBM_SDIO_BUS
	/*Block size set*/
	hw_priv->sbus_ops->lock(hw_priv->sbus_priv);
	ATBM_WARN_ON_FUNC(hw_priv->sbus_ops->set_block_size(hw_priv->sbus_priv,ATBM_SDIO_BLOCK_SIZE));
	hw_priv->sbus_ops->unlock(hw_priv->sbus_priv);
	
	hw_priv->init_done = 1;
	/* Register Interrupt Handler */
	ret = hw_priv->sbus_ops->irq_subscribe(hw_priv->sbus_priv,
		(sbus_irq_handler)atbm_irq_handler, hw_priv);
	if (ret < 0) {
		wifi_printk(WIFI_IF,
			"%s: can't register IRQ handler.\n", __FUNCTION__);
	}
#endif
__wait_start_up:
	
	wifi_printk(WIFI_ALWAYS,"atbm: Atbmwifi_halEntry(), wsm_startup_done.\n");
	if (atbm_os_wait_event_timeout(&hw_priv->wsm_startup_done,2*HZ) < 0) {
		if(!hw_priv->wsm_caps.firmwareReady){
			wifi_printk(WIFI_OS,"wait_event_interruptible_timeout wsm_startup_done timeout ERROR !!\n");
			goto AtbmMain_ERR;
		}
	}
	else {
		if(!hw_priv->wsm_caps.firmwareReady){
			wifi_printk(WIFI_DBG_MSG,"atbm: Atbmwifi_halEntry(), FW is not ready(%dms).\n", atbm_GetOsTimeMs());
			goto __wait_start_up;
		}
	}
	wifi_printk(WIFI_ALWAYS,"atbm: Atbmwifi_halEntry(), FW load done.\n");
	atbm_firmware_init_check(hw_priv);

	/*Queue stats init*/
	if (atbm_unlikely(atbmwifi_queue_stats_init(&hw_priv->tx_queue_stats,
			WLAN_LINK_ID_MAX,
			hw_priv))) {
		ret = -2;
		goto AtbmMain_ERR;
	}

	/*Queue init*/
	hw_priv->vif0_throttle = ATBM_WIFI_MAX_QUEUE_SZ;
	for (i = 0; i < 4; ++i) {
		if (atbm_unlikely(atbmwifi_queue_init(&hw_priv->tx_queue[i],
				&hw_priv->tx_queue_stats, i, ATBM_WIFI_MAX_QUEUE_SZ))) { 
			ret = -3;
			goto AtbmMain_ERR;
		}
	}

	for (if_id = 0; if_id < _atbmwifi_get_nr_hw_ifaces(hw_priv); if_id++) { 
		wsm_set_operational_mode(hw_priv, &mode, if_id);
		/* Enable multi-TX confirmation */
		wsm_use_multi_tx_conf(hw_priv, ATBM_TRUE, if_id);
	}

	/*get mac addr from efuse*/
	atbm_get_mac_address(hw_priv);
	atbm_memcpy(priv->mac_addr,hw_priv->mac_addr,6);

	{
		struct efuse_headr efuse_data;
		if (wsm_get_efuse_data(hw_priv, (atbm_void *)&efuse_data, sizeof(efuse_data))) {
			wifi_printk(WIFI_ALWAYS,"wsm_get_efuse_data error\n");
		}
		else {
			wifi_printk(WIFI_ALWAYS,"efuse data is [0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x,0x%x:0x%x:0x%x:0x%x:0x%x:0x%x]\n",
					efuse_data.version,efuse_data.dcxo_trim,efuse_data.delta_gain1,efuse_data.delta_gain2,efuse_data.delta_gain3,
					efuse_data.Tj_room,efuse_data.topref_ctrl_bias_res_trim,efuse_data.PowerSupplySel,efuse_data.mac[0],efuse_data.mac[1],
					efuse_data.mac[2],efuse_data.mac[3],efuse_data.mac[4],efuse_data.mac[5]);
		}
	}
	atbm_register_netdevice(priv->ndev);
	wifi_printk(WIFI_ALWAYS,"mac_addr:"MACSTR"\n",MAC2STR(priv->mac_addr));
	/*Other initial*/
	atbm_wifi_ticks_timer_init();
	atbmwifi_setup_mac(hw_priv);
	atbmwifi_vif_setup(priv);
//	atbmwifi_setup_mac_pvif(priv);
	atbmwifi_update_filtering(priv);
	atbmwifi_ieee80211_channel_country(hw_priv,country_chinese);
	/*mac80211 stack control & initial*/
	atbmwifi_netstack_init(hw_priv);
	/*It's Indicate wifiRdy*/
	AtbmwifiRdy=1;
	/*start*/
	if(priv->config.mode){
		//atbmwifi_start_ap(priv);
	}
	else {		
		//atbmwifi_start_sta(priv);
	}
	/*Open Lmac log*/
	//atbmwifi_enable_lmaclog(1);

AtbmMain_ERR:
	//atbmwifi_thread_exit();
	///TODO  
	wifi_printk(WIFI_ALWAYS,"atbm: Atbmwifi_halEntry() <===\n");

	return ret;
}
