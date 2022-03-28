
#include "atbm_hal.h"

#ifdef CONFIG_WPS
#include "wpa_supplicant_i.h"
#include "includes.h"
#endif

static int atbmwifi_rx_authen(struct atbmwifi_vif *priv,struct atbm_buff *skb);

atbm_void atbmwifi_rx_actionFrame(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{	
	struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *) ATBM_OS_SKB_DATA(skb);
	atbm_uint8 *tmp_ie;
	struct atbmwifi_ieee80211_channel_sw_packed_ie sw_packed_ie;
	sw_packed_ie.chan_sw_ie = ATBM_NULL;
	sw_packed_ie.ex_chan_sw_ie = ATBM_NULL;
	sw_packed_ie.sec_chan_offs_ie = ATBM_NULL;
	switch (mgmt->u.action.category) {
	case ATBM_WLAN_CATEGORY_SPECTRUM_MGMT:
		// add 8.5.2.6 Channel Switch Announcement frame format
		if(ATBM_WLAN_ACTION_SPCT_CHL_SWITCH == mgmt->u.action.u.chan_switch.action_code)
		{
			sw_packed_ie.chan_sw_ie = &mgmt->u.action.u.chan_switch.sw_elem;
			tmp_ie = ((atbm_uint8 *)sw_packed_ie.chan_sw_ie) + 3;

			if((tmp_ie[0] == ATBM_WLAN_EID_SECONDARY_CH_OFFSET)&&(tmp_ie[1]==1))
			{
				sw_packed_ie.sec_chan_offs_ie = (struct atbmwifi_ieee80211_sec_chan_offs_ie *)(tmp_ie+2);
			}
			atbm_ieee80211_sta_process_chanswitch(priv,&priv->bss,&sw_packed_ie,0);
		}
		break;
	case ATBM_WLAN_CATEGORY_PUBLIC:
		//add 8.5.8.7 Extended Channel Switch Announcement frame format
		if(ATBM_WLAN_PUB_ACTION_EX_CHL_SW_ANNOUNCE == mgmt->u.action.u.ext_chan_switch.action_code)
		{
			sw_packed_ie.ex_chan_sw_ie = &mgmt->u.action.u.ext_chan_switch.ext_sw_elem;
	
			atbm_ieee80211_sta_process_chanswitch(priv,&priv->bss,&sw_packed_ie,0);
			break;
		}
#ifdef CONFIG_P2P
	case ATBM_WLAN_CATEGORY_VENDOR_SPECIFIC:
		{
			struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *)ATBM_OS_SKB_DATA(skb);
			struct atbmwifi_ieee80211_rx_status *hw_hdr = ATBM_IEEE80211_SKB_RXCB(skb);
			atbm_uint8 *data = (atbm_uint8 *)ATBM_OS_SKB_DATA(skb) + offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_req.variable) + 1;
			int len = ATBM_OS_SKB_LEN(skb) - offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_req.variable) - 1;
			atbm_p2p_rx_action(priv, mgmt->da, mgmt->sa, mgmt->bssid,
				mgmt->u.action.category, data, len, hw_hdr->freq);
		}
#endif
		break;
	case ATBM_WLAN_CATEGORY_HT:
		{
			//add 8.5.12.2 Notify Channel Width frame format
			if(ATBM_WLAN_HT_ACTION_NOTIFY_CHANWIDTH == mgmt->u.action.u.notify_chan_width.action_code)
			{
				atbm_uint8 prev_lock = priv->bss.ht_40M;
				atbm_uint8 new_lock  = 0;
				if(mgmt->u.action.u.notify_chan_width.chan_width)
				{
					/*
					*if not surport ht40, we should not receive this frame.
					*/
					if(priv->bss.channel_type<=ATBM_NL80211_CHAN_HT20){
						wifi_printk(WIFI_DBG_ERROR, "%s:in 20M mode,we can not recive this frame,what happend",__func__); 
						priv->bss.ht_40M=0;
					}
				}
				else
				{
					if(priv->bss.channel_type>=ATBM_NL80211_CHAN_HT40MINUS){
						priv->bss.ht_40M=1;
					}
				}
				new_lock =priv->bss.ht_40M;
				
				if(prev_lock^new_lock)
				{					
					atbm_queue_work(priv->hw_priv,priv->chantype_switch_work);
				}	
			}
		}
		break;	
	default:
		break;
	}
}

/*
is ssid in the scan result(hw_priv->scan_ret.info),
if in return  0;
not return  1;
*/
ATBM_BOOL atbmwifi_rx_scan_is_valid(struct atbmwifi_common *hw_priv,atbm_uint8 * ie)
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
FLASH_FUNC atbm_void atbmwifi_ap_rx_probe_resp(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	atbm_uint8 * data = (atbm_uint8 *)ATBM_OS_SKB_DATA(skb)+offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_resp.variable);
	int len = ATBM_OS_SKB_LEN(skb)-offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_resp.variable);
	struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *) ATBM_OS_SKB_DATA(skb);
	atbm_uint8 *ie ;
//	ATBM_BOOL privacy = 0;
	struct atbmwifi_ieee802_11_elems * pelems;
	struct atbmwifi_ieee80211_rx_status *hwhdr = ATBM_IEEE80211_SKB_RXCB(skb);
	int ret = -1;
	pelems = atbm_kmalloc(sizeof(struct atbmwifi_ieee802_11_elems),GFP_KERNEL);

	if(pelems==ATBM_NULL){
		ret = -101;
		goto __error; 
	}
	ie = cfg80211_find_ie(ATBM_WLAN_EID_SSID,data,len);	
	if(ie==ATBM_NULL){
		ret = -100;
		goto __error; 
	}
	if(hw_priv->ApScan_in_process){
		if((hw_priv->scan_ret.info)
			&&(priv->scan_no_connect)
			&&(hw_priv->scan_ret.len < MAX_SCAN_INFO_NUM)){
			if(atbmwifi_rx_scan_is_valid(hw_priv,ie)){					
				struct atbmwifi_scan_result_info *info = hw_priv->scan_ret.info + hw_priv->scan_ret.len;
				atbm_ieee802_11_parse_elems(data,len,pelems);
				atbm_memcpy(info->ssid ,pelems->ssid,pelems->ssid_len);
				atbm_memcpy(info->BSSID,mgmt->bssid,6);
				info->ssid[pelems->ssid_len] = 0;
				info->ssidlen = pelems->ssid_len;
				info->channel = pelems->ds_params[0];
				if(pelems->tim)
					info->dtim_period = pelems->tim->dtim_period;
				info->beacon_interval = mgmt->u.probe_resp.beacon_int;
				info->capability  = mgmt->u.probe_resp.capab_info;
				info->ht = pelems->ht_cap_elem?1:(pelems->ht_info_elem?1:0);
				info->wpa= pelems->wpa ?1:0;
				info->rsn= pelems->rsn?1:0;
				info->encrypt = (mgmt->u.probe_resp.capab_info& ATBM_WLAN_CAPABILITY_PRIVACY)?1:0;
				info->rssi = hwhdr->signal;
				//info->b40M= ?1:0;
				hw_priv->scan_ret.len++;
				if(hw_priv->scan_ret.len==1){
					wifi_printk(WIFI_ALWAYS,"scan_no_connect: %d\n",priv->scan_no_connect);
				}
				wifi_printk(WIFI_ALWAYS,"SSID: %s\n",info->ssid);
				wifi_printk(WIFI_ALWAYS,"	channel %d\n",info->channel);
				wifi_printk(WIFI_ALWAYS,"	ht[%d] wpa[%d] rsn[%d] enc[%d]\n",info->ht,info->wpa,info->rsn,info->encrypt);
			}
		}
	}
	atbm_kfree(pelems);
	return;
__error:
	wifi_printk(WIFI_DBG_MSG,"%s++ ret %d\n",__FUNCTION__,ret);
	atbm_kfree(pelems);
	return;
}

FLASH_FUNC atbm_int8 atbmwifi_get_security_mode(atbm_int32 protect, struct atbmwifi_ieee802_11_elems *elems){
//	struct atbmwifi_wpa_ie_data ie;

	if(!protect){
		return ATBM_KEY_NONE;
	}
	if(elems->wpa){
		if(elems->rsn){
			return ATBM_KEY_MIX;
		}
		return ATBM_KEY_WPA;
	}
	if(elems->rsn){
		return ATBM_KEY_WPA2;
	}
	return ATBM_KEY_WEP;
}

FLASH_FUNC atbm_void atbmwifi_rx_probe_resp(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	atbm_uint8 * data = (atbm_uint8 *)ATBM_OS_SKB_DATA(skb)+offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_resp.variable);
	int len = ATBM_OS_SKB_LEN(skb)-offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_resp.variable);
	struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *) ATBM_OS_SKB_DATA(skb);
#ifdef CONFIG_WPS
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)priv->appdata;
	struct wps_parse_attr *attr = ATBM_NULL;
#endif
	atbm_uint8 *ie ;
	ATBM_BOOL privacy = 0;
	struct atbmwifi_ieee802_11_elems * pelems;
	struct atbmwifi_ieee80211_rx_status *hwhdr = ATBM_IEEE80211_SKB_RXCB(skb);
	int ret = -1;
	char debug_ie[ATBM_IEEE80211_MAX_SSID_LEN];
	//int  i =0,j;
	
	pelems = atbm_kmalloc(sizeof(struct atbmwifi_ieee802_11_elems),GFP_KERNEL);

	if(pelems==ATBM_NULL){
		ret = -101;
		goto __error; 
	}
	ie = cfg80211_find_ie(ATBM_WLAN_EID_SSID,data,len);	
	if(ie==ATBM_NULL){
		ret = -100;
		goto __error; 
	}
	if(ie[1] <= ATBM_IEEE80211_MAX_SSID_LEN){
		atbm_memcpy(debug_ie,&ie[2],ie[1]);
		debug_ie[ie[1]] = 0;
		//iot_printf("rx_probe_resp ssid(%s)\n",debug_ie);
	}
	else {
		//iot_printf("rx_probe_resp ssid err\n");
	}
	 //in scan process we get scan info
	 //in no scan process we check info
	 if(hw_priv->scan.in_progress||hw_priv->ApScan_in_process){
#ifdef CONFIG_P2P
		if(priv->p2p_scan){
			atbm_p2p_prash_ie(priv, mgmt->bssid, hwhdr->freq, hwhdr->signal, data, len);
		}else
#endif
#ifdef CONFIG_WPS
		if(wpa_s->wps_mode != WPS_MODE_UNKNOWN){
			attr = (struct wps_parse_attr *)atbm_kmalloc(sizeof(*attr),GFP_KERNEL);
			if(attr == ATBM_NULL){
				ret = -200;
				goto __error;
			}
			atbm_ieee802_11_parse_elems(data, len, pelems);
			if(wps_parse_msg_attr(pelems->wps_ie, pelems->wps_ie_len, attr)){
				wifi_printk(WIFI_DBG_ERROR, "wps parse failed.\n");
			}

#ifdef CONFIG_P2P
			if(priv->p2p_join){
				if(priv->ssid_length != pelems->ssid_len ||
					atbm_memcmp(priv->ssid, pelems->ssid, priv->ssid_length)){
					ret = -200;
					goto __error;
				}
			}
#endif
			if(check_valid_wps_ap(priv, attr, wpa_s->own_addr)){
//			if((attr->selected_registrar) &&
//				(*(attr->selected_registrar) == 1) &&
//				(attr->primary_dev_type != ATBM_NULL)){

				priv->bss.capability = mgmt->u.probe_resp.capab_info;
				priv->bss.beacon_interval = mgmt->u.probe_resp.beacon_int;
				if(pelems->tim){
					priv->bss.dtim_period = pelems->tim->dtim_period;
				}else{
					priv->bss.dtim_period = 0;
				}
				if(pelems->erp_info){
					priv->bss.short_preamble = (pelems->erp_info[0] & ATBM_WLAN_ERP_BARKER_PREAMBLE) == 0;
				}
				priv->bss.wpa = (pelems->rsn_len || pelems->wpa_len) ? 1 : 0;
				priv->bss.ht = (pelems->ht_info_elem || pelems->ht_cap_elem) ? 1 : 0;
				priv->bss.rate.ht = priv->bss.ht;
				if(pelems->ht_cap_elem){
					atbmwifi_ieee80211_ht_cap_ie_to_sta_ht_cap(&atbmwifi_band_2ghz, pelems->ht_cap_elem, &priv->bss.rate.ht_cap);
				}
				atbmwifi_ieee80211_get_sta_rateinfo(&priv->bss.rate, pelems->supp_rates, pelems->supp_rates_len);
				atbmwifi_ieee80211_get_sta_rateinfo(&priv->bss.rate, pelems->ext_supp_rates, pelems->ext_supp_rates_len);
				wifi_printk(WIFI_WPS, "priv->bss.rate support_rates(%x) %x \n", priv->bss.rate.support_rates, priv->bss.rate.basic_rates);
				wifi_printk(WIFI_WPS, "probe_resp wpa_len(%d), wpa(%d) \n", pelems->wpa_len, priv->bss.wpa);
				//free the element ie
				if(priv->bss.information_elements && 
					(priv->bss.len_information_elements < len)){
					atbm_kfree(priv->bss.information_elements);
					priv->bss.information_elements = ATBM_NULL;
				}
				if(priv->bss.information_elements == ATBM_NULL){
					priv->bss.information_elements = atbm_kmalloc(len, GFP_KERNEL);
					if(priv->bss.information_elements == ATBM_NULL){
						ret = -205;
						goto __error;
					}
				}
				atbm_memcpy(priv->bss.information_elements, data, len);
				priv->bss.len_information_elements = len;
				if((atbm_memcmp(priv->bssid, mgmt->bssid, ATBM_ETH_ALEN) != 0)
					|| (wpa_s->wps_ap_cnt == 0)){
					wpa_s->wps_ap_cnt++;
				}
				atbm_memcpy(priv->daddr, mgmt->bssid, 6);
				atbm_memcpy(priv->bssid, mgmt->bssid, 6);
				atbm_memcpy(priv->ssid, pelems->ssid, pelems->ssid_len);
				priv->ssid[pelems->ssid_len] = '\0';
				priv->ssid_length = pelems->ssid_len;
				atbm_memcpy(priv->config.ssid, pelems->ssid, pelems->ssid_len);
				priv->config.ssid_len = pelems->ssid_len;

				hw_priv->scan.status = 1;
				wifi_printk(WIFI_WPS, "Found wps AP ssid=%s "MACSTR"<===\n", (char*)priv->ssid, MAC2STR(priv->bssid));
			}
			if(attr != ATBM_NULL){
				atbm_kfree(attr);
			}
		}
#endif
		if((hw_priv->scan_ret.info)
			&&(priv->scan_no_connect)
			&&(hw_priv->scan_ret.len < MAX_SCAN_INFO_NUM)){
			if(atbmwifi_rx_scan_is_valid(hw_priv,ie)){					
				struct atbmwifi_scan_result_info *info = hw_priv->scan_ret.info + hw_priv->scan_ret.len;
				atbm_ieee802_11_parse_elems(data,len,pelems);
				atbm_memcpy(info->ssid ,pelems->ssid,pelems->ssid_len);
				atbm_memcpy(info->BSSID,mgmt->bssid,6);
				info->ssid[pelems->ssid_len] = 0;
				info->ssidlen = pelems->ssid_len;
				info->channel = pelems->ds_params[0];
				if(pelems->tim)
					info->dtim_period = pelems->tim->dtim_period;
				info->beacon_interval = mgmt->u.probe_resp.beacon_int;
				info->capability  = mgmt->u.probe_resp.capab_info;
				info->ht = pelems->ht_cap_elem?1:(pelems->ht_info_elem?1:0);
				info->wpa= pelems->wpa ?1:0;
				info->rsn= pelems->rsn?1:0;
				info->encrypt = (mgmt->u.probe_resp.capab_info& ATBM_WLAN_CAPABILITY_PRIVACY)?1:0;
				info->rssi = hwhdr->signal;
				info->security = atbmwifi_get_security_mode(info->encrypt, pelems);
				//info->b40M= ?1:0;
				hw_priv->scan_ret.len++;
				if(hw_priv->scan_ret.len==1){
					wifi_printk(WIFI_ALWAYS,"scan_no_connect: %d\n",priv->scan_no_connect);
				}
				wifi_printk(WIFI_ALWAYS,"SSID: %s\n",info->ssid);
				wifi_printk(WIFI_ALWAYS,"	channel %d\n",info->channel);
				wifi_printk(WIFI_ALWAYS,"	ht[%d] wpa[%d] rsn[%d] enc[%d] security[%d]\n",info->ht,info->wpa,info->rsn,info->encrypt,info->security);
			}
		}

		if(!priv->scan_no_connect
			&&(priv->ssid_length != 0)
			&&(ie[1] == priv->ssid_length)
			&&(atbm_memcmp(&ie[2],priv->ssid,priv->ssid_length)==0)){	
//			struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
			ret = 0;
			
			atbm_ieee802_11_parse_elems(data,len,pelems);
			atbm_memcpy(priv->daddr,mgmt->bssid,6);
		    atbm_memcpy(priv->bssid,mgmt->bssid,6);
			priv->bss.capability =  mgmt->u.probe_resp.capab_info;
			privacy = !!(priv->bss.capability & ATBM_WLAN_CAPABILITY_PRIVACY);
			#ifdef STA_KEY_TYPE_SET
			if(privacy != config->privacy){
				ret = -2;
				wifi_printk(WIFI_ALWAYS,"privacy miss:\n");
				goto __error;
			}
			if(((config->wpa == ATBM_WPA_PROTO_RSN) ||(config->wpa == ATBM_WPA_PROTO_WPA))
				&&(pelems->rsn_len + pelems->wpa_len ==0)){
				ret = -3;
				wifi_printk(WIFI_DBG_ERROR,"%s key_mgmt %d,rsn_len %d,wpa_len %d\n",__FUNCTION__,config->wpa,pelems->rsn_len
					,pelems->wpa_len);
				goto __error;
			}
			#endif
			priv->bss.beacon_interval =  mgmt->u.probe_resp.beacon_int;
			//ie = cfg80211_find_ie(ATBM_WLAN_EID_DS_PARAMS,data,len);
				
			if( pelems->ds_params==ATBM_NULL){
				ret = -4;
				wifi_printk(WIFI_ALWAYS,"ds_params miss:\n");
				goto __error;
			}
			priv->bss.channel_num =  pelems->ds_params[0];
			atbm_memcpy(priv->bss.bssid, mgmt->bssid,6);
			if(pelems->tim)
				priv->bss.dtim_period = pelems->tim->dtim_period;
			else
				priv->bss.dtim_period = 0;
			if(pelems->erp_info)
				priv->bss.short_preamble = (pelems->erp_info[0]& ATBM_WLAN_ERP_BARKER_PREAMBLE) == 0;
			
			priv->bss.rssi = hwhdr->signal;
			/*		
			if (erp_valid) {
				use_protection = (erp & WLAN_ERP_USE_PROTECTION) != 0;
				use_short_preamble = (erp & ATBM_WLAN_ERP_BARKER_PREAMBLE) == 0;
			} else {
				use_protection = ATBM_FALSE;
				use_short_preamble = !!(capab & ATBM_WLAN_CAPABILITY_SHORT_PREAMBLE);
			}
			*/
			priv->bss.wpa = !!(pelems->rsn_len || pelems->wpa_len);
#ifdef CONFIG_WPS
			priv->bss.wps = pelems->wps_ie_len != 0;
#endif
			priv->bss.privacy = privacy;
			//priv->bss.wps = pelems->wps_ie_len ? 1:0;
			//priv->bss.p2p = pelems->p2p_ie_len ? 1:0;
			//priv->bss.bcm_ap = elems->bcm_ie_len ? 1:0;	
			priv->bss.ht =  (pelems->ht_info_elem || pelems->ht_cap_elem)? 1:0;
			priv->bss.rate.ht = priv->bss.ht;
			if(pelems->ht_cap_elem){
				atbmwifi_ieee80211_ht_cap_ie_to_sta_ht_cap(&atbmwifi_band_2ghz,
							 	 pelems->ht_cap_elem,
							  	&priv->bss.rate.ht_cap);
			}
			
			atbmwifi_ieee80211_get_sta_rateinfo(&priv->bss.rate,pelems->supp_rates, pelems->supp_rates_len);
			atbmwifi_ieee80211_get_sta_rateinfo(&priv->bss.rate,pelems->ext_supp_rates, pelems->ext_supp_rates_len);

			//wifi_printk(WIFI_SCAN,"probe_resp wpa_len(%d),wpa(%d) \n",pelems->wpa_len,priv->bss.wpa);
			//free the element ie
			if(priv->bss.information_elements &&
				(priv->bss.len_information_elements < len)){
				atbm_kfree(priv->bss.information_elements);
				priv->bss.information_elements = ATBM_NULL;
			}
			
			if(priv->bss.information_elements == ATBM_NULL){
				priv->bss.information_elements = atbm_kmalloc(len,GFP_KERNEL);
				if(priv->bss.information_elements==ATBM_NULL)
				{
					ret = -5;

					wifi_printk(WIFI_ALWAYS,"information_elements miss:\n");
					goto __error;
				}
			}
			atbm_memcpy(priv->bss.information_elements,data,len);
			priv->bss.len_information_elements =  len;
			
			
			hw_priv->scan.status = ATBMWIFI_SCAN_CONNECT_AP_SUCCESS;	
			
			wifi_printk(WIFI_ALWAYS,"[atbm_wifi] connect AP have been Scanned\n");
			//wifi_printk(WIFI_RATE,"support_rates %x,basic_rates %x\n",priv->bss.support_rates,priv->bss.basic_rates);		
		
		}
	
	}
	 else {
	 	//TODO add to check beacon info code,if ap beacon info change we need disconnect it
	 }
	 atbm_kfree(pelems);
	return;
__error:
#ifdef CONFIG_WPS
	if(attr != ATBM_NULL)
		atbm_kfree(attr);
#endif
	wifi_printk(WIFI_DBG_MSG,"%s++ ret %d\n",__FUNCTION__,ret);
	
	atbm_kfree(pelems);
	return;
}
FLASH_FUNC atbm_void atbmwifi_switch_channletpye(struct atbmwifi_vif *priv,struct atbmwifi_ieee802_11_elems *elems)
{
	struct atbmwifi_ieee80211_channel_sw_packed_ie sw_packed_ie;
	if(elems->ch_switch_elem)
	{
		sw_packed_ie.chan_sw_ie = (struct atbmwifi_ieee80211_channel_sw_ie *)elems->ch_switch_elem;
		atbm_ieee80211_sta_process_chanswitch(priv,
								&priv->bss,
								&sw_packed_ie,
								0);
	}
	if(elems->secondary_ch_elem){
		sw_packed_ie.sec_chan_offs_ie= (struct atbmwifi_ieee80211_sec_chan_offs_ie *)elems->secondary_ch_elem;
		atbm_ieee80211_sta_process_chanswitch(priv,
								&priv->bss,
								&sw_packed_ie,
								0);
	}
	if(elems->extended_ch_switch_elem)
	{
		sw_packed_ie.ex_chan_sw_ie= (struct atbmwifi_ieee80211_ext_chansw_ie *)elems->extended_ch_switch_elem;
		atbm_ieee80211_sta_process_chanswitch(priv,
								&priv->bss,
								&sw_packed_ie,
								0);
	
	}

}

FLASH_FUNC atbm_void atbmwifi_rx_beacon(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{
//	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	struct atbmwifi_ieee802_11_elems elems;
	int erp_valid =ATBM_FALSE;
	atbm_uint8 erp_value = 0;
	int  baselen;
	int changed = 0;
	int len = ATBM_OS_SKB_LEN(skb)-offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_resp.variable);
	struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *) ATBM_OS_SKB_DATA(skb);
	/* Process beacon from the current BSS */
	baselen = (atbm_uint8 *) mgmt->u.beacon.variable - (atbm_uint8 *) mgmt;
	if(priv->assoc_ok ==0){
		return ;
	}else{
		atbm_ieee802_11_parse_elems(mgmt->u.beacon.variable, len - baselen, &elems);
		/*parse 40M ies*/
		atbmwifi_switch_channletpye(priv,&elems);
		/*parse wmm param*/
		if (elems.wmm_param){
			atbmwifi_ieee80211_sta_wmm_params(priv,elems.wmm_param,elems.wmm_param_len);
		}
		/*parse ps mode */
		//
		if (elems.erp_info && elems.erp_info_len >= 1) {
			erp_valid = ATBM_TRUE;
			erp_value = elems.erp_info[0];
		} else {
			erp_valid = ATBM_FALSE;
		}
		changed |= atbm_ieee80211_handle_bss_capability(priv,atbm_le16_to_cpu(mgmt->u.beacon.capab_info),erp_valid, erp_value);
		if (elems.ht_cap_elem && elems.ht_info_elem && elems.wmm_param &&
		    !(config->flags & ATBM_IEEE80211_STA_DISABLE_11N)) {
			struct atbmwifi_ieee80211_supported_band *sband;
			atbm_uint16 ap_ht_cap_flags;
			sband = &atbmwifi_band_2ghz;

			atbmwifi_ieee80211_ht_cap_ie_to_sta_ht_cap(sband,
					elems.ht_cap_elem, &priv->bss.rate.ht_cap);

			ap_ht_cap_flags = priv->bss.rate.ht_cap.cap;

			changed |= atbmwifi_ieee80211_enable_ht(elems.ht_info_elem,
						       priv, ap_ht_cap_flags, ATBM_TRUE);
		}
		/* Note: country IE parsing is done for us by cfg80211 */
		if (elems.country_elem) {
			///TODO;;
		}
		atbmwifi_ieee80211_bss_info_change_notify(priv, changed);
	}
	return;
}
FLASH_FUNC atbm_void atbmwifi_rx_sta_mgmtframe(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{	
	struct atbmwifi_ieee80211_hdr * hdr = (struct atbmwifi_ieee80211_hdr *) ATBM_OS_SKB_DATA(skb);
	atbm_uint16 stype = hdr->frame_control & atbm_cpu_to_le16(ATBM_IEEE80211_FCTL_STYPE);	
	int ret= 0;
	wifi_printk(WIFI_DBG_MSG,"atbmwifi_rx_sta_mgmtframe++ stype %x\n",stype);
     switch(stype){
	 	case ATBM_IEEE80211_STYPE_BEACON:
//			atbmwifi_rx_beacon(priv,skb);
		case ATBM_IEEE80211_STYPE_PROBE_RESP:
			atbmwifi_rx_probe_resp(priv,skb);
			break;
		case ATBM_IEEE80211_STYPE_AUTH:
			{
				int res;
				res = atbmwifi_rx_authen(priv,skb);
				if(res == ATBM_WLAN_STATUS_SUCCESS_NEXTSETP){
					//send assoc req
					atbmwifi_event_uplayer(priv,ATBM_WIFI_AUTH_EVENT,(atbm_uint8*)0);
				}
				else if(res>0)
				{
					wifi_printk(WIFI_CONNECT,"[sta]:rx_sta_mgm AUTH fail just DEAUTH\n");
					atbmwifi_event_uplayer(priv,ATBM_WIFI_DEAUTH_EVENT,(atbm_uint8*)&res);
				}
				else {
					//drop
				}
			}
			break;
		case ATBM_IEEE80211_STYPE_ASSOC_RESP:
		case ATBM_IEEE80211_STYPE_REASSOC_RESP:
			ret= atbmwifi_rx_assoc_rsp(priv,skb);
			if(!ret)
			{
				atbmwifi_assoc_success(priv,skb);
			}
			else
			{
				priv->assoc_ok = 0;
				priv->connect_ok = 0;
				if(priv->scan_expire < 60){
					priv->scan_expire++;
				}
				atbmwifi_event_uplayer(priv,ATBM_WIFI_DEASSOC_EVENT,0);
			}			
			break;
		case ATBM_IEEE80211_STYPE_DEAUTH:
		case ATBM_IEEE80211_STYPE_DISASSOC:
			if(priv->assoc_ok || priv->join_status == ATBMWIFI__JOIN_STATUS_STA){
				wifi_printk(WIFI_CONNECT,"[sta]:rx_sta_mgm DEAUTH\n");
				wifi_printk(WIFI_ALWAYS,"atbmwifi_rx_sta_mgmtframe() ---deauth\n");
#if FAST_CONNECT_MODE
				if(priv->fast_channel){
					priv->fast_connect = 1;
				}
#endif
#if FAST_CONNECT_NO_SCAN
				if(priv->auth_retry && !priv->assoc_ok){
					priv->auth_retry = 0;
					atbmwifi_wpa_event_queue((atbm_void*)priv,ATBM_NULL,ATBM_NULL,WPA_EVENT__SUPPLICANT_AUTHEN,ATBM_WPA_EVENT_NOACK);
					break;
				}
#endif
				sta_deauth(priv);
			}
			atbmwifi_event_uplayer(priv,ATBM_WIFI_DEAUTH_EVENT,0);
			break;
#ifdef CONFIG_P2P
		case ATBM_IEEE80211_STYPE_PROBE_REQ:
			{
				struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *)ATBM_OS_SKB_DATA(skb);
				struct atbmwifi_ieee80211_rx_status *hw_hdr = ATBM_IEEE80211_SKB_RXCB(skb);
				atbm_uint8 *data = (atbm_uint8 *)ATBM_OS_SKB_DATA(skb) + offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_req.variable);
				int len = ATBM_OS_SKB_LEN(skb) - offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_req.variable);
				atbm_p2p_probe_req_rx(priv, mgmt->sa, mgmt->da, mgmt->bssid,
					data, len, hw_hdr->freq, (int)hw_hdr->signal);
			}
			break;
		case ATBM_IEEE80211_STYPE_ACTION:
			{
				struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *)ATBM_OS_SKB_DATA(skb);
				struct atbmwifi_ieee80211_rx_status *hw_hdr = ATBM_IEEE80211_SKB_RXCB(skb);
				atbm_uint8 *data = (atbm_uint8 *)ATBM_OS_SKB_DATA(skb) + offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_req.variable) + 1;
				int len = ATBM_OS_SKB_LEN(skb) - offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_req.variable) - 1;
				atbm_p2p_rx_action(priv, mgmt->da, mgmt->sa, mgmt->bssid,
					mgmt->u.action.category, data, len, hw_hdr->freq);
			}
			break;
#endif
		default:
			break;
	}
}

FLASH_FUNC static int atbmwifi_rx_authen(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{
	atbm_uint16 auth_alg, auth_transaction, status_code=-1;
//	atbm_uint16 fc; 
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
//	atbm_uint8 * data = (atbm_uint8 *)OS_SKB_DATA(skb)+offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_resp.variable);
	int len = ATBM_OS_SKB_LEN(skb)-offsetof(struct atbmwifi_ieee80211_mgmt, u.auth.variable);
	struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *) ATBM_OS_SKB_DATA(skb);
//	atbm_uint16 resp = ATBM_WLAN_STATUS_SUCCESS;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	atbm_uint8 *resp_ies = ATBM_NULL;
	atbm_size_t resp_ies_len = 0;
	struct atbm_buff *skb_tx = ATBM_NULL;

	auth_alg = mgmt->u.auth.auth_alg;
	auth_transaction = mgmt->u.auth.auth_transaction;
	status_code = mgmt->u.auth.status_code;
//	fc = mgmt->frame_control;

	if(status_code != ATBM_WLAN_STATUS_SUCCESS)
	{
		return 	status_code;
	}
	if(auth_alg != config->auth_alg)
	{
		return 	ATBM_WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG;
	}

	if(auth_alg == ATBM_WLAN_AUTH_OPEN)
	{
		return ATBM_WLAN_STATUS_SUCCESS_NEXTSETP;
	}
	else if((auth_alg == ATBM_WLAN_AUTH_SHARED_KEY))
	{
		switch(auth_transaction)
		{
			case 1:
				return -2;
			case 2:
			//if(priv->connect_state != WAIT_AUTH_4)
			{
				wifi_printk(WIFI_DBG_MSG,"atbmwifi_rx_sta_mgmtframe++:authen len(%d) \n",len);
				if ((len >= 2 + ATBM_WLAN_AUTH_CHALLENGE_LEN) &&
	    		(mgmt->u.auth.variable[0] == ATBM_WLAN_EID_CHALLENGE) &&
	    		(mgmt->u.auth.variable[1] == ATBM_WLAN_AUTH_CHALLENGE_LEN))
				{
					resp_ies = atbm_kmalloc(2 + ATBM_WLAN_AUTH_CHALLENGE_LEN,GFP_KERNEL);

					if(resp_ies == ATBM_NULL)
					{
						status_code = ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
						
						return status_code;
					}
					resp_ies[0] = ATBM_WLAN_EID_CHALLENGE;
					resp_ies[1] = ATBM_WLAN_AUTH_CHALLENGE_LEN;
					atbm_memcpy(resp_ies + 2, &mgmt->u.auth.variable[2],
						  ATBM_WLAN_AUTH_CHALLENGE_LEN);
					resp_ies_len = 2 + ATBM_WLAN_AUTH_CHALLENGE_LEN;
					wifi_printk(WIFI_DBG_MSG,"atbmwifi_rx_sta_mgmtframe++:challenge \n");
					priv->connect_state = WAIT_AUTH_4;
				}
				
				break;
			}
			case 4:
				if(priv->connect_state == WAIT_AUTH_4)
					return ATBM_WLAN_STATUS_SUCCESS_NEXTSETP;
				else 
					return ATBM_WLAN_STATUS_JUST_DROP;
					
		}
	}
	else {
		return ATBM_WLAN_STATUS_JUST_DROP;
	}
	if(priv->extra_ie){
		//priv->extra_ie = NULL;
		//priv->extra_ie_len = 0;
		atbm_kfree(priv->extra_ie );
	}
	priv->extra_ie = resp_ies;
	priv->extra_ie_len = resp_ies_len;
	skb_tx = atbmwifi_ieee80211_send_auth(priv,auth_transaction+1,auth_alg,mgmt->sa,priv->bssid,0);
	atbmwifi_tx(hw_priv,skb_tx,priv);
	priv->extra_ie = ATBM_NULL;
	priv->extra_ie_len = 0;

	atbm_kfree(resp_ies);
	return status_code;
	
}

FLASH_FUNC int atbmwifi_ieee80211_build_preq_ies(struct atbmwifi_vif *priv,atbm_uint8 *buffer,
			     const atbm_uint8 *ie, atbm_size_t ie_len,atbm_uint8 channel)
{
	atbm_uint8 *pos;

	pos = buffer;

	/* SSID */
	*pos++ = ATBM_WLAN_EID_SSID;
	*pos++ = 0;
	//*pos++ = priv->ssid_length;
	//atbm_memcpy(pos,priv->ssid, priv->ssid_length);
	//pos += priv->ssid_length;
	
	/* Supported rates */
	/* Extended supported rates */	
	pos = atbmwifi_ieee80211_add_rate_ie(pos ,0,~0);	
	
	
	if (channel ) {
		*pos++ = ATBM_WLAN_EID_DS_PARAMS;
		*pos++ = 1;
		*pos++ = channel;
	}
	pos = atbmwifi_ieee80211_add_ht_ie(priv,pos);

#ifdef CONFIG_WPS
	pos = atbmwifi_ieee80211_add_preq_wps_ie(priv, pos);
#endif

#ifdef CONFIG_P2P
	if(priv->p2p_scan){
		pos = atbm_p2p_add_scan_ie(priv, pos);
	}else if(priv->p2p_join){
		if(priv->p2p_assoc_req_ie && priv->p2p_assoc_req_ie_len){
			atbm_memcpy(pos, priv->p2p_assoc_req_ie, priv->p2p_assoc_req_ie_len);
			pos += priv->p2p_assoc_req_ie_len;
		}
	}
#endif

	/* add any remaining custom IEs */
	if (ie && ie_len) {
		atbm_memcpy(pos, ie ,ie_len);
		pos += ie_len;
	}

	return pos - buffer;
}



FLASH_FUNC struct atbm_buff *atbmwifi_ieee80211_build_probe_req(struct atbmwifi_vif *priv, 
					  atbm_uint8 *dst, const atbm_uint8 *ie, atbm_size_t ie_len)
{
	//struct atbmwifi_common * hw_priv = priv->hw_priv;
	struct atbm_buff *skb=ATBM_NULL;
	struct atbmwifi_ieee80211_mgmt *mgmt;
	atbm_size_t buf_len;
	atbm_uint8 *buf;
	struct atbmwifi_ieee80211_hdr_3addr *hdr;
	struct atbmwifi_ieee80211_tx_info *tx_info;
	 
	skb = atbm_dev_alloc_skb(1024);
	if (!skb)
		return ATBM_NULL;
		
	
	hdr = (struct atbmwifi_ieee80211_hdr_3addr *) atbm_skb_put(skb, sizeof(*hdr));
	//iot_printf("hmac:build_probe_req ++<%p>\n",hdr);
	atbm_memset(hdr, 0, sizeof(*hdr));
	hdr->frame_control = atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_MGMT |
					 ATBM_IEEE80211_STYPE_PROBE_REQ);
	atbm_memcpy(hdr->addr2, priv->mac_addr, ATBM_ETH_ALEN);
	hdr->seq_ctrl  = 0;
	hdr->duration_id = 0;
	if (dst) {
		mgmt = (struct atbmwifi_ieee80211_mgmt *) hdr;
		atbm_memcpy(mgmt->da, dst, ATBM_ETH_ALEN);
		atbm_memcpy(mgmt->bssid, dst, ATBM_ETH_ALEN);
	}
	else {
		atbm_memset(hdr->addr1, 0xff, ATBM_ETH_ALEN);
		atbm_memset(hdr->addr3, 0xff, ATBM_ETH_ALEN);
	}
	buf = (atbm_uint8 *)(hdr + 1);

	buf_len = atbmwifi_ieee80211_build_preq_ies(priv, buf, ie, ie_len,
					  priv->bss.channel_num);

	atbm_skb_put(skb, buf_len);

	tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
	tx_info->flags = ATBM_IEEE80211_TX_INTFL_DONT_ENCRYPT;

	return skb;
}


FLASH_FUNC struct atbm_buff * atbmwifi_ieee80211_send_probe_req(struct atbmwifi_vif *priv, atbm_uint8 *dst,
			      const atbm_uint8 *ie, atbm_size_t ie_len, ATBM_BOOL no_cck)
{
	struct atbm_buff *skb;
	struct atbmwifi_ieee80211_tx_info *tx_info;

	skb = atbmwifi_ieee80211_build_probe_req(priv, dst,ie, ie_len);
	tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
	if (skb) {
		if (no_cck)
			tx_info->flags |=
				ATBM_IEEE80211_TX_CTL_NO_CCK_RATE;
	}
#ifdef CONFIG_P2P
	if(priv->p2pdata){
		tx_info->flags |= ATBM_IEEE80211_TX_CTL_NO_CCK_RATE;
	}
#endif
	return skb;
}

FLASH_FUNC struct atbm_buff * atbmwifi_ieee80211_send_assoc_req(struct atbmwifi_vif *priv)
{
	//struct atbmwifi_common * hw_priv = priv->hw_priv;
	struct atbm_buff *skb;
	struct atbmwifi_ieee80211_mgmt *mgmt;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	atbm_uint8 *pos;
	//atbm_size_t offset = 0, noffset;
	atbm_uint16 capab;
	atbm_uint32 rates = 0,rates_len;
	struct atbmwifi_ieee80211_tx_info *tx_info;
#ifdef CONFIG_WPS
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)priv->appdata;
#endif

		/*
		 * In case AP not provide any supported rates information
		 * before association, we send information element(s) with
		 * all rates that we support.
		 */
	rates = priv->bss.rate.support_rates;
	if(rates < 0xf)
		rates = 0xffffffff;
	rates_len = atbmwifi_g_rates_size;
	//iot_printf("atbmwifi_rates %d %d\n",sizeof(atbmwifi_rates),sizeof(atbmwifi_rates[0]));


	skb = atbm_dev_alloc_skb(
			sizeof(*mgmt) + /* bit too much but doesn't matter */
			2 + priv->ssid_length+ /* SSID */
			4 + rates_len + /* (extended) rates */
			4 + /* power capability */
			2 + /* supported channels */
			2 + sizeof(struct atbmwifi_ieee80211_ht_cap) + /* HT */
			priv->extra_ie_len+ /* extra IEs */
			9);/* WMM */
	if (!skb)
		return ATBM_NULL;


	capab = ATBM_WLAN_CAPABILITY_ESS;


	capab |= ATBM_WLAN_CAPABILITY_SHORT_SLOT_TIME;
	capab |= ATBM_WLAN_CAPABILITY_SHORT_PREAMBLE;

	if (config->privacy)
	capab |= ATBM_WLAN_CAPABILITY_PRIVACY;

	mgmt = (struct atbmwifi_ieee80211_mgmt *) ATBM_OS_SKB_DATA(skb);
	atbm_memset(mgmt, 0, 24);
	
	atbm_memcpy(mgmt->sa, priv->mac_addr, ATBM_ETH_ALEN);
	atbm_memcpy(mgmt->da, priv->daddr, ATBM_ETH_ALEN);
	atbm_memcpy(mgmt->bssid, priv->bssid, ATBM_ETH_ALEN);


	mgmt->frame_control = atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_MGMT |
						  ATBM_IEEE80211_STYPE_ASSOC_REQ);
	mgmt->u.assoc_req.capab_info = atbm_cpu_to_le16(capab);
	mgmt->u.assoc_req.listen_interval =
				atbm_cpu_to_le16(priv->bss.beacon_interval);
	pos= mgmt->u.assoc_req.variable;
	
	/* SSID */
	*pos++ = ATBM_WLAN_EID_SSID;
	*pos++ = priv->ssid_length;
	atbm_memcpy(pos,priv->ssid, priv->ssid_length);
	pos += priv->ssid_length;
	
	/* add all rates which were marked to be used above */
	pos = atbmwifi_ieee80211_add_rate_ie(pos,0,rates);
	/*
	if (priv->bss.channel_num) {
		*pos++ = ATBM_WLAN_EID_DS_PARAMS;
		*pos++ = 1;
		*pos++ = priv->bss.channel_num;
	}*/

	pos = atbmwifi_ieee80211_add_ht_ie(priv,pos);

#ifdef CONFIG_P2P
	if(priv->p2p_join){
		if(priv->p2p_assoc_req_ie && priv->p2p_assoc_req_ie_len){
			atbm_memcpy(pos, priv->p2p_assoc_req_ie, priv->p2p_assoc_req_ie_len);
			pos += priv->p2p_assoc_req_ie_len;
		}
	}
#endif

	if (priv->bss.wmm_used){
		pos = (atbm_uint8*)atbmwifi_ieee80211_add_wme(priv,pos);
	}

#ifdef CONFIG_WPS
	if(wpa_s->wps_mode != WPS_MODE_UNKNOWN)
		pos = atbmwifi_ieee80211_add_assocreq_wps_ie(priv, pos);
	else
#endif
	/* if present, add any custom IEs that go before HT */
	if (priv->extra_ie && priv->extra_ie_len) {
		atbm_memcpy(pos, priv->extra_ie, priv->extra_ie_len);
		pos += priv->extra_ie_len;
		wifi_printk(WIFI_DBG_MSG,"assciating:ie(%d)\n", priv->extra_ie_len);
	}
	
	atbm_skb_put(skb, pos-(atbm_uint8 *)mgmt);

	tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
#ifdef CONFIG_P2P
	if(priv->p2pdata){
		tx_info->flags |= ATBM_IEEE80211_TX_CTL_NO_CCK_RATE;
	}else
#endif
	{
		tx_info->flags |= ATBM_IEEE80211_TX_CTL_USE_MINRATE;
	}
	tx_info->flags |= ATBM_IEEE80211_TX_INTFL_DONT_ENCRYPT;
	return skb;
}

FLASH_FUNC atbm_void atbmwifi_tx_sta_mgmtframe(struct atbmwifi_vif *priv,atbm_uint16 stype,atbm_uint16 transaction )
{
	
	//struct atbmwifi_ieee80211_hdr *hdr;
	struct atbmwifi_common * hw_priv = priv->hw_priv;
	struct atbm_buff *skb = ATBM_NULL;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	wifi_printk(WIFI_TX,"atbmwifi_tx_sta_mgmtframe  bssid=%x %x:%x\n",(atbm_uint32)priv->bssid[0],(atbm_uint32)priv->bssid[4],(atbm_uint32)priv->bssid[5]);
	//
	///build mgmt frame 
	//
	switch(stype){
		case ATBM_IEEE80211_STYPE_PROBE_REQ:
			//atbmwifi_ieee80211_send_probe_req(priv,NULL,priv->ssid,priv->ssid_length,priv->extra_ie,priv->extra_ie_len,-1,0);
			break;
		case ATBM_IEEE80211_STYPE_AUTH:
			wifi_printk(WIFI_TX|WIFI_CONNECT,"[sta]:send STYPE_AUTH \n");
			skb = atbmwifi_ieee80211_send_auth(priv,transaction,config->auth_alg,priv->daddr,priv->bssid,0);
			break;
		case ATBM_IEEE80211_STYPE_ASSOC_REQ:
		case ATBM_IEEE80211_STYPE_REASSOC_REQ:
			wifi_printk(WIFI_TX|WIFI_CONNECT,"[sta]:send ASSOC_REQ \n");
			skb = atbmwifi_ieee80211_send_assoc_req(priv);
			break;
		default:
			break;
	}
	if(skb == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR|WIFI_TX,"atbmwifi_tx_sta_mgmtframe %x error!! \n",stype);
		return;
	}
	//
	//send mgmt frame
	//
	atbmwifi_tx(hw_priv,skb,priv);
}

static atbm_uint8 sta_chllenge[ATBM_WLAN_AUTH_CHALLENGE_LEN];

atbm_void atbmwifi_rx_ap_auth(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{
	atbm_uint16 auth_alg, auth_transaction, status_code;
	atbm_uint16 fc;
//	struct hostapd_data *hapd = (struct hostapd_data *)priv->appdata;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	int len = ATBM_OS_SKB_LEN(skb)-offsetof(struct atbmwifi_ieee80211_mgmt, u.auth.variable);
	struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *) ATBM_OS_SKB_DATA(skb);
	atbm_uint16 resp = ATBM_WLAN_STATUS_SUCCESS;
	struct atbmwifi_ieee80211_tx_info * tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
	atbm_uint8 *resp_ies = ATBM_NULL;
	atbm_size_t resp_ies_len = 0;
	struct atbm_buff *skb_tx = ATBM_NULL;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	//struct hostapd_sta_info *sta = NULL;

	auth_alg = mgmt->u.auth.auth_alg;
	auth_transaction = mgmt->u.auth.auth_transaction;
	status_code = mgmt->u.auth.status_code;
	fc = mgmt->frame_control;

	wifi_printk(WIFI_WPA,"ap:rx_auth:alg(%d),tran(%d),status(%d),fc(%x)\n",
		auth_alg,auth_transaction,status_code,fc);


	if (!(((config->auth_alg==ATBM_WLAN_AUTH_OPEN) &&
	       auth_alg == ATBM_WLAN_AUTH_OPEN) ||
	      ((config->auth_alg==ATBM_WLAN_AUTH_SHARED_KEY) &&
	       auth_alg == ATBM_WLAN_AUTH_SHARED_KEY))) {
		wifi_printk(WIFI_WPA,"ap:rx_auth:Unsupport rxalg(%d!=%d)\n",auth_alg,config->auth_alg);
 		dump_mem(mgmt,32);
		
		resp = ATBM_WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG;
		goto fail;
	}

	if (!(auth_transaction == 1 ||
	      (auth_alg == ATBM_WLAN_AUTH_SHARED_KEY && auth_transaction == 3))) {
#ifdef WPA_HOST_DEBUG
			wifi_printk(WIFI_DBG_INIT,"ap:Unknown auth transnum (%d)\n",
			auth_transaction);
#endif
		resp = ATBM_WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION;
		goto fail;
	}

	if (atbm_memcmp(mgmt->sa, priv->mac_addr, ATBM_ETH_ALEN) == 0)
	{
		wifi_printk(WIFI_DBG_INIT,"Sta " MACSTR " not allow to auth\n",
		       MAC2STR(mgmt->sa));
		resp = ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
		goto fail;
	}

	if(auth_alg == ATBM_WLAN_AUTH_SHARED_KEY)
	{
		
		if(auth_transaction == 1)
		{
			atbm_uint8 key[8]= {0,1,2,3,4,5,6,7};
			resp_ies = atbm_kmalloc(2 + ATBM_WLAN_AUTH_CHALLENGE_LEN,GFP_KERNEL);

			if(resp_ies == ATBM_NULL)
			{
				resp = ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
				goto fail;
			}
			rc4_skip(key, sizeof(key), 0,
				 sta_chllenge, ATBM_WLAN_AUTH_CHALLENGE_LEN);

			resp_ies[0] = ATBM_WLAN_EID_CHALLENGE;
			resp_ies[1] = ATBM_WLAN_AUTH_CHALLENGE_LEN;
			atbm_memcpy(resp_ies + 2, sta_chllenge,
				  ATBM_WLAN_AUTH_CHALLENGE_LEN);
			resp_ies_len = 2 + ATBM_WLAN_AUTH_CHALLENGE_LEN;
//			wifi_printk(WIFI_DBG_INIT,"atbmwifi_ieee80211_send_auth:set challenge\n");
			
		}
		else if(auth_transaction == 3)
		{
			const atbm_uint8 *challenge = ATBM_NULL;
//			wifi_printk(WIFI_DBG_MSG,"hostapd_rx_auten len(%d)\n\r",len);
//			wifi_printk(WIFI_DBG_MSG,"hostapd_rx_auten len(%d)\n\r",IEEE80211_HDRLEN + sizeof(mgmt->u.auth) +
//	    		2 + ATBM_WLAN_AUTH_CHALLENGE_LEN);
			if ((len >=2 + ATBM_WLAN_AUTH_CHALLENGE_LEN )&&
	    		(mgmt->u.auth.variable[0] == ATBM_WLAN_EID_CHALLENGE) &&
	    		(mgmt->u.auth.variable[1] == ATBM_WLAN_AUTH_CHALLENGE_LEN))
				{
					challenge = &mgmt->u.auth.variable[2];
//					wifi_printk(WIFI_DBG_MSG,"hostapd_rx_auten challenge\n\r");
				}
			if ( !challenge ||
	   			atbm_memcmp(sta_chllenge, challenge, ATBM_WLAN_AUTH_CHALLENGE_LEN))
				{
				    wifi_printk(WIFI_WPA,"ap_rx_auth challenge ATBM_FALSE\n\r");
					resp = ATBM_WLAN_STATUS_CHALLENGE_FAIL;
				}
			
		}
	}
	
	if(priv->extra_ie){
		atbm_kfree(priv->extra_ie);
	}
	priv->extra_ie = resp_ies;
	priv->extra_ie_len = resp_ies_len;
	
	skb_tx = atbmwifi_ieee80211_send_auth(priv,auth_transaction+1,auth_alg,mgmt->sa,priv->bssid,resp);
	atbmwifi_tx(hw_priv,skb_tx,priv);
	if(resp  == ATBM_WLAN_STATUS_SUCCESS) {
		priv->connect_timer_linkid = tx_info->link_id;
		wifi_printk(WIFI_WPA,"atbm: atbmwifi_rx_ap_auth(), ms=%u\n", atbm_GetOsTimeMs());
		atbm_StartTimer(&priv->connect_expire_timer,ATBM_WIFI_AUTH_TIMEOUT);
	}
fail:
	atbm_kfree(resp_ies);
	priv->extra_ie_len = 0;
	priv->extra_ie = ATBM_NULL;
	
}

static ATBM_BOOL is_uapsd_supported(struct atbmwifi_ieee802_11_elems *elems)
{
	atbm_uint8 qos_info;

	if (elems->wmm_info && elems->wmm_info_len == 7
	    && elems->wmm_info[5] == 1)
		qos_info = elems->wmm_info[6];
	else if (elems->wmm_param && elems->wmm_param_len == 24
		 && elems->wmm_param[5] == 1)
		qos_info = elems->wmm_param[6];
	else
		/* no valid wmm information or parameter element found */
		return ATBM_FALSE;

	return qos_info & ATBM_IEEE80211_WMM_IE_STA_QOSINFO_AC_MASK;
}


FLASH_FUNC int atbmwifi_rx_assoc_req(struct atbmwifi_vif *priv,struct atbmwifi_ieee80211_mgmt *mgmt,int len,struct atbmwifi_ieee80211_tx_info * tx_info)
{
	//struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *) OS_SKB_DATA(skb);
	//struct atbmwifi_ieee80211_tx_info * tx_info = IEEE80211_SKB_CB(skb);
	atbm_uint16 type = mgmt->frame_control & atbm_cpu_to_le16(ATBM_IEEE80211_FCTL_STYPE);
	atbm_uint16 resp = ATBM_WLAN_STATUS_SUCCESS;
	struct atbmwifi_ieee802_11_elems elems;
	const atbm_uint8 *wpa_ie=ATBM_NULL;
//	atbm_size_t wpa_ie_len=0;
	atbm_uint8 * data=ATBM_NULL;
	int ret =0;
	atbm_uint16 ap_ht_cap_flags;
	atbm_uint8 atbm_is_40m = 0;
	atbm_uint8 sta_supp_40m = 0;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	struct atbmwifi_sta_priv *sta_priv = atbmwifi_sta_find_form_linkid(priv,tx_info->link_id);
	//struct atbmwifi_cfg80211_bss *sta = &priv->bss;
#ifdef CONFIG_WPS
	atbm_uint8 *wps_ie = ATBM_NULL;
	atbm_size_t wps_ie_len = 0;
	struct wpabuf *wpaBuff = ATBM_NULL;
#endif

	wifi_printk(WIFI_CONNECT,  "atbmwifi_rx_assoc_req \n");
	if(sta_priv == ATBM_NULL){
		wifi_printk(WIFI_CONNECT, "<ERROR>atbmwifi_rx_assoc_req sta_priv ATBM_NULL just drop \n");
		resp = ATBM_WLAN_STATUS_AUTH_TIMEOUT;
		goto fail;
	}

	if(type == ATBM_IEEE80211_STYPE_ASSOC_REQ)
	{
		data = mgmt->u.assoc_req.variable;
		len  = len-offsetof(struct atbmwifi_ieee80211_mgmt, u.assoc_req.variable);
		
	}
	else if(type == ATBM_IEEE80211_STYPE_REASSOC_REQ)
	{
		data = mgmt->u.reassoc_req.variable;
		len  = len-offsetof(struct atbmwifi_ieee80211_mgmt, u.reassoc_req.variable);
		
	}
	else {
		return -1;
	}
	//atbm_memcpy(sta_priv.mac,mgmt->sa,6);
	//sta_priv.priv = priv;

	//ie = cfg80211_find_ie(ATBM_WLAN_EID_DS_PARAMS,data,len);
	atbm_memset(&elems,0,sizeof(elems));
	atbm_ieee802_11_parse_elems(data,len,&elems);

	if (elems.rsn) {
		wpa_ie = elems.rsn-2;
//		wpa_ie_len = elems.rsn_len;
	} else if (elems.wpa) {
		wpa_ie = elems.wpa-2;
//		wpa_ie_len = elems.wpa_len;
	} else {
		wpa_ie = ATBM_NULL;
//		wpa_ie_len = 0;
	}

	resp = check_ssid(config,  elems.ssid, elems.ssid_len);
	if (resp != ATBM_WLAN_STATUS_SUCCESS)
		goto fail;
	
	if (!elems.supp_rates) {		
		resp = ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
		goto fail;
	}
/*
	if (elems->supp_rates_len + elems->ext_supp_rates_len >
	    sizeof(sta->supported_rates)) {		
		resp = ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
		goto fail;
	}
*/
	//	wifi_printk(WIFI_DBG_INIT,"check_ie:wpa_ie_len(%d)\n",wpa_ie_len);	
#ifdef CONFIG_WPS
	if((priv->pbc || priv->pin) && elems.wps_ie)
	{
		wpaBuff = wps_build_assoc_resp_ie();
		if(!wpaBuff){
			resp = ATBM_WLAN_REASON_UNSPECIFIED;
			goto fail;
		}
		wps_ie = wpaBuff->buf;
		wps_ie_len = wpaBuff->used;
	}else
#endif
	if (config->wpa && wpa_ie == ATBM_NULL) {
		resp = ATBM_WLAN_STATUS_INVALID_IE;
		goto fail;
	}
	else if ((config->wpa==0) && wpa_ie ) {
		resp = ATBM_WLAN_STATUS_INVALID_IE;
		goto fail;
	}

	if (elems.wmm_param || elems.wmm_info){
		sta_priv->uapsd_support_queues=is_uapsd_supported(&elems);
		if(elems.wmm_info){
			sta_priv->max_sp=(*(elems.wmm_info+8)>>5&0x3);
		}else if(elems.wmm_param){
			sta_priv->max_sp=(*(elems.wmm_param+8)>>5&0x3);
		}
		atbm_wmm_status_set(1);		
		wifi_printk(WIFI_CONNECT,"uapsd_support_queues=%x,max_sp=%d\n",sta_priv->uapsd_support_queues,sta_priv->max_sp);
	}else{
		atbm_wmm_status_set(0);
	}
	sta_priv->beacon_interval = mgmt->u.assoc_req.listen_interval;
	//priv->bss.channel_num =  elems.ds_params[0];
	//atbm_memcpy(priv->bss.bssid, mgmt->bssid,6);
	//if(elems.tim)
	//	priv->bss.dtim_period = elems.tim->dtim_period;
	//else
	//	priv->bss.dtim_period = 0;
	
	if(elems.erp_info)
		sta_priv->short_preamble = (elems.erp_info[0]& ATBM_WLAN_ERP_BARKER_PREAMBLE) == 0;
	/*		
	if (erp_valid) {
		use_protection = (erp & WLAN_ERP_USE_PROTECTION) != 0;
		use_short_preamble = (erp & ATBM_WLAN_ERP_BARKER_PREAMBLE) == 0;
	} else {
		use_protection = ATBM_FALSE;
		use_short_preamble = !!(capab & ATBM_WLAN_CAPABILITY_SHORT_PREAMBLE);
	}
	*/
	sta_priv->wpa = (elems.rsn_len || elems.wpa_len) ? 1:0;
	//priv->bss.wps = elems.wps_ie_len ? 1:0;
	//priv->bss.p2p = elems.p2p_ie_len ? 1:0;
	//priv->bss.bcm_ap = elems->bcm_ie_len ? 1:0;	
	sta_priv->ht =	elems.ht_cap_elem? 1:0;
	
	sta_priv->rate.ht = sta_priv->ht;
	
	if(elems.ht_cap_elem){
		atbmwifi_ieee80211_ht_cap_ie_to_sta_ht_cap(&atbmwifi_band_2ghz,
						 elems.ht_cap_elem,
						&sta_priv->rate.ht_cap);
	}
	ap_ht_cap_flags = sta_priv->rate.ht_cap.cap;
	
	atbm_is_40m = !!atbmwifi_chtype_is_40M(priv->hw_priv->channel_type);
	sta_supp_40m = !!(sta_priv->rate.ht_cap.cap&ATBM_IEEE80211_HT_CAP_SUP_WIDTH_20_40);

	if(atbm_is_40m^sta_supp_40m){
		sta_priv->rate.channel_type = sta_priv->ht ? ATBM_NL80211_CHAN_HT20 : ATBM_NL80211_CHAN_NO_HT;
	}else {
		sta_priv->rate.channel_type = sta_priv->ht ? priv->hw_priv->channel_type : ATBM_NL80211_CHAN_NO_HT;
	}

	if(sta_priv->ht&&(ap_ht_cap_flags&(ATBM_IEEE80211_HT_CAP_SGI_20|ATBM_IEEE80211_HT_CAP_SGI_40))){
		sta_priv->sgi = 1;
	}else {
		sta_priv->sgi = 0;
	}
	
	wifi_printk(WIFI_RATE,"atbm_is_40m [%x],sta_supp_40m [%x],sta_chtype[%x]\n",atbm_is_40m,sta_supp_40m,sta_priv->rate.channel_type);
	atbmwifi_ieee80211_get_sta_rateinfo(&sta_priv->rate,elems.supp_rates, elems.supp_rates_len);
	atbmwifi_ieee80211_get_sta_rateinfo(&sta_priv->rate,elems.ext_supp_rates, elems.ext_supp_rates_len);
	
	wifi_printk(WIFI_RATE,"support_rates %x,basic_rates %x\n",sta_priv->rate.support_rates,sta_priv->rate.basic_rates);

	ret = atbmwifi_sta_add(priv,mgmt->sa);
	if(ret){	
		resp = ATBM_WLAN_STATUS_AUTH_TIMEOUT;
		goto fail;
	}
	priv->assoc_ok = 1;
	atbm_CancelTimer(&priv->connect_expire_timer);

fail:
	{
		struct atbm_buff *skb = ATBM_NULL;	
		//atbm_spin_lock(mgm_tx);
		atbm_memcpy(priv->daddr,mgmt->sa,6);
#ifdef CONFIG_WPS
		skb = atbmwifi_ieee80211_send_assoc_resp(priv,resp,type == ATBM_IEEE80211_STYPE_REASSOC_REQ ? 1:0,wps_ie,wps_ie_len,tx_info->link_id);
		wpabuf_free(wpaBuff);
#else
		skb = atbmwifi_ieee80211_send_assoc_resp(priv,resp,type == ATBM_IEEE80211_STYPE_REASSOC_REQ ? 1:0,wpa_ie,wpa_ie_len,tx_info->link_id);
#endif
		atbmwifi_tx(priv->hw_priv,skb,priv);
		//atbm_spin_unlock(mgm_tx);
		
	}
	return resp;
}

FLASH_FUNC atbm_void atbmwifi_rx_ap_mgmtframe(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{
	struct atbmwifi_ieee80211_hdr * hdr = (struct atbmwifi_ieee80211_hdr *) ATBM_OS_SKB_DATA(skb);
	atbm_uint16 stype = hdr->frame_control & atbm_cpu_to_le16(ATBM_IEEE80211_FCTL_STYPE);
	struct atbmwifi_ieee80211_tx_info * tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
	
	
     switch(stype){
		case ATBM_IEEE80211_STYPE_PROBE_REQ:
			//atbmwifi_tx_ap_mgmtframe(priv,ATBM_IEEE80211_STYPE_PROBE_RESP,0);
			break;
		case ATBM_IEEE80211_STYPE_PROBE_RESP:
			atbmwifi_ap_rx_probe_resp(priv,skb);
			break;
		case ATBM_IEEE80211_STYPE_AUTH:	
			//atbm_spin_lock(mgm_tx);
			//save daddr
			atbm_memcpy(priv->daddr,hdr->addr2,6);
			tx_info->link_id = atbmwifi_sta_alloc(priv,priv->daddr);
			if(tx_info->link_id > ATBMWIFI__MAX_STA_IN_AP_MODE || tx_info->link_id <= 0)
				return;
			//		
			atbmwifi_rx_ap_auth(priv,skb);
			//atbm_spin_unlock(mgm_tx);
			
			atbmwifi_event_uplayer(priv,ATBM_WIFI_AUTH_EVENT,(atbm_uint8*)skb);
			break;
		case ATBM_IEEE80211_STYPE_ASSOC_REQ:
		case ATBM_IEEE80211_STYPE_REASSOC_REQ:
			
			tx_info->link_id = atbmwifi_find_link_id(priv,hdr->addr2);
			if(tx_info->link_id == 0){
				//drop
				atbmwifi_ieee80211_tx_mgmt_deauth(priv,hdr->addr2,priv->bssid,ATBM_WLAN_REASON_PREV_AUTH_NOT_VALID);
				break;
			}
			//rx_info->link_id
			if(atbmwifi_rx_assoc_req(priv,(struct atbmwifi_ieee80211_mgmt *)hdr,ATBM_OS_SKB_LEN(skb),tx_info) == ATBM_WLAN_STATUS_SUCCESS){
				atbmwifi_event_uplayer(priv,ATBM_WIFI_ASSOC_EVENT,(atbm_uint8*)skb);
			}
			else {
				atbmwifi_event_uplayer(priv,ATBM_WIFI_DEASSOC_EVENT,0);
			}
			break;
		case ATBM_IEEE80211_STYPE_DEAUTH:
		case ATBM_IEEE80211_STYPE_DISASSOC:
			tx_info->link_id = atbmwifi_find_link_id(priv,hdr->addr2);
			wifi_printk(WIFI_WPA,"[ap]:rx DEAUTH \n");
			atbmwifi_ap_deauth(priv,atbmwifi_ieee80211_get_SA(hdr));
			break;
#ifdef CONFIG_P2P
		case ATBM_IEEE80211_STYPE_ACTION:
			{
				struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *)ATBM_OS_SKB_DATA(skb);
				struct atbmwifi_ieee80211_rx_status *hw_hdr = ATBM_IEEE80211_SKB_RXCB(skb);
				atbm_uint8 *data = (atbm_uint8 *)ATBM_OS_SKB_DATA(skb) + offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_req.variable);
				int len = ATBM_OS_SKB_LEN(skb) - offsetof(struct atbmwifi_ieee80211_mgmt, u.probe_req.variable);
				atbm_p2p_rx_action(priv, mgmt->da, mgmt->sa, mgmt->bssid,
					mgmt->u.action.category, data, len, hw_hdr->freq);
			}
			break;
#endif
		default:
			break;
	}
}


FLASH_FUNC atbm_void atbmwifi_tx_ap_mgmtframe(struct atbmwifi_vif *priv,atbm_uint16 stype,atbm_uint16 transaction )
{
	
	//struct atbmwifi_ieee80211_hdr *hdr;
	struct atbmwifi_common * hw_priv = priv->hw_priv;
	struct atbm_buff *skb = ATBM_NULL;

	
	//
	///build mgmt frame 
	//
	switch(stype){
		case ATBM_IEEE80211_STYPE_PROBE_RESP:
			/*probe resp is send by lmac*/
			//atbmwifi_ieee80211_send_probe_resp(priv,NULL,priv->ssid,priv->ssid_length,priv->extra_ie,priv->extra_ie_len);
			break;
		case ATBM_IEEE80211_STYPE_AUTH:
			wifi_printk(WIFI_CONNECT, "[ap]:tx AUTH \n");
			skb = atbmwifi_ieee80211_send_auth(priv,transaction,ATBM_WLAN_AUTH_OPEN,priv->daddr,priv->bssid,0);
			break;
		case ATBM_IEEE80211_STYPE_ASSOC_RESP:
			wifi_printk(WIFI_CONNECT, "[ap]:tx ASSOC\n");
			skb = atbmwifi_ieee80211_send_assoc_resp(priv,0,0,ATBM_NULL,0,0);
			break;
		default:
			break;
	}
	if(skb == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR, "atbmwifi_tx_ap_mgmtframe %x error!! \n",stype);
		return;
	}
	//
	//send mgmt frame
	//
	atbmwifi_tx(hw_priv,skb,priv);

}

FLASH_FUNC struct atbm_buff * atbmwifi_ieee80211_send_assoc_resp(struct atbmwifi_vif *priv,
			    atbm_uint16 status_code, int reassoc, const atbm_uint8 *ies,
			    atbm_size_t ies_len,atbm_uint16 aid)
{
	int send_len;
	struct atbm_buff *skb=ATBM_NULL;
//	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct atbmwifi_ieee80211_mgmt *reply;
	atbm_uint8 *p = ATBM_NULL;
	atbm_uint16 capab=0;
	struct atbmwifi_ieee80211_tx_info *tx_info;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);

	wifi_printk(WIFI_DBG_MSG,"atbm: atbmwifi_ieee80211_send_assoc_resp() ===>\n");

	skb = atbm_dev_alloc_skb(
			sizeof(struct atbmwifi_ieee80211_mgmt) +1024);/* WMM */
	if (!skb){
		//iot_printf("atbm_dev_alloc_skb NULL \n");
		return ATBM_NULL;
	}

	p = ATBM_OS_SKB_DATA(skb);

	//atbm_memset(p, 0, OS_SKB_LEN(skb));
	reply = (struct atbmwifi_ieee80211_mgmt *) p;
	atbm_memset(p, 0, sizeof(struct atbmwifi_ieee80211_mgmt));

	reply->frame_control =  atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_MGMT |
			      						ATBM_IEEE80211_STYPE_ASSOC_RESP);
	atbm_memcpy(reply->da, priv->daddr, ATBM_ETH_ALEN);
	atbm_memcpy(reply->sa, priv->mac_addr, ATBM_ETH_ALEN);
	atbm_memcpy(reply->bssid, priv->bssid, ATBM_ETH_ALEN);
	send_len = ATBM_IEEE80211_HDRLEN;
	send_len += sizeof(reply->u.assoc_resp);
	
	if(config->privacy)	
		capab |= ATBM_WLAN_CAPABILITY_PRIVACY;
	
	capab |= ATBM_WLAN_CAPABILITY_SHORT_SLOT_TIME;
	capab |= ATBM_WLAN_CAPABILITY_ESS|ATBM_WLAN_CAPABILITY_SHORT_PREAMBLE;
	
	reply->u.assoc_resp.capab_info = capab;
	
	reply->u.assoc_resp.status_code = atbm_cpu_to_le16(status_code);
	reply->u.assoc_resp.aid = atbm_cpu_to_le16(aid/*aid=1*/   | BIT(14) | BIT(15));
	/* Supported rates */
	p = reply->u.assoc_resp.variable;	

	/* Supported rates */	
	/* Extended supported rates */	
	p = atbmwifi_ieee80211_add_rate_ie(p ,0,~0);

	///*p++ = ATBM_WLAN_EID_DS_PARAMS;
	//*p++ = 1;
	//*p++ = hw_priv->channel_idex;

	p  = atbmwifi_ieee80211_add_wmm_param(priv,p);

#ifdef CONFIG_IEEE80211N
	p = atbmwifi_ieee80211_add_ht_ie(priv,p);
	p = atbmwifi_ieee80211_add_ht_operation(priv,p);
#endif /* CONFIG_IEEE80211N */

#ifdef CONFIG_WPS
	if(ies_len > 0){
		atbm_memcpy(p, ies, ies_len);
		p += ies_len;
	}
#endif

#ifdef CONFIG_P2P
	if(priv->p2p_ap){
		p = atbm_p2p_add_ap_assoc_resp_ie(priv, p);
	}
#endif

	send_len += p - reply->u.assoc_resp.variable;
	atbm_skb_put(skb,send_len);
	tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
	tx_info->flags |= ATBM_IEEE80211_TX_INTFL_DONT_ENCRYPT;
	tx_info->flags |= ATBM_IEEE80211_TX_CTL_USE_MINRATE;
	wifi_printk(WIFI_DBG_MSG,"atbm: atbmwifi_ieee80211_send_assoc_resp() <===\n");

	return skb;
	
}
FLASH_FUNC struct atbm_buff *atbmwifi_ieee80211_send_proberesp(struct atbmwifi_vif *priv,
				const atbm_uint8 *ies,
			    atbm_size_t ies_len)
{	
	int send_len;
	struct atbm_buff *skb=ATBM_NULL;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct atbmwifi_ieee80211_mgmt *reply;
	atbm_uint8 *p=ATBM_NULL;
	atbm_uint16 capab =0;	
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);

	skb = atbm_dev_alloc_skb(
			sizeof(struct atbmwifi_ieee80211_mgmt) +1024);/* WMM */
	if (!skb){
		wifi_printk(WIFI_DBG_ERROR,"alloc_skb ATBM_NULL\n");
		return ATBM_NULL;
	}

	p = ATBM_OS_SKB_DATA(skb);
	atbm_memset(p, 0, ATBM_OS_SKB_LEN(skb));
	reply = (struct atbmwifi_ieee80211_mgmt *) p;
	reply->frame_control =  atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_MGMT |
			      						ATBM_IEEE80211_STYPE_PROBE_RESP);
	
	//iot_printf("atbmwifi_ieee80211_send_proberesp FC=%x\n",reply->frame_control);
	atbm_memcpy(reply->da, priv->daddr, ATBM_ETH_ALEN);

	atbm_memcpy(reply->sa, priv->mac_addr, ATBM_ETH_ALEN);
	atbm_memcpy(reply->bssid, priv->bssid, ATBM_ETH_ALEN);

	send_len = ATBM_IEEE80211_HDRLEN;
	send_len += sizeof(reply->u.probe_resp);


	
	if (config->privacy)	
		capab |= ATBM_WLAN_CAPABILITY_PRIVACY;
	capab |= ATBM_WLAN_CAPABILITY_SHORT_SLOT_TIME;
	capab |= ATBM_WLAN_CAPABILITY_ESS|ATBM_WLAN_CAPABILITY_SHORT_PREAMBLE;
	
	reply->u.probe_resp.beacon_int = hw_priv->beaconInterval;
	reply->u.probe_resp.capab_info = capab;

	p = reply->u.probe_resp.variable;

	/*If hide ssid,probeResponse need to add ssid in ies*/
	/* SSID */
	*p++ = ATBM_WLAN_EID_SSID;
	*p++ = priv->ssid_length;
	atbm_memcpy(p,priv->ssid, priv->ssid_length);
	p+= priv->ssid_length;
	/* Supported rates */	
	/* Extended supported rates */	
	p = atbmwifi_ieee80211_add_rate_ie(p ,0,~0);
	

	*p++ = ATBM_WLAN_EID_DS_PARAMS;
	*p++ = 1;
	*p++ = hw_priv->channel_idex;
	
	p  = atbmwifi_ieee80211_add_wmm_param(priv,p);

#ifdef CONFIG_IEEE80211N
	p = atbmwifi_ieee80211_add_ht_ie(priv,p);
	p = atbmwifi_ieee80211_add_ht_operation(priv,p);
#endif /* CONFIG_IEEE80211N */

	if (ies_len > 0) {
		atbm_memcpy(p,ies, ies_len);
		p += ies_len;
	}

#ifdef CONFIG_WPS
	if(priv->wps_probe_resp_ie){
		atbm_memcpy(p, priv->wps_probe_resp_ie, priv->wps_probe_resp_ie_len);
		p += priv->wps_probe_resp_ie_len;
	}
#endif

#ifdef CONFIG_P2P
	if(priv->p2p_ap){
		p = atbm_p2p_add_ap_pbresp_ie(priv, p);
	}
#endif

	send_len += p - reply->u.probe_resp.variable;

	atbm_skb_put(skb,send_len);

	return skb;

	
}
/*
 * Indicate whether there are frames queued for a station in power-save mode.
 */
int atbmwifi_set_tim(struct atbmwifi_vif  *priv, atbm_uint16 aid, ATBM_BOOL set)
{
    if ((aid == 0) || (aid > ATBMWIFI__MAX_STA_IN_AP_MODE))
            return 0;
    if (set != (atbm_test_bit(aid,(atbm_uint32 *)priv->tim_vbitmap) != 0)) {
        if (set) {
            atbm_set_bit(aid,(atbm_uint32 *)priv->tim_vbitmap);
			wifi_printk(WIFI_PS,"updata tim info %x\n",priv->tim_vbitmap[0]);
            priv->pspending_sta_num++;
        }
        else {
			wifi_printk(WIFI_PS,"clear tim info %x\n",priv->tim_vbitmap[0]);
            atbm_clear_bit(aid,(atbm_uint32 *)priv->tim_vbitmap);
            priv->pspending_sta_num--;
        }
       return 1;
    }
	return 0;
}

atbm_uint8 * atbmwifi_add_tim(atbm_uint8 *frm,
                        struct atbmwifi_vif  *priv,
                        atbm_uint8 mcast)
{
        struct atbmwifi_ieee80211_tim_ie *tim_ie = (struct atbmwifi_ieee80211_tim_ie *)frm;
        atbm_uint8 timoff;
        atbm_uint8 timlen=0;
        atbm_uint8 i;
        if (priv->pspending_sta_num != 0) {
                timoff = WIFI_TIMBITMAP_LEN;		/* impossibly large */
                for (i = 0; i < WIFI_TIMBITMAP_LEN; i++) {
                    if (priv->tim_vbitmap[i]) {
                            timoff = i & ATBM_TIM_BITCTL_UCAST_MASK;
                            break;
                    }
                }
                for (i = WIFI_TIMBITMAP_LEN-1; i >= timoff; i--) {
                    if (priv->tim_vbitmap[i])
                            break;
                }
                timlen = 1 + (i - timoff);
        }
        else {
			timoff = 0;
			timlen = 1;
        }
        /* update information element */
        tim_ie->tim_ie= ATBM_WLAN_EID_TIM;
        tim_ie->tim_len = 3 + timlen;
        tim_ie->dtim_count = 0;
        tim_ie->dtim_period= priv->hw_priv->DTIMPeriod;
        tim_ie->tim_bitmapctl = timoff;
        if (mcast && (tim_ie->dtim_count == 0))
                tim_ie->tim_bitmapctl |= ATBM_TIM_BITCTL_MCAST;
        else
                tim_ie->tim_bitmapctl &= ~ATBM_TIM_BITCTL_MCAST;
        atbm_memcpy(tim_ie->tim_vbitmap, priv->tim_vbitmap + timoff,
               timlen);

        return ((atbm_uint8 *)frm+tim_ie->tim_len+2);
}




FLASH_FUNC struct atbm_buff *atbmwifi_ieee80211_send_beacon(struct atbmwifi_vif  *priv,const atbm_uint8 *ies, atbm_size_t ies_len)
{
	int send_len;
	struct atbm_buff *skb=ATBM_NULL;	
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);	
	struct atbmwifi_ieee80211_mgmt *beacon;
	atbm_uint8 *p=ATBM_NULL;
	atbm_uint16 capab =0;
	struct atbmwifi_ieee80211_tx_info *tx_info;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);

	skb = atbm_dev_alloc_skb(
			sizeof(struct atbmwifi_ieee80211_mgmt) +1024+ies_len);/* WMM */
	if (!skb){
		wifi_printk(WIFI_DBG_ERROR,"alloc_skb ATBM_NULL \n");
		return ATBM_NULL;
	}

	p = ATBM_OS_SKB_DATA(skb);
	atbm_memset(p, 0, ATBM_OS_SKB_LEN(skb));
	beacon = (struct atbmwifi_ieee80211_mgmt *) p;
	beacon->frame_control =  atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_MGMT |
			      						ATBM_IEEE80211_STYPE_BEACON);
	//atbm_memcpy(beacon->da, priv->daddr, ATBM_ETH_ALEN);
	atbm_memset(beacon->da, 0xff, ATBM_ETH_ALEN);
	atbm_memcpy(beacon->sa, priv->mac_addr, ATBM_ETH_ALEN);
	atbm_memcpy(beacon->bssid, priv->bssid, ATBM_ETH_ALEN);

	send_len = ATBM_IEEE80211_HDRLEN;
	send_len += sizeof(beacon->u.beacon);

	if (config->privacy)
		capab |= ATBM_WLAN_CAPABILITY_PRIVACY;
	capab |= ATBM_WLAN_CAPABILITY_SHORT_SLOT_TIME;
	capab |= ATBM_WLAN_CAPABILITY_ESS|ATBM_WLAN_CAPABILITY_SHORT_PREAMBLE;
	
	beacon->u.beacon.beacon_int = hw_priv->beaconInterval;
	beacon->u.beacon.capab_info = capab;

	p = beacon->u.beacon.variable;

	if(!config->hide_ssid/*hide_ssid*/){
		/* ssid*/
		*p++ = ATBM_WLAN_EID_SSID;
		*p++ = priv->ssid_length;
		atbm_memcpy(p,priv->ssid, priv->ssid_length);
		p += priv->ssid_length;
	}else{
		/*hide ssid need set ssidLen=0 or set ssidLen=1&&ssid=0*/
		*p++ = ATBM_WLAN_EID_SSID;
		*p++ = 0;
	}
	/* Supported rates */
	/* Extended supported rates */	
	p = atbmwifi_ieee80211_add_rate_ie(p ,0,~0);
	
	*p++ = ATBM_WLAN_EID_DS_PARAMS;
	*p++ = 1;
	*p++ = hw_priv->channel_idex;
	
	/* Supported ERP */
	*p++ = ATBM_WLAN_EID_ERP_INFO;
	*p++ = 1;
	*p++ =BIT(2);
	
	p  = atbmwifi_ieee80211_add_wmm_param(priv,p);
	p = atbmwifi_add_tim(p,priv,0);
	
#ifdef CONFIG_IEEE80211N
	p = atbmwifi_ieee80211_add_ht_ie(priv,p);
	p = atbmwifi_ieee80211_add_ht_operation(priv,p);
#endif /* CONFIG_IEEE80211N */
	
	if (ies_len > 0) {
		atbm_memcpy(p,ies, ies_len);
		p += ies_len;
	}

#ifdef CONFIG_WPS
	if(priv->wps_beacon_ie != ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR, "set wps_beacon_ie \n");
		atbm_memcpy(p, priv->wps_beacon_ie, priv->wps_beacon_ie_len);
		p += priv->wps_beacon_ie_len;
	}
#endif

#ifdef CONFIG_P2P
	if(priv->p2p_ap){
		p = atbm_p2p_add_ap_beacon_ie(priv, p);
	}
#endif

	send_len += p - beacon->u.beacon.variable;

	atbm_skb_put(skb,send_len);
	tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
	tx_info->flags |= ATBM_IEEE80211_TX_INTFL_DONT_ENCRYPT;
	tx_info->flags |= ATBM_IEEE80211_TX_CTL_USE_MINRATE;
	//iot_printf("beacon len %d \n",OS_SKB_LEN(skb));
	return skb;
}


FLASH_FUNC struct atbm_buff * atbmwifi_ieee80211_send_auth(struct atbmwifi_vif *priv,
			 atbm_uint16 transaction, atbm_uint16 auth_alg,  const atbm_uint8 *da,const atbm_uint8 *bssid,atbm_uint16 resp)
{
//	struct atbmwifi_common * hw_priv = priv->hw_priv;
	struct atbm_buff *skb;
	struct atbmwifi_ieee80211_mgmt *mgmt;
	struct atbmwifi_ieee80211_tx_info *tx_info;
	int err=1;

	skb = atbm_dev_alloc_skb(sizeof(*mgmt) + 6 + priv->extra_ie_len);
	if (!skb)
	{
		wifi_printk(WIFI_TX,"<ERROR> send_auth alloc skb \n");
		return ATBM_NULL;
	}
	wifi_printk(WIFI_WPA,"send_auth alg(%d),transaction(%d),ielen(%d)\n",auth_alg,transaction,priv->extra_ie_len);
	
	mgmt = (struct atbmwifi_ieee80211_mgmt *) atbm_skb_put(skb, 24 + 6);
	atbm_memset(mgmt, 0, 24 + 6);
	mgmt->frame_control = atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_MGMT|
					  ATBM_IEEE80211_STYPE_AUTH);
	atbm_memcpy(mgmt->da, da, ATBM_ETH_ALEN);
	atbm_memcpy(mgmt->sa, priv->mac_addr, ATBM_ETH_ALEN);
	atbm_memcpy(mgmt->bssid, bssid, ATBM_ETH_ALEN);
	mgmt->u.auth.auth_alg = atbm_cpu_to_le16(auth_alg);
	mgmt->u.auth.auth_transaction = atbm_cpu_to_le16(transaction);
	mgmt->u.auth.status_code = atbm_cpu_to_le16(resp);

	if (priv->extra_ie && priv->extra_ie_len) {
		atbm_memcpy(atbm_skb_put(skb, priv->extra_ie_len), priv->extra_ie, priv->extra_ie_len);
	}

	tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
	if (auth_alg == ATBM_WLAN_AUTH_SHARED_KEY && transaction == 3) {
//		mgmt->frame_control |= atbm_cpu_to_le16(ATBM_IEEE80211_FCTL_PROTECTED);
		tx_info->flags |= ATBM_IEEE80211_TX_INTFL_DONT_ENCRYPT;
		ATBM_WARN_ON_FUNC(err);
		return skb;
	}

#ifdef CONFIG_P2P
	if(priv->p2pdata){
		tx_info->flags |= ATBM_IEEE80211_TX_CTL_NO_CCK_RATE;
	}else
#endif
	{
		tx_info->flags |= ATBM_IEEE80211_TX_CTL_USE_MINRATE;
	}

	tx_info->flags |= ATBM_IEEE80211_TX_INTFL_DONT_ENCRYPT;

	return skb;
}

FLASH_FUNC struct atbm_buff * atbmwifi_ieee80211_send_deauth(struct atbmwifi_vif *priv,const atbm_uint8 *da,const atbm_uint8 *bssid,atbm_uint16 reason)
{
//	struct atbmwifi_common * hw_priv = priv->hw_priv;
	struct atbm_buff *skb;
	struct atbmwifi_ieee80211_mgmt *mgmt;
	struct atbmwifi_ieee80211_tx_info *tx_info;
//	int err=1;

	skb = atbm_dev_alloc_skb(sizeof(*mgmt) + 2);
	if (!skb)
	{
		wifi_printk(WIFI_TX,"<ERROR> send_auth alloc skb \n");
		return ATBM_NULL;
	}
	wifi_printk(WIFI_TX,"send_deauth reason(%d)\n",reason);
	
	mgmt = (struct atbmwifi_ieee80211_mgmt *) atbm_skb_put(skb, 24 + 2);
	atbm_memset(mgmt, 0, 24 + 2);
	mgmt->frame_control = atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_MGMT|
					  ATBM_IEEE80211_STYPE_DEAUTH);
	atbm_memcpy(mgmt->da, da, ATBM_ETH_ALEN);
	atbm_memcpy(mgmt->sa, priv->mac_addr, ATBM_ETH_ALEN);
	atbm_memcpy(mgmt->bssid, bssid, ATBM_ETH_ALEN);
	mgmt->u.deauth.reason_code = atbm_cpu_to_le16(reason);

	tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
	tx_info->flags |= ATBM_IEEE80211_TX_INTFL_DONT_ENCRYPT;
	tx_info->flags |= ATBM_IEEE80211_TX_CTL_USE_MINRATE;
	return skb;
}
FLASH_FUNC int atbmwifi_ieee80211_tx_mgmt_deauth(struct atbmwifi_vif *priv,const atbm_uint8 *da,const atbm_uint8 *bssid,atbm_uint16 reason)
{
	struct atbm_buff *skb;

	skb = atbmwifi_ieee80211_send_deauth(priv,da,bssid,reason);

	if(skb == ATBM_NULL)
		return -1;

	atbmwifi_tx(priv->hw_priv,skb,priv);

	return 0;
}
#if NEW_SUPPORT_PS
FLASH_FUNC struct atbm_buff * atbmwifi_ieee80211_NullData(struct atbmwifi_vif *priv,const atbm_uint8 *da,const atbm_uint8 *bssid)
{
	//struct atbmwifi_common * hw_priv = priv->hw_priv;
	struct atbm_buff *skb;
	struct atbmwifi_ieee80211_hdr *nulldata;
	skb = atbm_dev_alloc_skb(sizeof(struct atbmwifi_ieee80211_hdr));
	if (!skb)
	{
		wifi_printk(WIFI_TX,"<ERROR> send_auth alloc skb \n");
		return ATBM_NULL;
	}	
	nulldata = (struct atbmwifi_ieee80211_hdr *) atbm_skb_put(skb, 24);
	atbm_memset(nulldata, 0, 24);
	nulldata->frame_control = atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_DATA|
					  ATBM_IEEE80211_STYPE_NULLFUNC);
	atbm_memcpy(nulldata->addr1, da, ATBM_ETH_ALEN);
	atbm_memcpy(nulldata->addr2, priv->mac_addr, ATBM_ETH_ALEN);
	atbm_memcpy(nulldata->addr3, bssid, ATBM_ETH_ALEN);

	
	ATBM_IEEE80211_SKB_TXCB(skb)->flags |=ATBM_IEEE80211_TX_INTFL_DONT_ENCRYPT| 
										ATBM_IEEE80211_TX_CTL_POLL_RESPONSE;
	return skb;
}
FLASH_FUNC struct atbm_buff * atbmwifi_ieee80211_QosNullData(struct atbmwifi_vif *priv,const atbm_uint8 *da,const atbm_uint8 *bssid,atbm_uint8 tid)
{
	//struct atbmwifi_common * hw_priv = priv->hw_priv;
	struct atbm_buff *skb;
	struct atbmwifi_ieee80211_qos_hdr *QosNulldata;

	skb = atbm_dev_alloc_skb(sizeof(struct atbmwifi_ieee80211_qos_hdr));
	if (!skb)
	{
		wifi_printk(WIFI_TX,"<ERROR> send_auth alloc skb \n");
		return ATBM_NULL;
	}
	
	QosNulldata = (struct atbmwifi_ieee80211_qos_hdr *) atbm_skb_put(skb, 26);
	atbm_memset(QosNulldata, 0, 26);
	QosNulldata->frame_control = atbm_cpu_to_le16(ATBM_IEEE80211_FTYPE_DATA|
					  ATBM_IEEE80211_STYPE_QOS_NULLFUNC);
	atbm_memcpy(QosNulldata->addr1, da, ATBM_ETH_ALEN);
	atbm_memcpy(QosNulldata->addr2, priv->mac_addr, ATBM_ETH_ALEN);
	atbm_memcpy(QosNulldata->addr3, bssid, ATBM_ETH_ALEN);
	QosNulldata->qos_ctrl = tid;
	QosNulldata->qos_ctrl |=
		atbm_cpu_to_le16(ATBM_IEEE80211_QOS_CTL_EOSP);
	ATBM_IEEE80211_SKB_TXCB(skb)->flags |= ATBM_IEEE80211_TX_INTFL_DONT_ENCRYPT|
										ATBM_IEEE80211_TX_STATUS_EOSP;
	return skb;
}
#endif

