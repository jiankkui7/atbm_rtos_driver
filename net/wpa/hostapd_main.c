/**************************************************************************************************************
 * altobeam RTOS WSM host interface (HI) implementation
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/



/*
#define WLAN_FC_GET_STYPE(fc) (fc & ATBM_IEEE80211_FCTL_STYPE)
#define WLAN_FC_STYPE_BEACON IEEE80211_STYPE_BEACON
#define WLAN_FC_STYPE_ACTION IEEE80211_STYPE_ACTION
#define WLAN_FC_STYPE_AUTH ATBM_IEEE80211_STYPE_AUTH
#define WLAN_FC_STYPE_ASSOC_REQ ATBM_IEEE80211_STYPE_ASSOC_REQ
*/
#include "atbm_hal.h"
#include "atbm_sha1.h"

#ifdef CONFIG_WPS
#include "includes.h"
#endif

static atbm_uint32 dot11RSNAConfigPairwiseUpdateCount = 4;
static atbm_uint32 dot11RSNAConfigGroupUpdateCount = 4;
struct hostapd_data *g_hostapd;


atbm_void __wpa_send_eapol(struct atbmwifi_cfg *config,
		      struct atbmwifi_wpa_state_machine *sm, int key_info,
		      const atbm_uint8 *key_rsc, const atbm_uint8 *nonce,
		      const atbm_uint8 *kde, atbm_size_t kde_len,
		      int keyidx, int encr, int force_version);
int hostapd_eapol_init(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm);
static atbm_void hostapd_4_way_handshake_err(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm);
atbm_void hostapd_4_way_handshake_start(atbm_void *data1,atbm_void *data2);
atbm_void hostapd_link_sta_sm(struct atbmwifi_vif *priv, struct atbmwifi_sta_priv *sta_priv,atbm_uint8* mac);

#ifdef CONFIG_WPS
atbm_void hostapd_wps_handshake_process(struct atbmwifi_vif *priv, struct hostapd_sta_info *sta,
							struct atbmwifi_ieee802_1x_hdr *hdr, atbm_uint16 datalen)
{
	struct hostapd_data *hostapd = (struct hostapd_data *)priv->appdata;

	wpabuf_free(hostapd->wps_last_rx_data);
	hostapd->wps_last_rx_data = wpabuf_alloc_copy(hdr, datalen + sizeof(*hdr));
	if(hostapd->wps_last_rx_data == ATBM_NULL){
		wpa_printf(MSG_ERROR, "wps_handshake_process alloc_copy failed");
		return;
	}

	hostapd_run(priv,sta);
}
#endif

struct atbmwifi_vif *wpa_sm_get_priv(struct atbmwifi_wpa_state_machine *sm)
{
	struct atbmwifi_wpa_group *group = sm->group;
	struct hostapd_data *hostapd = atbm_container_of(group,struct hostapd_data,group);
	
	return hostapd->priv;
}

static atbm_void wpa_send_eapol_timeout(atbm_void *data1,atbm_void *data2)
{
	struct atbmwifi_wpa_state_machine *sm = (struct atbmwifi_wpa_state_machine *)data1;
	struct atbmwifi_vif *priv = wpa_sm_get_priv(sm);

	hostapd_4_way_handshake_err(priv,sm);
	
}

	
atbm_size_t merge_byte_arrays(atbm_uint8 *res, atbm_size_t res_len,
			 const atbm_uint8 *src1, atbm_size_t src1_len,
			 const atbm_uint8 *src2, atbm_size_t src2_len)
{
	atbm_size_t len = 0;

	atbm_memset(res, 0, res_len);

	if (src1) {
		if (src1_len >= res_len) {
			atbm_memcpy(res, src1, res_len);
			return res_len;
		}

		atbm_memcpy(res, src1, src1_len);
		len += src1_len;
	}

	if (src2) {
		if (len + src2_len >= res_len) {
			atbm_memcpy(res + len, src2, res_len - len);
			return res_len;
		}

		atbm_memcpy(res + len, src2, src2_len);
		len += src2_len;
	}

	return len;
}
static atbm_void wpa_send_eapol(struct atbmwifi_cfg *config,
			   struct atbmwifi_wpa_state_machine *sm, int key_info,
			   const atbm_uint8 *key_rsc, const atbm_uint8 *nonce,
			   const atbm_uint8 *kde, atbm_size_t kde_len,
			   int keyidx, int encr)
{
//	int timeout_ms;
	int pairwise = key_info & ATBM_WPA_KEY_INFO_KEY_TYPE;
	int ctr;

	if (sm == ATBM_NULL)
		return;

	__wpa_send_eapol(config, sm, key_info, key_rsc, nonce, kde, kde_len,
			 keyidx, encr, 0);

	ctr = pairwise ? sm->TimeoutCtr : sm->GTimeoutCtr;


	if (pairwise && ctr == 1 && !(key_info & ATBM_WPA_KEY_INFO_MIC))
		sm->pending_1_of_4_timeout = 1;
	
	eloop_cancel_timeout(wpa_send_eapol_timeout, (atbm_void *)sm, ATBM_NULL);
	eloop_register_timeout(WPA_SEND_EAPOL_TIMEOUT, 0,
			       wpa_send_eapol_timeout, (atbm_void *)sm, ATBM_NULL);
}

static  int wpa_gmk_to_gtk(const atbm_uint8 *gmk, const char *label, const atbm_uint8 *addr,
			  const atbm_uint8 *gnonce, atbm_uint8 *gtk, atbm_size_t gtk_len)
{
	atbm_uint8 data[ATBM_ETH_ALEN + ATBM_WPA_NONCE_LEN + 8 + 16];
	atbm_uint8 *pos;
	int ret = 0;

	/* GTK = PRF-X(GMK, "Group key expansion",
	 *	AA || GNonce || Time || atbm_os_random data)
	 * The example described in the IEEE 802.11 standard uses only AA and
	 * GNonce as inputs here. Add some more entropy since this derivation
	 * is done only at the Authenticator and as such, does not need to be
	 * exactly same.
	 */
	atbm_memcpy(data, addr, ATBM_ETH_ALEN);
	atbm_memcpy(data + ATBM_ETH_ALEN, gnonce, ATBM_WPA_NONCE_LEN);
	pos = data + ATBM_ETH_ALEN + ATBM_WPA_NONCE_LEN;
//	wpa_get_ntp_timestamp(pos);
	pos += 8;
	if (os_get_random(pos, 16) < 0)
		ret = -1;

#ifdef CONFIG_IEEE80211W
	sha256_prf(gmk, ATBM_WPA_GMK_LEN, label, data, sizeof(data), gtk, gtk_len);
#else /* CONFIG_IEEE80211W */
	if (atbm_sha1_prf(gmk, ATBM_WPA_GMK_LEN, label, data, sizeof(data), gtk, gtk_len)
	    < 0)
		ret = -1;
#endif /* CONFIG_IEEE80211W */

	return ret;
}

static int wpa_gtk_update(struct atbmwifi_cfg *config,
			  struct atbmwifi_wpa_group *group)
{
	int ret = 0;

	atbm_memcpy(group->GNonce, group->Counter, ATBM_WPA_NONCE_LEN);
	inc_byte_array(group->Counter, ATBM_WPA_NONCE_LEN);
	if (wpa_gmk_to_gtk(group->GMK, "Group key expansion",
			   config->bssid, group->GNonce,
			   group->GTK[group->GN - 1], group->GTK_len) < 0)
		ret = -1;
/*
	wpa_hexdump_key(MSG_DEBUG, "GTK",
			group->GTK[group->GN - 1], group->GTK_len);
*/
#ifdef CONFIG_IEEE80211W
	if (wpa_auth->conf.atbmwifi_ieee80211w != ATBM_NO_MGMT_FRAME_PROTECTION) {
		atbm_memcpy(group->GNonce, group->Counter, ATBM_WPA_NONCE_LEN);
		inc_byte_array(group->Counter, ATBM_WPA_NONCE_LEN);
		if (wpa_gmk_to_gtk(group->GMK, "IGTK key expansion",
				   wpa_auth->addr, group->GNonce,
				   group->IGTK[group->GN_igtk - 4],
				   WPA_IGTK_LEN) < 0)
			ret = -1;
/*
		wpa_hexdump_key(MSG_DEBUG, "IGTK",
				group->IGTK[group->GN_igtk - 4], WPA_IGTK_LEN);
*/
	}
#endif /* CONFIG_IEEE80211W */

	return ret;
}

static  atbm_void wpa_group_gtk_init(struct atbmwifi_cfg *config,
			       struct atbmwifi_wpa_group *group)
{
#if 0
	wpa_printf(MSG_DEBUG, "WPA: group state machine entering state "
		   "GTK_INIT (VLAN-ID %d)", group->vlan_id);
#endif
	group->changed = ATBM_FALSE; /* GInit is not cleared here; avoid loop */
	group->wpa_group_state = ATBM_WPA_GROUP_GTK_INIT;

	/* GTK[0..N] = 0 */
	atbm_memset(group->GTK, 0, sizeof(group->GTK));
	group->GN = 1;
	group->GM = 2;
#ifdef CONFIG_IEEE80211W
	group->GN_igtk = 4;
	group->GM_igtk = 5;
#endif /* CONFIG_IEEE80211W */
	/* GTK[GN] = CalcGTK() */
	wpa_gtk_update(config, group);
}

static int wpa_group_init_gmk_and_counter(struct atbmwifi_cfg *config,
					  struct atbmwifi_wpa_group *group)
{
#define RKEY_LEN 32
#define RBUF_LEN (ATBM_ETH_ALEN + 8 + sizeof(group))
	//atbm_uint8 buf[ATBM_ETH_ALEN + 8 + sizeof(group)];
	//atbm_uint8 rkey[32];
	int ret =0;
	atbm_uint8 * buf =atbm_kmalloc(RBUF_LEN/*buf*/+RKEY_LEN/*rkey*/,GFP_KERNEL);
	atbm_uint8 * rkey = &buf[RBUF_LEN];
	
	if (os_get_random(group->GMK, ATBM_WPA_GMK_LEN) < 0)		{
			ret= -1;
			goto __ret ;
	}

	/*
	 * Counter = PRF-256(Random number, "Init Counter",
	 *                   Local MAC Address || Time)
	 */
	atbm_memcpy(buf, config->bssid, ATBM_ETH_ALEN);

	atbm_memcpy(buf + ATBM_ETH_ALEN + 8, &group, sizeof(group));
	if (os_get_random(rkey, RKEY_LEN) < 0){
		ret= -1;
		goto __ret ;
	}

	if (atbm_sha1_prf(rkey, RKEY_LEN, "Init Counter", buf, RBUF_LEN,
		     group->Counter, ATBM_WPA_NONCE_LEN) < 0)
		ret= -1;


__ret:
	atbm_kfree(buf);
	return ret;
}

static  struct atbmwifi_wpa_group * wpa_group_init(struct atbmwifi_cfg *config,
											struct atbmwifi_wpa_group *group,
					 int vlan_id)
{
	if (group == ATBM_NULL)
		return ATBM_NULL;

	group->GTKAuthenticator = ATBM_TRUE;
//	group->vlan_id = vlan_id;
	group->GTK_len = wpa_commom_key_len(config->group_cipher);

	/*
	 * Set initial GMK/Counter value here. The actual values that will be
	 * used in negotiations will be set once the first station tries to
	 * connect. This allows more time for collecting additional randomness
	 * on embedded devices.
	 */
	if (wpa_group_init_gmk_and_counter(config, group) < 0) {
#if 0
		wpa_printf(MSG_ERROR, "Failed to get atbm_os_random data for WPA "
			   "initialization.");
#endif
//		wifi_printk(WIFI_DBG_MSG,"group init err\n\r");
		atbm_kfree(group);
		return ATBM_NULL;
	}

//	group->GInit = TRUE;
	
	wpa_group_gtk_init(config, group);
//	group->GInit = FALSE;
//	wpa_group_sm_step(wpa_auth, group);

	return group;
}

atbm_uint16 check_ssid(struct atbmwifi_cfg *config, 
		      const atbm_uint8 *ssid_ie, atbm_size_t ssid_ie_len)
{
	if (ssid_ie == ATBM_NULL)
		return ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;

	if (ssid_ie_len != config->ssid_len||
	    atbm_memcmp(ssid_ie, config->ssid, ssid_ie_len) != 0) {
		return ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	return ATBM_WLAN_STATUS_SUCCESS;
}
static atbm_uint16 copy_supp_rates(struct atbmwifi_cfg *config, struct hostapd_sta_info *sta,
			   struct atbmwifi_ieee802_11_elems *elems)
{
	if (!elems->supp_rates) {
		
		return ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (elems->supp_rates_len + elems->ext_supp_rates_len >
	    sizeof(sta->supported_rates)) {
		
		return ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->supported_rates_len = merge_byte_arrays(
		sta->supported_rates, sizeof(sta->supported_rates),
		elems->supp_rates, elems->supp_rates_len,
		elems->ext_supp_rates, elems->ext_supp_rates_len);

	return ATBM_WLAN_STATUS_SUCCESS;
}
struct atbmwifi_wpa_state_machine *
wpa_auth_sta_init(struct atbmwifi_cfg *config,const atbm_uint8 *addr)
{
	struct atbmwifi_wpa_state_machine *sm;

	sm = atbm_kzalloc(sizeof(struct atbmwifi_wpa_state_machine)+sizeof(struct atbmwifi_wpa_group),GFP_KERNEL);
	if (sm == ATBM_NULL)
		return ATBM_NULL;
	atbm_memcpy(sm->addr, addr, ATBM_ETH_ALEN);
	
	{
		struct atbmwifi_vif * priv =(struct atbmwifi_vif * )atbmwifi_config_get_priv(config);
		struct hostapd_data * hostapd =(struct hostapd_data *)(priv->appdata);
		sm->group = &hostapd->group;
	}
	//wpa_group_init(config,sm->group,0);
	return sm;
}
int wpa_validate_wpa_ie(struct atbmwifi_cfg *config,
			struct atbmwifi_wpa_state_machine *sm,
			const atbm_uint8 *wpa_ie, atbm_size_t wpa_ie_len)
{
	struct atbmwifi_wpa_ie_data data;
	int ciphers, key_mgmt, res, version;
//	atbm_uint32 selector;
//	atbm_size_t i;
//	const atbm_uint8 *pmkid = NULL;

	if (config == ATBM_NULL || sm == ATBM_NULL)
	{
//		wifi_printk(WIFI_DBG_INIT,"parame ATBM_FALSE(1)\n");
		return ATBM_FALSE;
	}

	if (wpa_ie == ATBM_NULL || wpa_ie_len < 1)
	{
//		wifi_printk(WIFI_DBG_INIT,"parame ATBM_FALSE(2)\n");
		return ATBM_FALSE;
	}
	if (wpa_ie[0] == ATBM_WLAN_EID_RSN)
		version = ATBM_WPA_PROTO_RSN;
	else
		version = ATBM_WPA_PROTO_WPA;

	if (!(config->wpa& version)) {
//		wifi_printk(WIFI_DBG_INIT,"version ATBM_FALSE(%d)\n",version);
		return ATBM_FALSE;
	}

	if (version == ATBM_WPA_PROTO_RSN) 
	{
		res = atbmwifi_wpa_parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, &data);
	} else 
	{
		
		if((res = wpa_parse_wpa_ie_wpa(wpa_ie, wpa_ie_len, &data))<0)
		{
//			wifi_printk(WIFI_DBG_INIT,"data ie ATBM_FALSE\n");
			return ATBM_FALSE;
		}
	}
	if (res<0) 
	{
#ifdef LINUX_DEBUG

		wpa_printf(MSG_DEBUG, "Failed to parse WPA/RSN IE from "
			   MACSTR " (res=%d)", MAC2STR(sm->addr), res);
		wpa_hexdump(MSG_DEBUG, "WPA/RSN IE", wpa_ie, wpa_ie_len);
#endif
//		wifi_printk(WIFI_DBG_INIT,"pase ie ATBM_FALSE\n");
		return ATBM_FALSE;
	}

	if (data.group_cipher != config->group_cipher)
	{
#ifdef LINUX_DEBUG

		wpa_printf(MSG_DEBUG, "Invalid WPA group cipher (0x%x) from "
			   MACSTR, data.group_cipher, MAC2STR(sm->addr));
#endif
//		wifi_printk(WIFI_DBG_INIT,"g ATBM_FALSE\n");
		return ATBM_FALSE;
	}

	key_mgmt = data.key_mgmt & config->key_mgmt;
	
	if (!key_mgmt)
	{
#ifdef LINUX_DEBUG

		wpa_printf(MSG_DEBUG, "Invalid WPA key mgmt (0x%x) from "
			   MACSTR, data.key_mgmt, MAC2STR(sm->addr));
#endif
		wifi_printk(WIFI_DBG_INIT,"k ATBM_FALSE\n");
		return ATBM_FALSE;
	}


	
	if (key_mgmt & ATBM_WPA_KEY_MGMT_IEEE8021X)
		sm->wpa_key_mgmt =ATBM_WPA_KEY_MGMT_IEEE8021X;
	else
		sm->wpa_key_mgmt = ATBM_WPA_KEY_MGMT_PSK;

	ciphers = data.pairwise_cipher & config->pairwise_cipher;
	
	if (!ciphers) 
	{
#ifdef LINUX_DEBUG

		wpa_printf(MSG_DEBUG, "Invalid %s pairwise cipher (0x%x) "
			   "from " MACSTR,
			   version == ATBM_WPA_PROTO_RSN ? "RSN" : "WPA",
			   data.pairwise_cipher, MAC2STR(sm->addr));
#endif
//		wifi_printk(WIFI_DBG_INIT,"p ATBM_FALSE\n");
		return ATBM_FALSE;
	}



#ifdef CONFIG_IEEE80211W

	if (data.mgmt_group_cipher != ATBM_WPA_CIPHER_AES_128_CMAC)
	{
#ifdef LINUX_DEBUG

		wpa_printf(MSG_DEBUG, "Unsupported management group "
			   "cipher %d", data.mgmt_group_cipher);
#endif

		return ATBM_FALSE;
	}
#endif
	if (!(data.capabilities & ATBM_WPA_CAPABILITY_MFPC))
		sm->mgmt_frame_prot = 0;
	else
		sm->mgmt_frame_prot = 1;


	if (ciphers & ATBM_WPA_CIPHER_CCMP)
		sm->pairwise = ATBM_WPA_CIPHER_CCMP;
	else if (ciphers & ATBM_WPA_CIPHER_GCMP)
		sm->pairwise = ATBM_WPA_CIPHER_GCMP;
	else
		sm->pairwise = ATBM_WPA_CIPHER_TKIP;

	/* TODO: clear WPA/WPA2 state if STA changes from one to another */
	if (wpa_ie[0] == ATBM_WLAN_EID_RSN)
		sm->wpa = ATBM_WPA_VERSION_WPA2;
	else
		sm->wpa = ATBM_WPA_VERSION_WPA;
	
	if (sm->wpa_ie == ATBM_NULL || sm->wpa_ie_len < wpa_ie_len) {
		atbm_kfree(sm->wpa_ie);
		sm->wpa_ie = atbm_kmalloc(wpa_ie_len,GFP_KERNEL);
		if (sm->wpa_ie == ATBM_NULL)
		{
//			wifi_printk(WIFI_DBG_INIT,"sm ie ATBM_FALSE\n");
			return ATBM_FALSE;
		}
	}
	atbm_memcpy(sm->wpa_ie, wpa_ie, wpa_ie_len);
	sm->wpa_ie_len = wpa_ie_len;

	return ATBM_TRUE;
}

atbm_void wpa_auth_sta_no_wpa(struct atbmwifi_wpa_state_machine *sm)
{
	/* WPA/RSN was not used - clear WPA state. This is needed if the STA
	 * reassociates back to the same AP while the previous entry for the
	 * STA has not yet been removed. */
	if (sm == ATBM_NULL)
		return;

	sm->wpa_key_mgmt = 0;
}

static atbm_uint16 check_assoc_ies(struct atbmwifi_cfg *config, struct hostapd_sta_info *sta,
			   struct atbmwifi_ieee802_11_elems *elems, int reassoc)
{
	atbm_uint16 resp;
	const atbm_uint8 *wpa_ie;
	atbm_size_t wpa_ie_len;
#ifdef CONFIG_WPS
	struct atbmwifi_vif *priv = atbmwifi_config_get_priv(config);
#endif

	resp = check_ssid(config,  elems->ssid, elems->ssid_len);
	if (resp != ATBM_WLAN_STATUS_SUCCESS)
		return resp;
	resp = copy_supp_rates(config, sta, elems);
	if (resp != ATBM_WLAN_STATUS_SUCCESS){
		
		return resp;
	}
	if ((config->wpa & ATBM_WPA_PROTO_RSN) && elems->rsn) {
		wpa_ie = elems->rsn;
		wpa_ie_len = elems->rsn_len;
	} else if ((config->wpa & ATBM_WPA_PROTO_WPA) &&
		   elems->wpa) {
		wpa_ie = elems->wpa;
		wpa_ie_len = elems->wpa_len;
	} else {
		wpa_ie = ATBM_NULL;
		wpa_ie_len = 0;
	}
//	wifi_printk(WIFI_DBG_INIT,"check_ie:wpa_ie_len(%d)\n",wpa_ie_len);
#ifdef CONFIG_WPS
	if((priv->pbc || priv->pin) && (elems->wps_ie)){
		wpa_ie = ATBM_NULL;
		wpa_ie_len = 0;
	}else
#endif
	if (config->wpa && wpa_ie == ATBM_NULL) {
		return ATBM_WLAN_STATUS_INVALID_IE;
	}

	if (config->wpa && wpa_ie) {
		int res;
		wpa_ie -= 2;
		wpa_ie_len += 2;
		if (sta->atbmwifi_wpa_sm == ATBM_NULL)
			sta->atbmwifi_wpa_sm = wpa_auth_sta_init(config,
							sta->addr);
		if (sta->atbmwifi_wpa_sm == ATBM_NULL) {
			
			return ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
		}
		res = wpa_validate_wpa_ie(config, sta->atbmwifi_wpa_sm,
					  wpa_ie, wpa_ie_len);
		if (res == ATBM_FALSE)
		{
			resp = ATBM_WLAN_STATUS_INVALID_IE;
		}
		else
		{
			resp = ATBM_WLAN_STATUS_SUCCESS;
		}
		if (resp != ATBM_WLAN_STATUS_SUCCESS)
			return resp;

#ifdef CONFIG_IEEE80211N
		if ((sta->flags & (WLAN_STA_HT | WLAN_STA_VHT)) &&
		    sta->atbmwifi_wpa_sm->pairwise == ATBM_WPA_CIPHER_TKIP) {
			return ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
		}
#endif /* CONFIG_IEEE80211N */
	} 
	else{
	
		//wifi_printk(WIFI_DBG_MSG,"[ap]:%s %d\n",__FUNCTION__,__LINE__);
		wpa_auth_sta_no_wpa(sta->atbmwifi_wpa_sm);
	}
	return ATBM_WLAN_STATUS_SUCCESS;
}

atbm_uint8 * wpa_add_kde(atbm_uint8 *pos, atbm_uint32 kde, const atbm_uint8 *data, atbm_size_t data_len,
		 const atbm_uint8 *data2, atbm_size_t data2_len)
{
	*pos++ = ATBM_WLAN_EID_VENDOR_SPECIFIC;
	*pos++ = ATBM_RSN_SELECTOR_LEN + data_len + data2_len;
	ATBM_RSN_SELECTOR_PUT(pos, kde);
	pos += ATBM_RSN_SELECTOR_LEN;
	atbm_memcpy(pos, data, data_len);
	pos += data_len;
	if (data2) {
		atbm_memcpy(pos, data2, data2_len);
		pos += data2_len;
	}
	return pos;
}
static int atbmwifi_ieee80211w_kde_len(struct atbmwifi_wpa_state_machine *sm)
{
	return 0;
}


static atbm_uint8 * atbmwifi_ieee80211w_kde_add(struct atbmwifi_wpa_state_machine *sm, atbm_uint8 *pos)
{
	return pos;
}
static int wpa_verify_key_mic(struct atbmwifi_wpa_ptk *PTK, atbm_uint8 *data, atbm_size_t data_len)
{
	struct atbmwifi_ieee802_1x_hdr *hdr;
	struct atbmwifi_wpa_eapol_key *key;
	atbm_uint16 key_info;
	int ret = 0;
	atbm_uint8 mic[16];

	if (data_len < sizeof(*hdr) + sizeof(*key))
	{
//		wifi_printk(WIFI_DBG_MSG,"ptk len err \n\r");
		return -1;
	}
	hdr = (struct atbmwifi_ieee802_1x_hdr *) data;
	key = (struct atbmwifi_wpa_eapol_key *) (hdr + 1);
	key_info = ATBM_WPA_GET_BE16(key->key_info);
	atbm_memset(mic,0,16);
	atbm_memcpy(mic, key->key_mic, 16);
	atbm_memset(key->key_mic, 0, 16);
#if 0
	wifi_printk(WIFI_DBG_MSG, "wpa kck mic:mic[1](%x),mic[5](%x),mic[10](%x),mic[15](%x)\n"
			   ,mic[1],mic[5],mic[10],mic[15]);
#endif
	if (wpa_eapol_key_mic(PTK->kck, key_info & ATBM_WPA_KEY_INFO_TYPE_MASK,
			      data, data_len, key->key_mic) ||
	    atbm_memcmp(mic, key->key_mic, 16) != 0)
		ret = -1;
#if 0
	wifi_printk(WIFI_DBG_MSG, "wpa kck mic:mic[1](%x),mic[5](%x),mic[10](%x),mic[15](%x)\n"
			   ,key->key_mic[1],key->key_mic[5],key->key_mic[10],key->key_mic[15]);
#endif
	atbm_memcpy(key->key_mic, mic, 16);
	return ret;
}

/**
 * wpa_parse_kde_ies - Parse EAPOL-Key Key Data IEs
 * @buf: Pointer to the Key Data buffer
 * @len: Key Data Length
 * @ie: Pointer to parsed IE data
 * Returns: 0 on success, -1 on failure
 */
int wpa_parse_kde_ies(const atbm_uint8 *buf, atbm_size_t len, struct wpa_eapol_ie_parse *ie)
{
	const atbm_uint8 *pos, *end;
	int ret = 0;

	atbm_memset(ie, 0, sizeof(*ie));
	for (pos = buf, end = pos + len; pos + 1 < end; pos += 2 + pos[1]) {
		if (pos[0] == 0xdd &&
		    ((pos == buf + len - 1) || pos[1] == 0)) {
			/* Ignore padding */
			break;
		}
		if (pos + 2 + pos[1] > end) {
#if 0
			wpa_printf(MSG_DEBUG, "WPA: EAPOL-Key Key Data "
				   "underflow (ie=%d len=%d pos=%d)",
				   pos[0], pos[1], (int) (pos - buf));
			wpa_hexdump_key(MSG_DEBUG, "WPA: Key Data",
					buf, len);
#endif
			ret = -1;
			break;
		}
		if (*pos == ATBM_WLAN_EID_RSN) {
			ie->rsn_ie = pos;
			ie->rsn_ie_len = pos[1] + 2;
#ifdef CONFIG_IEEE80211R
		} else if (*pos == ATBM_WLAN_EID_MOBILITY_DOMAIN) {
			ie->mdie = pos;
			ie->mdie_len = pos[1] + 2;
		} else if (*pos == ATBM_WLAN_EID_FAST_BSS_TRANSITION) {
			ie->ftie = pos;
			ie->ftie_len = pos[1] + 2;
#endif /* CONFIG_IEEE80211R */
		} else if (*pos == ATBM_WLAN_EID_VENDOR_SPECIFIC) {
			ret = wpa_parse_generic(pos, end, ie);
			if (ret < 0)
				break;
			if (ret > 0) {
				ret = 0;
				break;
			}
		} else {
#if 0
			wpa_hexdump(MSG_DEBUG, "WPA: Unrecognized EAPOL-Key "
				    "Key Data IE", pos, 2 + pos[1]);
#endif
		}
	}

	return ret;
}

static int wpa_replay_counter_valid(struct atbmwifi_wpa_key_replay_counter *ctr,
				    const atbm_uint8 *replay_counter)
{
	int i;
	for (i = 0; i < RSNA_MAX_EAPOL_RETRIES; i++) {
		if (!ctr[i].valid)
			break;
		if (atbm_memcmp(replay_counter, ctr[i].counter,
			      ATBM_WPA_REPLAY_COUNTER_LEN) == 0)
			return 1;
	}
	return 0;
}
static atbm_void wpa_replay_counter_mark_invalid(struct atbmwifi_wpa_key_replay_counter *ctr,
					    const atbm_uint8 *replay_counter)
{
	int i;
	for (i = 0; i < RSNA_MAX_EAPOL_RETRIES; i++) {
		if (ctr[i].valid &&
		    (replay_counter == ATBM_NULL ||
		     atbm_memcmp(replay_counter, ctr[i].counter,
			       ATBM_WPA_REPLAY_COUNTER_LEN) == 0))
			ctr[i].valid = ATBM_FALSE;
	}
}

static int wpa_use_aes_cmac(struct atbmwifi_wpa_state_machine *sm)
{
	int ret = 0;
#ifdef CONFIG_IEEE80211R
	if (atbmwifi_wpa_key_mgmt_ft(sm->wpa_key_mgmt))
		ret = 1;
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_IEEE80211W
	if (atbmwifi_wpa_key_mgmt_sha256(sm->wpa_key_mgmt))
		ret = 1;
#endif /* CONFIG_IEEE80211W */
	return ret;
}
static int wpa_derive_ptk(struct atbmwifi_cfg *config,struct atbmwifi_wpa_state_machine *sm, const atbm_uint8 *pmk,
			  struct atbmwifi_wpa_ptk *ptk)
{
	atbm_size_t ptk_len = sm->pairwise != ATBM_WPA_CIPHER_TKIP ? 48 : 64;
#ifdef CONFIG_IEEE80211R
	if (atbmwifi_wpa_key_mgmt_ft(sm->wpa_key_mgmt))
		return wpa_auth_derive_ptk_ft(sm, pmk, ptk, ptk_len);
#endif /* CONFIG_IEEE80211R */
/*
	wpa_pmk_to_ptk(pmk, ATBM_PMK_LEN, "Pairwise key expansion",
		       config->bssid, sm->addr, sm->ANonce, sm->SNonce,
		       (atbm_uint8 *) ptk, ptk_len,
		       atbmwifi_wpa_key_mgmt_sha256(sm->wpa_key_mgmt));
*/	
	wpa_pmk_to_ptk(pmk, ATBM_PMK_LEN, "Pairwise key expansion",
				   config->bssid, sm->addr, sm->ANonce, sm->SNonce,
				   (atbm_uint8 *) ptk, ptk_len,
				   atbmwifi_wpa_key_mgmt_sha256(sm->wpa_key_mgmt));

	return 0;
}
static int hostapd_prepare_pmk(struct atbmwifi_cfg *config,struct atbmwifi_wpa_state_machine *sm)
{
	struct atbmwifi_wpa_ptk PTK;
	int ok = 0;
	const atbm_uint8 *pmk = ATBM_NULL;

	sm->EAPOLKeyReceived = ATBM_FALSE;
	sm->update_snonce = ATBM_FALSE;

	/* WPA with IEEE 802.1X: use the derived PMK from EAP
	 * WPA-PSK: iterate through possible PSKs and select the one matching
	 * the packet */
	for (;;) {
		if (atbmwifi_wpa_key_mgmt_wpa_psk(sm->wpa_key_mgmt)) {
			
			if(config->psk_set == 1)
				pmk = config->psk;
			if (pmk == ATBM_NULL)
				break;
		} else//if atbmwifi_ieee80211X or WPS or 802.11r
			pmk = sm->PMK;
#if 0
		wifi_printk(WIFI_DBG_MSG, "pmk[0](%d),pmk[10](%d),pmk[16](%d),pmk[20](%d)\n"
							  "pmk[25](%d),pmk[28](%d),pmk[30](%d),pmk[31](%d)\n",
							  pmk[0],pmk[10],pmk[16],pmk[20],
							  pmk[25],pmk[28],pmk[30],pmk[31]);
#endif

		wpa_derive_ptk(config,sm, pmk, &PTK);
		
//		wifi_printk(WIFI_DBG_MSG,"ptk over \n\r");

		if (wpa_verify_key_mic(&PTK, sm->last_rx_eapol_key,
				       sm->last_rx_eapol_key_len) == 0) {
			ok = 1;
			break;
		}
#if 0
		wifi_printk(WIFI_DBG_MSG, "wpa kck:kck[1](%x),kck[5](%x),kck[10](%x),kck[15](%x)\n"
			   ,PTK.kck[1],PTK.kck[5],PTK.kck[10],PTK.kck[15]);
#endif
		if (!atbmwifi_wpa_key_mgmt_wpa_psk(sm->wpa_key_mgmt))
			break;

		return -1;
	}

	if (!ok) {

		wifi_printk(WIFI_DBG_MSG,"mic err \n\r");
		return -1;
	}

#ifdef CONFIG_IEEE80211R
	if (sm->wpa == ATBM_WPA_VERSION_WPA2 && atbmwifi_wpa_key_mgmt_ft(sm->wpa_key_mgmt)) {
		/*
		 * Verify that PMKR1Name from EAPOL-Key message 2/4 matches
		 * with the value we derived.
		 */
		if (atbm_memcmp(sm->sup_pmk_r1_name, sm->pmk_r1_name,
			      ATBM_WPA_PMK_NAME_LEN) != 0) {
			wpa_auth_logger(sm->wpa_auth, sm->addr, LOGGER_DEBUG,
					"PMKR1Name mismatch in FT 4-way "
					"handshake");
			wpa_hexdump(MSG_DEBUG, "FT: PMKR1Name from "
				    "Supplicant",
				    sm->sup_pmk_r1_name, ATBM_WPA_PMK_NAME_LEN);
			wpa_hexdump(MSG_DEBUG, "FT: Derived PMKR1Name",
				    sm->pmk_r1_name, ATBM_WPA_PMK_NAME_LEN);
			return;
		}
	}
#endif /* CONFIG_IEEE80211R */

	sm->pending_1_of_4_timeout = 0;

	if (atbmwifi_wpa_key_mgmt_wpa_psk(sm->wpa_key_mgmt)) {
		/* PSK may have changed from the previous choice, so update
		 * state machine data based on whatever PSK was selected here.
		 */
		atbm_memcpy(sm->PMK, pmk, ATBM_PMK_LEN);
	}

	sm->MICVerified = ATBM_TRUE;
	//wifi_printk(WIFI_DBG_MSG,"MIC TRUE\n\r");
	atbm_memcpy(&sm->PTK, &PTK, sizeof(PTK));
	sm->PTK_valid = ATBM_TRUE;
	eloop_cancel_timeout(wpa_send_eapol_timeout,(atbm_void *)sm,ATBM_NULL);
//	sm->TimeoutCtr = 0;	
	
	return 0;
}
static int hostapd_send_4_of_3_msg(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	atbm_uint8 rsc[ATBM_WPA_KEY_RSC_LEN], *_rsc, *gtk, *kde, *pos, dummy_gtk[32];
	atbm_size_t gtk_len, kde_len;
	struct atbmwifi_wpa_group *gsm = sm->group;
	atbm_uint8 *wpa_ie;
	int wpa_ie_len, secure, keyidx, encr = 0;
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	
	sm->TimeoutCtr++;
	sm->TimeoutEvt = ATBM_FALSE;
	if(hostapd_prepare_pmk(config,sm)<0)
	{
		wifi_printk(WIFI_DBG_MSG,"hostapd_pmk err\n\r");
		return -1;
	}
	
//	wifi_printk(WIFI_DBG_MSG,"TC(%d)\n\r",sm->TimeoutCtr);
	if (sm->TimeoutCtr > (int) dot11RSNAConfigPairwiseUpdateCount) {
		/* No point in sending the EAPOL-Key - we will disconnect
		 * immediately following this. */
		wifi_printk(WIFI_DBG_MSG,"hostap tx 3/4 Timeout err\n\r");
		return -1;
	}
	/* Send EAPOL(1, 1, 1, Pair, P, RSC, ANonce, MIC(PTK), RSNIE, [MDIE],
	   GTK[GN], IGTK, [FTIE], [TIE * 2])
	 */
	atbm_memset(rsc, 0, ATBM_WPA_KEY_RSC_LEN);
	/* If FT is used, wpa_auth->wpa_ie includes both RSNIE and MDIE */
	/*
	wpa_ie = sm->wpa_auth->wpa_ie;
	wpa_ie_len = sm->wpa_auth->wpa_ie_len;
	*/
	wpa_ie = priv->bss.information_elements;
	wpa_ie_len = priv->bss.len_information_elements;
	if (sm->wpa == ATBM_WPA_VERSION_WPA &&
	    (config->wpa & ATBM_WPA_PROTO_RSN) &&
	    wpa_ie_len > wpa_ie[1] + 2 && wpa_ie[0] == ATBM_WLAN_EID_RSN) {
		/* WPA-only STA, remove RSN IE */
		wpa_ie = wpa_ie + wpa_ie[1] + 2;
		wpa_ie_len = wpa_ie[1] + 2;
	}

	if (sm->wpa == ATBM_WPA_VERSION_WPA2) {
		/* WPA2 send GTK in the 4-way handshake */
		secure = 1;
		gtk = gsm->GTK[gsm->GN - 1];
		gtk_len = gsm->GTK_len;
		if (0) {
			/*
			 * Provide unique atbm_os_random GTK to each STA to prevent use
			 * of GTK in the BSS.
			 */
			if (os_get_random(dummy_gtk, gtk_len) < 0)
				return -1;
			gtk = dummy_gtk;
		}
		keyidx = gsm->GN;
		_rsc = rsc;
		encr = 1;
	} else {
		/* WPA does not include GTK in msg 3/4 */
		secure = 0;
		gtk = ATBM_NULL;
		gtk_len = 0;
		keyidx = 0;
		_rsc = ATBM_NULL;
	}
	kde_len = wpa_ie_len + atbmwifi_ieee80211w_kde_len(sm);
	if (gtk)
		kde_len += 2 + ATBM_RSN_SELECTOR_LEN + 2 + gtk_len;

	kde = atbm_kmalloc(kde_len,GFP_KERNEL);
	if (kde == ATBM_NULL)
	{
		wifi_printk(WIFI_DBG_MSG,"kde err\n\r");
		return -1;
	}

	pos = kde;
	atbm_memcpy(pos, wpa_ie, wpa_ie_len);
	pos += wpa_ie_len;

	if (gtk) {
		atbm_uint8 hdr[2];
		hdr[0] = keyidx & 0x03;
		hdr[1] = 0;
		pos = wpa_add_kde(pos, ATBM_RSN_KEY_DATA_GROUPKEY, hdr, 2,
				  gtk, gtk_len);
	}
	pos = atbmwifi_ieee80211w_kde_add(sm, pos);


	wifi_printk(WIFI_DBG_MSG,"ie len(%d),kde len(%d)\n",wpa_ie_len,pos - kde);
	wpa_send_eapol(config, sm,
		       (secure ? ATBM_WPA_KEY_INFO_SECURE : 0) | ATBM_WPA_KEY_INFO_MIC |
		       ATBM_WPA_KEY_INFO_ACK | ATBM_WPA_KEY_INFO_INSTALL |
		       ATBM_WPA_KEY_INFO_KEY_TYPE,
		       _rsc, sm->ANonce, kde, pos - kde, keyidx, encr);
	atbm_kfree(kde);
	wifi_printk(WIFI_DBG_MSG,"hostapd 3/4\n\r");
	return 0;
}
atbm_void wpa_receive(struct atbmwifi_vif *priv,
		 struct atbmwifi_wpa_state_machine *sm,
		 atbm_uint8 *data, atbm_size_t data_len)
{
	struct atbmwifi_ieee802_1x_hdr *hdr;
	struct atbmwifi_wpa_eapol_key *key;
	atbm_uint16 key_info, key_data_length;
	enum { PAIRWISE_2, PAIRWISE_4, GROUP_2, REQUEST} msg;
//	char *msgtxt;
	struct wpa_eapol_ie_parse kde;
	int ft;
	const atbm_uint8 *eapol_key_ie;
	atbm_size_t eapol_key_ie_len;
//	wifi_printk(WIFI_DBG_MSG, "wpa_receive:++\n");

	if (priv == ATBM_NULL || sm == ATBM_NULL)
		return;

	if (data_len < sizeof(*hdr) + sizeof(*key))
		return;

	hdr = (struct atbmwifi_ieee802_1x_hdr *) data;
	key = (struct atbmwifi_wpa_eapol_key *) (hdr + 1);
	key_info = ATBM_WPA_GET_BE16(key->key_info);
	key_data_length = ATBM_WPA_GET_BE16(key->key_data_length);

	if (key_data_length > data_len - sizeof(*hdr) - sizeof(*key)) {
	
		return;
	}

	if (sm->wpa == ATBM_WPA_VERSION_WPA2) {
		if (key->type == ATBM_EAPOL_KEY_TYPE_WPA) {
			/*
			 * Some deployed station implementations seem to send
			 * msg 4/4 with incorrect type value in WPA2 mode.
			 */

			wifi_printk(WIFI_DBG_MSG, "wpa_rx:wpa2\n");
		} else if (key->type != ATBM_EAPOL_KEY_TYPE_RSN) {
			wifi_printk(WIFI_DBG_MSG, "wpa_rx:rsn\n");
			return;
		}
	} else {
		if (key->type != ATBM_EAPOL_KEY_TYPE_WPA) {
			wifi_printk(WIFI_DBG_MSG, "wpa_rx:wpa\n");
			return;
		}
	}
	/* FIX: verify that the EAPOL-Key frame was encrypted if pairwise keys
	 * are set */

	if (key_info & ATBM_WPA_KEY_INFO_REQUEST) {
		msg = REQUEST;
//		msgtxt = "Request";
	} else if (!(key_info & ATBM_WPA_KEY_INFO_KEY_TYPE)) {
		msg = GROUP_2;
//		msgtxt = "2/2 Group";
	} else if (key_data_length == 0) {
		msg = PAIRWISE_4;
//		msgtxt = "4/4 Pairwise";
	} else {
		msg = PAIRWISE_2;
//		msgtxt = "2/4 Pairwise";
	}

	/* TODO: key_info type validation for PeerKey */
	if (msg == REQUEST || msg == PAIRWISE_2 || msg == PAIRWISE_4 ||
	    msg == GROUP_2) {
		atbm_uint16 ver = key_info & ATBM_WPA_KEY_INFO_TYPE_MASK;
		if (sm->pairwise == ATBM_WPA_CIPHER_CCMP ||
		    sm->pairwise == ATBM_WPA_CIPHER_GCMP) {
			if (wpa_use_aes_cmac(sm) &&
			    ver != ATBM_WPA_KEY_INFO_TYPE_AES_128_CMAC) {
			 	
				wifi_printk(WIFI_DBG_MSG,"wpa_rx :AES-128-CMAC,ERR\n\r");
				return;
			}

			if (!wpa_use_aes_cmac(sm) &&
			    ver != ATBM_WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
			 
				wifi_printk(WIFI_DBG_MSG,"wpa_rx: HMAC-SHA1-AES ERR\n\r");
				return;
			}
		}
	}

	if (key_info & ATBM_WPA_KEY_INFO_REQUEST) {
		if (sm->req_replay_counter_used &&
		    atbm_memcmp(key->replay_counter, sm->req_replay_counter,
			      ATBM_WPA_REPLAY_COUNTER_LEN) <= 0) {
		
			wifi_printk(WIFI_DBG_MSG,"wpa_rx PN err\n\r");
			return;
		}
	}

	if (!(key_info & ATBM_WPA_KEY_INFO_REQUEST) &&
	    !wpa_replay_counter_valid(sm->key_replay, key->replay_counter)) {
		int i;

		if (msg == PAIRWISE_2 &&
		    wpa_replay_counter_valid(sm->prev_key_replay,
					     key->replay_counter) &&
		    sm->wpa_ptk_state == ATBM_WPA_PTK_PTKINITNEGOTIATING &&
		    atbm_memcmp(sm->SNonce, key->key_nonce, ATBM_WPA_NONCE_LEN) != 0)
		{
			/*
			 * Some supplicant implementations (e.g., Windows XP
			 * WZC) update SNonce for each EAPOL-Key 2/4. This
			 * breaks the workaround on accepting any of the
			 * pending requests, so allow the SNonce to be updated
			 * even if we have already sent out EAPOL-Key 3/4.
			 */
		
			wifi_printk(WIFI_DBG_MSG,"wpa_receive:""STA"
						"EAPOL-Key1/4\n\r");
			sm->update_snonce = 1;
			wpa_replay_counter_mark_invalid(sm->prev_key_replay,
							key->replay_counter);
			goto continue_processing;
		}

		if (msg == PAIRWISE_2 &&
		    wpa_replay_counter_valid(sm->prev_key_replay,
					     key->replay_counter) &&
		    sm->wpa_ptk_state == ATBM_WPA_PTK_PTKINITNEGOTIATING) {
			wifi_printk(WIFI_DBG_MSG,"wpa_receive:"
						"SNonce did not change\n\r");
		} else {
		#ifdef LINUX_DEBUG
			wpa_auth_vlogger(wpa_auth, sm->addr, LOGGER_DEBUG,
					 "received EAPOL-Key %s with "
					 "unexpected replay counter", msgtxt);
		#endif
		}
		for (i = 0; i < RSNA_MAX_EAPOL_RETRIES; i++) {
			if (!sm->key_replay[i].valid)
				break;
		#ifdef LINUX_DEBUG
			wpa_hexdump(MSG_DEBUG, "pending replay counter",
				    sm->key_replay[i].counter,
				    ATBM_WPA_REPLAY_COUNTER_LEN);
		#endif
		}
#ifdef LINUX_DEBUG
		wpa_hexdump(MSG_DEBUG, "received replay counter",
			    key->replay_counter, ATBM_WPA_REPLAY_COUNTER_LEN);
#endif
		return;
	}

continue_processing:
	switch (msg) {
	case PAIRWISE_2:
		if (sm->wpa_ptk_state != ATBM_WPA_PTK_PTKSTART &&
		    sm->wpa_ptk_state != ATBM_WPA_PTK_PTKCALCNEGOTIATING &&
		    (!sm->update_snonce ||
		     sm->wpa_ptk_state != ATBM_WPA_PTK_PTKINITNEGOTIATING)) {
#if 0
			wpa_auth_vlogger(wpa_auth, sm->addr, LOGGER_INFO,
					 "received EAPOL-Key msg 2/4 in "
					 "invalid state (%d) - dropped",
					 sm->wpa_ptk_state);
#endif
			return;
		}
//		random_add_randomness(key->key_nonce, ATBM_WPA_NONCE_LEN);
		if (wpa_parse_kde_ies((atbm_uint8 *) (key + 1), key_data_length,
				      &kde) < 0) {
#if 0
			wpa_auth_vlogger(wpa_auth, sm->addr, LOGGER_INFO,
					 "received EAPOL-Key msg 2/4 with "
					 "invalid Key Data contents");
#endif		
			wifi_printk(WIFI_DBG_ERROR, "kde err\n");
			return;
		}
		if (kde.rsn_ie) {
			eapol_key_ie = kde.rsn_ie;
			eapol_key_ie_len = kde.rsn_ie_len;
		} else {
			eapol_key_ie = kde.wpa_ie;
			eapol_key_ie_len = kde.wpa_ie_len;
		}
		ft = sm->wpa == ATBM_WPA_VERSION_WPA2 &&
			atbmwifi_wpa_key_mgmt_ft(sm->wpa_key_mgmt);
		if (sm->wpa_ie == ATBM_NULL ||
		    wpa_compare_rsn_ie(ft,
				       sm->wpa_ie, sm->wpa_ie_len,
				       eapol_key_ie, eapol_key_ie_len)) {
			
			wifi_printk(WIFI_DBG_ERROR,"wpa_rx:""WPA IE not match M2/4\n");
			/* MLME-DEAUTHENTICATE.request */
//			wpa_sta_disconnect(wpa_auth, sm->addr);
			return;
		}
		break;
	case PAIRWISE_4:
		if (sm->wpa_ptk_state != ATBM_WPA_PTK_PTKINITNEGOTIATING ||
		    !sm->PTK_valid) {
 			wifi_printk(WIFI_DBG_MSG,"wpa_rx:invalid state (%d) - dropped\n\r", sm->wpa_ptk_state);
			return;
		}
		break;
	case GROUP_2:
		if (sm->wpa_ptk_group_state != ATBM_WPA_PTK_GROUP_REKEYNEGOTIATING
		    || !sm->PTK_valid) {
			wifi_printk(WIFI_DBG_ERROR, "wpa_rx:groop 2 err\n\r");
			return;
		}
		break;
	case REQUEST:
		break;
	}
//	wifi_printk(WIFI_DBG_MSG,"received EAPOL-Key frame(%s)\n\r",msgtxt);

	if (key_info & ATBM_WPA_KEY_INFO_ACK) {		
		wifi_printk(WIFI_DBG_ERROR,"wpa_receive:Key Ack set\n\r");
		return;
	}

	if (!(key_info & ATBM_WPA_KEY_INFO_MIC)) {		
 		wifi_printk(WIFI_DBG_ERROR,"wpa:Key MIC not set\n\r");
		return;
	}

	sm->MICVerified = ATBM_FALSE;
	if (sm->PTK_valid && !sm->update_snonce) {
		if (wpa_verify_key_mic(&sm->PTK, data, data_len)) {
			wifi_printk(WIFI_DBG_ERROR,"wpa_receive:MIC err(1)\n\r");
			return;
		}
		sm->MICVerified = ATBM_TRUE;


		eloop_cancel_timeout(wpa_send_eapol_timeout,  (atbm_void *)sm,ATBM_NULL);
		sm->pending_1_of_4_timeout = 0;
		wifi_printk(WIFI_DBG_ERROR,"wpa_receive: MIC OK\n\r");
	}

	if (key_info & ATBM_WPA_KEY_INFO_REQUEST) {
		if (sm->MICVerified) {
			sm->req_replay_counter_used = 1;
			atbm_memcpy(sm->req_replay_counter, key->replay_counter,
				  ATBM_WPA_REPLAY_COUNTER_LEN);
		} else {		
			wifi_printk(WIFI_DBG_ERROR,"wpa rx:MIC err(2)\n\r");
			return;
		}
#if 0
		/*
		 * TODO: should decrypt key data field if encryption was used;
		 * even though MAC address KDE is not normally encrypted,
		 * supplicant is allowed to encrypt it.
		 */
		if (msg == SMK_ERROR) {
#ifdef CONFIG_PEERKEY
			wpa_smk_error(wpa_auth, sm, key);
#endif /* CONFIG_PEERKEY */
			return;
		} else if (key_info & WPA_KEY_INFO_ERROR) {
			wpa_receive_error_report(
				wpa_auth, sm,
				!(key_info & ATBM_WPA_KEY_INFO_KEY_TYPE));
		} else if (key_info & ATBM_WPA_KEY_INFO_KEY_TYPE) {
			wpa_auth_logger(wpa_auth, sm->addr, LOGGER_INFO,
					"received EAPOL-Key Request for new "
					"4-Way Handshake");
			wpa_request_new_ptk(sm);
#ifdef CONFIG_PEERKEY
		} else if (msg == SMK_M1) {
			wpa_smk_m1(wpa_auth, sm, key);
#endif /* CONFIG_PEERKEY */
		} else if (key_data_length > 0 &&
			   wpa_parse_kde_ies((const atbm_uint8 *) (key + 1),
					     key_data_length, &kde) == 0 &&
			   kde.mac_addr) {
		} else {
			wpa_auth_logger(wpa_auth, sm->addr, LOGGER_INFO,
					"received EAPOL-Key Request for GTK "
					"rekeying");
			eloop_cancel_timeout(wpa_rekey_gtk, wpa_auth, ATBM_NULL);
			wpa_rekey_gtk(wpa_auth, ATBM_NULL);
		}
#endif
	} else 

	{
		/* Do not allow the same key replay counter to be reused. */
		wpa_replay_counter_mark_invalid(sm->key_replay,
						key->replay_counter);

		if (msg == PAIRWISE_2) {
			/*
			 * Maintain a copy of the pending EAPOL-Key frames in
			 * case the EAPOL-Key frame was retransmitted. This is
			 * needed to allow EAPOL-Key msg 2/4 reply to another
			 * pending msg 1/4 to update the SNonce to work around
			 * unexpected supplicant behavior.
			 */
			atbm_memcpy(sm->prev_key_replay, sm->key_replay,
				  sizeof(sm->key_replay));
		} else {
			atbm_memset(sm->prev_key_replay, 0,
				  sizeof(sm->prev_key_replay));
		}

		/*
		 * Make sure old valid counters are not accepted anymore and
		 * do not get copied again.
		 */
		wpa_replay_counter_mark_invalid(sm->key_replay, ATBM_NULL);
	}

	atbm_kfree(sm->last_rx_eapol_key);
	sm->last_rx_eapol_key = atbm_kmalloc(data_len,GFP_KERNEL);
	if (sm->last_rx_eapol_key == ATBM_NULL)
		return;
	atbm_memcpy(sm->last_rx_eapol_key, data, data_len);
	sm->last_rx_eapol_key_len = data_len;

	sm->rx_eapol_key_secure = !!(key_info & ATBM_WPA_KEY_INFO_SECURE);
	sm->EAPOLKeyReceived = ATBM_TRUE;
	sm->EAPOLKeyPairwise = !!(key_info & ATBM_WPA_KEY_INFO_KEY_TYPE);
	sm->EAPOLKeyRequest = !!(key_info & ATBM_WPA_KEY_INFO_REQUEST);
	atbm_memcpy(sm->SNonce, key->key_nonce, ATBM_WPA_NONCE_LEN);

	if(msg == PAIRWISE_2)
	{
		if(sm->EAPOLKeyReceived && !sm->EAPOLKeyRequest &&
			 sm->EAPOLKeyPairwise)
		{
			wifi_printk(WIFI_WPA,"2/4 ok\n\r");
			sm->wpa_ptk_state = ATBM_WPA_PTK_PTKINITNEGOTIATING;
		}
		else
		{
			sm->wpa_ptk_state = ATBM_WPA_PTK_PTKSTART;
			wifi_printk(WIFI_WPA,"2/4 err\n\r");
		}
	}
	else if(msg == PAIRWISE_4)
	{
		if (sm->EAPOLKeyReceived && !sm->EAPOLKeyRequest &&
			 sm->EAPOLKeyPairwise && sm->MICVerified)
		{
			wifi_printk(WIFI_WPA,"4/4 ok\n\r");
			sm->wpa_ptk_state = ATBM_WPA_PTK_PTKINITDONE;
		}
		else
		{
			wifi_printk(WIFI_WPA,"4/4 err\n\r");
			sm->wpa_ptk_state = ATBM_WPA_PTK_PTKINITNEGOTIATING;
		}
	}
	else if(msg == GROUP_2)
	{
		if (sm->EAPOLKeyReceived && !sm->EAPOLKeyRequest &&
		    !sm->EAPOLKeyPairwise && sm->MICVerified)
		{
			wifi_printk(WIFI_WPA,"2/2 ok\n\r");
			sm->wpa_ptk_group_state = ATBM_WPA_PTK_GROUP_KEYINSTALLED;
			eloop_cancel_timeout(wpa_send_eapol_timeout, (atbm_void *)sm, ATBM_NULL);
		}
	}
	else
	{
		
	}

	eloop_register_task((atbm_void *)priv,ap_get_sta((struct hostapd_data *)priv->appdata,sm->addr));

//	wpa_sm_step(sm);
}

struct hostapd_sta_info * ap_get_sta(struct hostapd_data * hapd, const atbm_uint8 *sta)
{

	struct hostapd_sta_info *tmp;
	int i = 0;
	
	for(i=0;i<ATBMWIFI__MAX_STA_IN_AP_MODE;i++){
		tmp = hapd->sta_list[i];
		if(tmp==ATBM_NULL)		{
			continue;
		}
		if((tmp != ATBM_NULL)&&(atbm_memcmp(tmp->addr, sta, 6) == 0)) {
			return tmp;
		}
	}
	return ATBM_NULL;
}
/*
return empty stainfo id
if no empty return ATBMWIFI__MAX_STA_IN_AP_MODE
*/
int ap_get_emtpy_stainfo(struct hostapd_data * hapd)
{

	struct hostapd_sta_info *tmp;
	int i = 0;
	
	for(i=0;i<ATBMWIFI__MAX_STA_IN_AP_MODE;i++){
		tmp = hapd->sta_list[i];
		if(tmp==ATBM_NULL)
		{
			return i;
		}
	}
	return ATBMWIFI__MAX_STA_IN_AP_MODE;
}


struct hostapd_sta_info * ap_sta_add(struct hostapd_data *hapd, const atbm_uint8 *addr,atbm_uint8 linkid)
{

	struct hostapd_sta_info *sta;
//	struct atbmwifi_vif *priv = hapd->priv;
	int id=0;
	int IrqState;
	
	for(id=0;id<ATBMWIFI__MAX_STA_IN_AP_MODE;id++){
		sta = hapd->sta_list[id];
		if(sta==ATBM_NULL) 	{
			continue;
		}
		if(atbm_memcmp(addr, sta, 6) == 0)	{
			if((linkid-1) != id){
				//return tmp;
				//because the new sta have been alloc in new linkid free the old 
				ap_sta_del(hapd,sta);
			}
		}
		else if((linkid-1) == id){
			//if the same linkid but macaddr not the same,just free
			//because the new sta have been alloc in new linkid free the old 
			ap_sta_del(hapd,sta);
		}
	}

	sta = ap_get_sta(hapd, addr);
	if(sta)
		return sta;
	
	IrqState =atbm_local_irq_save();
	if (hapd->num_sta >= ATBMWIFI__MAX_STA_IN_AP_MODE) {
		/* FIX: might try to remove some old STAs first? */
		atbm_local_irq_restore(IrqState);
		return ATBM_NULL;
	}
	//id = ap_get_emtpy_stainfo(hapd);
	
	//if(id >= ATBMWIFI__MAX_STA_IN_AP_MODE) {
		/* FIX: might try to remove some old STAs first? */
	//	return NULL;
	//}
	
	sta = atbm_kzalloc(sizeof(struct hostapd_sta_info),GFP_KERNEL);
	if (sta == ATBM_NULL) {
		atbm_local_irq_restore(IrqState);
		return ATBM_NULL;
	}
 
	/* initialize STA info data */
#if 0
	eloop_register_timeout(hapd->conf->ap_max_inactivity, 0,
			       ap_handle_timer, hapd, sta);
#endif	
	atbm_memcpy(sta->addr, addr, ATBM_ETH_ALEN);
	hapd->sta_list[(linkid-1)] = sta;
	hapd->num_sta++;
	sta->deauth_reason = 1;
	sta->disassoc_reason = 1;
	sta->atbmwifi_wpa_sm = ATBM_NULL;
	atbm_local_irq_restore(IrqState);
	//ap_sta_hash_add(hapd, sta);
//	sta->ssid = &hapd->conf->ssid;
	//ap_sta_remove_in_other_bss(hapd, sta);
	
	return sta;

}



atbm_void ap_sta_del(struct hostapd_data *hostapd,struct hostapd_sta_info *sta)
{
	int i=0;
	int IrqState;
	
	IrqState =atbm_local_irq_save();
	hostapd->num_sta--;
	wifi_printk(WIFI_DBG_INIT,"hostapd sta_del\n");
	eloop_cancel_timeout(wpa_send_eapol_timeout,sta->atbmwifi_wpa_sm,ATBM_NULL);;
	eloop_cancel_timeout(hostapd_4_way_handshake_start,hostapd->priv,sta);
	if(sta->atbmwifi_wpa_sm)
	{
		if (sta->atbmwifi_wpa_sm->wpa_ie)
		{
			atbm_kfree(sta->atbmwifi_wpa_sm->wpa_ie);
		}

		if(sta->atbmwifi_wpa_sm->last_rx_eapol_key)
		{
			atbm_kfree(sta->atbmwifi_wpa_sm->last_rx_eapol_key);
		}
		atbm_kfree(sta->atbmwifi_wpa_sm);
		sta->atbmwifi_wpa_sm=ATBM_NULL;
	}
	for(i=0;i<ATBMWIFI__MAX_STA_IN_AP_MODE;i++){
		if( hostapd->sta_list[i]==sta)	{
			hostapd->sta_list[i]=ATBM_NULL;
			break;
		}
	}
	atbm_local_irq_restore(IrqState);
	atbm_kfree(sta);
#ifdef CONFIG_WPS
	if(hostapd->num_sta <= 0){
		if(hostapd->wpsdata == ATBM_NULL){
			if(hostapd->wps){
				if(!hostapd->wps->wpa_success_deauth){
//					atbm_p2p_restart(priv);
				}else{
					hostapd->wps->wpa_success_deauth = 1;
				}
			}
		}
	}
#endif
}

atbm_void hostap_sta_del(struct atbmwifi_vif *priv,atbm_uint8 * staMacAddr)
{
	struct hostapd_data *hostapd = (struct hostapd_data *)priv->appdata;
	struct hostapd_sta_info *sta = ap_get_sta(hostapd,staMacAddr);	
	wifi_printk(WIFI_ALWAYS,"hostap_sta_del\n");
	if(sta){		
		ap_sta_del(hostapd,sta);
	}
}



 int hostapd_get_aid(struct hostapd_data *hapd, struct hostapd_sta_info *sta)
{
#if 0
	int i, j = 32, aid;

	/* get a unique AID */
	if (sta->aid > 0) {
		return 0;
	}

	for (i = 0; i < AID_WORDS; i++) {
		if (hapd->sta_aid[i] == (atbm_uint32) -1)
			continue;
		for (j = 0; j < 32; j++) {
			if (!(hapd->sta_aid[i] & BIT(j)))
				break;
		}
		if (j < 32)
			break;
	}
	if (j == 32)
		return -1;
	aid = i * 32 + j + 1;
	if (aid > 2007)
		return -1;

	sta->aid = aid;
	hapd->sta_aid[i] |= BIT(j);
#endif
	if(sta->aid > ATBMWIFI__MAX_STA_IN_AP_MODE) 
		return -1;
	else
		return sta->aid;
}
 
 /**
  * ieee802_1x_receive - Process the EAPOL frames from the Supplicant
  * @hapd: hostapd BSS data
  * @sa: Source address (sender of the EAPOL frame)
  * @buf: EAPOL frame
  * @len: Length of buf in octets
  *
  * This function is called for each incoming EAPOL frame from the interface
  */
 
 atbm_void ieee802_1x_receive(struct atbmwifi_vif *priv,
							 const atbm_uint8 *sa, const atbm_uint8 *buf,
							 atbm_size_t len)
 {
	 struct hostapd_sta_info *sta;
	 struct atbmwifi_ieee802_1x_hdr *hdr;
	 struct atbmwifi_ieee802_1x_eapol_key *key;
	 atbm_uint16 datalen;
 //  int key_mgmt;
 
	 sta = ap_get_sta((struct hostapd_data *)priv->appdata, sa);
	 if(ATBM_NULL == sta)
	 {
		 return;
	 }
 
	 if (len < sizeof(*hdr)) {
		 return;
	 }
 
	 hdr = (struct atbmwifi_ieee802_1x_hdr *) buf;
	 datalen = atbm_be_to_host16(hdr->length);
 
	 if (len - sizeof(*hdr) < datalen) {
		 return;
	 }
	 if (len - sizeof(*hdr) > datalen) {
#ifdef LINUX_DEBUG
 		 wpa_printf(MSG_DEBUG, "   ignoring %lu extra octets after "
				"IEEE 802.1X packet",
				(unsigned long) len - sizeof(*hdr) - datalen);
#endif
	 }
 
	 key = (struct atbmwifi_ieee802_1x_eapol_key *) (hdr + 1);
	 if (datalen >= sizeof(struct atbmwifi_ieee802_1x_eapol_key) &&
		 hdr->type == ATBM_IEEE802_1X_TYPE_EAPOL_KEY &&
		 (key->type == ATBM_EAPOL_KEY_TYPE_WPA ||
		  key->type == ATBM_EAPOL_KEY_TYPE_RSN)) {
		 wpa_receive(priv, sta->atbmwifi_wpa_sm, (atbm_uint8 *) hdr,
				 sizeof(*hdr) + datalen);
		 return;
	 }
	 //
	 ///FIXME
	 //
	 //TODO: add WPS RX code this
#ifdef CONFIG_WPS
	switch(hdr->type){
		case ATBM_IEEE802_1X_TYPE_EAP_PACKET:
		case ATBM_IEEE802_1X_TYPE_EAPOL_START:
			hostapd_wps_handshake_process(priv, sta, hdr, datalen);
			break;
		case ATBM_IEEE802_1X_TYPE_EAPOL_LOGOFF:
			break;
		default:
			wpa_printf(MSG_DEBUG, "  unknown IEEE 802.1X packet type");
			break;
	}
#endif
 }

int hostapd_rx_assoc_req(struct atbmwifi_vif *priv,struct atbm_buff *skb)
{
	struct hostapd_sta_info *sta;
	int len = 0;
	atbm_uint8 * data = ATBM_NULL;
	struct hostapd_data *hapd = (struct hostapd_data *)priv->appdata;
	struct atbmwifi_ieee80211_mgmt *mgmt = (struct atbmwifi_ieee80211_mgmt *) ATBM_OS_SKB_DATA(skb);
	struct atbmwifi_ieee80211_tx_info * tx_info = ATBM_IEEE80211_SKB_TXCB(skb);
	atbm_uint16 type = mgmt->frame_control & atbm_cpu_to_le16(ATBM_IEEE80211_FCTL_STYPE);
	atbm_uint16 resp = ATBM_WLAN_STATUS_SUCCESS;
	struct atbmwifi_ieee802_11_elems elems;
//	const atbm_uint8 *wpa_ie;
//	atbm_size_t wpa_ie_len=0;
	
	sta = ap_get_sta(hapd, mgmt->sa);	
	if(sta == ATBM_NULL)
	{
		sta = ap_sta_add(hapd, mgmt->sa,tx_info->link_id);
		if(sta == ATBM_NULL)
		{	
			wifi_printk(WIFI_DBG_ERROR,"Sta " MACSTR " add FAIL.\n",
			       MAC2STR(mgmt->sa));
			resp = ATBM_WLAN_STATUS_UNSPECIFIED_FAILURE;
			goto fail;
		}
		sta->aid = tx_info->link_id;
	}
	if(type == ATBM_IEEE80211_STYPE_ASSOC_REQ)
	{
		data = (atbm_uint8 *)ATBM_OS_SKB_DATA(skb)+offsetof(struct atbmwifi_ieee80211_mgmt, u.assoc_req.variable);
		len = ATBM_OS_SKB_LEN(skb)-offsetof(struct atbmwifi_ieee80211_mgmt, u.assoc_req.variable);
		
	}
	else if(type == ATBM_IEEE80211_STYPE_REASSOC_REQ)
	{
		data = (atbm_uint8 *)ATBM_OS_SKB_DATA(skb)+offsetof(struct atbmwifi_ieee80211_mgmt, u.reassoc_req.variable);
		len = ATBM_OS_SKB_LEN(skb)-offsetof(struct atbmwifi_ieee80211_mgmt, u.reassoc_req.variable);
		
	}

	if(sta == ATBM_NULL)
	{
		return -1;
	}
	

	atbm_memset(&elems,0,sizeof(elems));
	atbm_ieee802_11_parse_elems((atbm_uint8 *)data, len, &elems);   
	resp = check_assoc_ies(atbmwifi_get_config(priv), sta, &elems, 0);
	if (resp != ATBM_WLAN_STATUS_SUCCESS)
		goto fail;

	if (hostapd_get_aid(hapd, sta) <= 0) {
		resp = ATBM_WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA;
		wifi_printk(WIFI_DBG_ERROR,"hostap ATBM_FALSE aid %d\n",sta->aid);
		goto fail;
	}

	sta->capability = type == ATBM_IEEE80211_STYPE_ASSOC_REQ ? 
							  (mgmt->u.assoc_req.capab_info) : 
							  (mgmt->u.assoc_req.capab_info);
	sta->listen_interval = type == ATBM_IEEE80211_STYPE_ASSOC_REQ ?
							  (mgmt->u.reassoc_req.listen_interval) :
							  (mgmt->u.assoc_req.listen_interval);

	if (sta->capability & ATBM_WLAN_CAPABILITY_SHORT_PREAMBLE)
		sta->flags |= WLAN_STA_SHORT_PREAMBLE;
	else
		sta->flags &= ~WLAN_STA_SHORT_PREAMBLE;

	sta->flags |= WLAN_STA_ASSOC_REQ_OK;
fail:

	
	if (resp != ATBM_WLAN_STATUS_SUCCESS){
		//FIXME add deauth
	}
	else {
		hostapd_link_sta_sm(priv,atbmwifi_sta_find_form_hard_linkid(priv,tx_info->link_id),mgmt->sa);
	}
	return resp;
	
}

atbm_void __wpa_send_eapol(struct atbmwifi_cfg *config,
		      struct atbmwifi_wpa_state_machine *sm, int key_info,
		      const atbm_uint8 *key_rsc, const atbm_uint8 *nonce,
		      const atbm_uint8 *kde, atbm_size_t kde_len,
		      int keyidx, int encr, int force_version)
{
	struct atbmwifi_ieee802_1x_hdr *hdr;
	struct atbmwifi_wpa_eapol_key *key;
	atbm_size_t len;
	int alg;
	int key_data_len, pad_len = 0;
	atbm_uint8 *buf, *pos;
	int version, pairwise;
	int i;

	len = sizeof(struct atbmwifi_ieee802_1x_hdr) + sizeof(struct atbmwifi_wpa_eapol_key);
	if (force_version)
		version = force_version;
	else if (wpa_use_aes_cmac(sm))
		version = ATBM_WPA_KEY_INFO_TYPE_AES_128_CMAC;
	else if (sm->pairwise != ATBM_WPA_CIPHER_TKIP)
		version = ATBM_WPA_KEY_INFO_TYPE_HMAC_SHA1_AES;
	else
		version = ATBM_WPA_KEY_INFO_TYPE_HMAC_MD5_RC4;

	pairwise = key_info & ATBM_WPA_KEY_INFO_KEY_TYPE;

	key_data_len = kde_len;

	if ((version == ATBM_WPA_KEY_INFO_TYPE_HMAC_SHA1_AES ||
	     version == ATBM_WPA_KEY_INFO_TYPE_AES_128_CMAC) && encr) {
		pad_len = key_data_len % 8;
		if (pad_len)
			pad_len = 8 - pad_len;
		key_data_len += pad_len + 8;
	}

	len += key_data_len;

	hdr = atbm_kzalloc(len,GFP_KERNEL);
	if (hdr == ATBM_NULL)
		return;
	// TO DO GET VERSION
	hdr->version = 2;////???? need FIX ME ,dlink_655 version =1
	hdr->type = ATBM_IEEE802_1X_TYPE_EAPOL_KEY;
	hdr->length = atbm_host_to_be16(len  - sizeof(*hdr));
	key = (struct atbmwifi_wpa_eapol_key *) (hdr + 1);

	key->type = sm->wpa == ATBM_WPA_VERSION_WPA2 ?
		ATBM_EAPOL_KEY_TYPE_RSN : ATBM_EAPOL_KEY_TYPE_WPA;
	key_info |= version;
	if (encr && sm->wpa == ATBM_WPA_VERSION_WPA2)
		key_info |= ATBM_WPA_KEY_INFO_ENCR_KEY_DATA;
	if (sm->wpa != ATBM_WPA_VERSION_WPA2)
		key_info |= keyidx << ATBM_WPA_KEY_INFO_KEY_INDEX_SHIFT;
	ATBM_WPA_PUT_BE16(key->key_info, key_info);

	alg = pairwise ? sm->pairwise : config->group_cipher;
	ATBM_WPA_PUT_BE16(key->key_length, wpa_commom_key_len(alg));
	if (key_info & ATBM_WPA_KEY_INFO_SMK_MESSAGE)
		ATBM_WPA_PUT_BE16(key->key_length, 0);

	/* FIX: STSL: what to use as key_replay_counter? */
	for (i = RSNA_MAX_EAPOL_RETRIES - 1; i > 0; i--) {
		sm->key_replay[i].valid = sm->key_replay[i - 1].valid;
		atbm_memcpy(sm->key_replay[i].counter,
			  sm->key_replay[i - 1].counter,
			  ATBM_WPA_REPLAY_COUNTER_LEN);
	}
	inc_byte_array(sm->key_replay[0].counter, ATBM_WPA_REPLAY_COUNTER_LEN);
	atbm_memcpy(key->replay_counter, sm->key_replay[0].counter,
		  ATBM_WPA_REPLAY_COUNTER_LEN);
	sm->key_replay[0].valid = ATBM_TRUE;

	if (nonce)
		atbm_memcpy(key->key_nonce, nonce, ATBM_WPA_NONCE_LEN);

	if (key_rsc)
		atbm_memcpy(key->key_rsc, key_rsc, ATBM_WPA_KEY_RSC_LEN);

	if (kde && !encr) {
		atbm_memcpy(key + 1, kde, kde_len);
		ATBM_WPA_PUT_BE16(key->key_data_length, kde_len);
	} else if (encr && kde) {
		buf = atbm_kzalloc(key_data_len,GFP_KERNEL);
		if (buf == ATBM_NULL) {
			atbm_kfree(hdr);
			return;
		}
		pos = buf;
		atbm_memcpy(pos, kde, kde_len);
		pos += kde_len;

		if (pad_len)
			*pos++ = 0xdd;

		if (version == ATBM_WPA_KEY_INFO_TYPE_HMAC_SHA1_AES ||
		    version == ATBM_WPA_KEY_INFO_TYPE_AES_128_CMAC) {
			if (aes_wrap(sm->PTK.kek, (key_data_len - 8) / 8, buf,
				     (atbm_uint8 *) (key + 1))) {
				atbm_kfree(hdr);
				atbm_kfree(buf);
				return;
			}
			ATBM_WPA_PUT_BE16(key->key_data_length, key_data_len);
		} else {
			atbm_uint8 ek[32];
			wifi_printk(WIFI_DBG_MSG,"WPA_HMAC_MD5_RC4\n\r");
			atbm_memcpy(key->key_iv,
				  sm->group->Counter + ATBM_WPA_NONCE_LEN - 16, 16);
			inc_byte_array(sm->group->Counter, ATBM_WPA_NONCE_LEN);
			atbm_memcpy(ek, key->key_iv, 16);
			atbm_memcpy(ek + 16, sm->PTK.kek, 16);
			atbm_memcpy(key + 1, buf, key_data_len);
			rc4_skip(ek, 32, 256, (atbm_uint8 *) (key + 1), key_data_len);
			ATBM_WPA_PUT_BE16(key->key_data_length, key_data_len);
			
		}
		atbm_kfree(buf);
	}

	if (key_info & ATBM_WPA_KEY_INFO_MIC) {
		if (!sm->PTK_valid) {

			atbm_kfree(hdr);
			return;
		}
		wpa_eapol_key_mic(sm->PTK.kck, version, (atbm_uint8 *) hdr, len,
				  key->key_mic);
	}
//	wifi_printk(WIFI_DBG_MSG,"__wpa_send_eapol len+kde(%d)\n\r",len);
	wifi_printk(WIFI_DBG_MSG,"hostap_tx_eap\n");
	hostapd_send_eapol((struct atbmwifi_vif * )atbmwifi_config_get_priv(config),sm->addr,ATBM_ETH_P_EAPOL,(atbm_uint8 *)hdr,len);
	atbm_kfree(hdr);
}

atbm_void hostapd_4_way_handshake_start(atbm_void *data1,atbm_void *data2)
{
	struct atbmwifi_vif *priv = (struct atbmwifi_vif*)data1;
	struct hostapd_sta_info *sta = (struct hostapd_sta_info*)data2;
	wifi_printk(WIFI_WPA,"hostapd_4way_start\n\r");
	sta->timeout = STA_START;
	//eloop_register_task((void *)priv,sta);
	hostapd_run(priv,sta);
}
atbm_void hostapd_setup_4_way_handshake(struct atbmwifi_vif *priv,atbm_uint8 *da)
{
	int link_id;
	struct hostapd_sta_info *sta;
//	struct atbmwifi_wpa_state_machine *sm;
	
	link_id = atbmwifi_find_link_id(priv, da);
	sta = (struct hostapd_sta_info *)priv->link_id_db[link_id-1].sta_priv.reserved;
	if((sta==ATBM_NULL) ||(sta->atbmwifi_wpa_sm==ATBM_NULL)){
		wifi_printk(WIFI_WPA,"hostapd_setup_4_way_handshake drop\n\r");
		return;
	}
	atbmwifi_wpa_event_queue((atbm_void*)priv,(atbm_void*)sta,ATBM_NULL,WPA_EVENT__HOSTAPD_STA_HANDSHAKE_START,0);
}
int hostapd_send_4_of_1_msg(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	sm->TimeoutCtr++;
	sm->TimeoutEvt = 0;
	if (sm->TimeoutCtr > (int) dot11RSNAConfigPairwiseUpdateCount) {
		/* No point in sending the EAPOL-Key - we will disconnect
		 * immediately following this. */
		return -1;
	}
	os_get_random(sm->ANonce,32);
	
	if (atbmwifi_wpa_key_mgmt_wpa_psk(sm->wpa_key_mgmt))
	{
		if (atbmwifi_get_config(priv)->psk)
		{
			atbm_memcpy(sm->PMK,atbmwifi_get_config(priv)->psk, ATBM_PMK_LEN);
		}
		else
		{
			sm->wpa_ptk_state = ATBM_WPA_PTK_INITIALIZE;

			return -1;
		}
		wifi_printk(WIFI_WPA,"hostapd 1/4\n\r");
		wpa_send_eapol(atbmwifi_get_config(priv), sm,
		       ATBM_WPA_KEY_INFO_ACK | ATBM_WPA_KEY_INFO_KEY_TYPE, ATBM_NULL,
		       sm->ANonce,ATBM_NULL,0, 0, 0);

		return 0;
	}
	wifi_printk(WIFI_DBG_ERROR,"hostapd 1/4 err\n\r");
	return -1;

}

int hostapd_handshake_over(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	sm->EAPOLKeyReceived = ATBM_FALSE;
	if (sm->Pair) {
		if (wpa_common_install_ptk(priv,&sm->PTK, sm->pairwise,1 | (sm->linkid << 8))) 	{
			wifi_printk(WIFI_DBG_ERROR,"install pk err\n");
			return -1;
		}
		/* FIX: MLME-SetProtection.Request(TA, Tx_Rx) */
		sm->pairwise_set = ATBM_TRUE;
		eloop_cancel_timeout(wpa_send_eapol_timeout, (atbm_void *)sm,ATBM_NULL);		
	}


	if (sm->wpa == ATBM_WPA_VERSION_WPA)
	{
		sm->PInitAKeys = ATBM_TRUE;
		sm->wpa_ptk_group_state = ATBM_WPA_PTK_GROUP_REKEYNEGOTIATING;
	}
	else
	{
		sm->has_GTK = ATBM_TRUE;
		sm->wpa_ptk_group_state = ATBM_WPA_PTK_GROUP_KEYINSTALLED;
	}

	sm->wpa_ptk_state = ATBM_WPA_PTK_INSTALL;
	sm->GTimeoutCtr = 0;

//	wifi_printk(WIFI_DBG_MSG,"hostapd_handshake_over+++,line=%d"
//				"pairwise key handshake completed (%s)\n\r",__LINE__,
//				 sm->wpa == ATBM_WPA_VERSION_WPA ? "WPA" : "RSN");

	return 0;
}
static atbm_void hostapd_4_way_handshake_err(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	atbm_uint32 IrqState = 0;
	struct hostapd_data *hostapd = (struct hostapd_data *)(priv->appdata);
	wifi_printk(WIFI_DBG_ERROR,"handshake err\n\r");
	if(hostapd->num_sta < 1)
	{
		//wifi_printk(WIFI_DBG_MSG,"sta info err num_sta %d\n\r",hostapd->num_sta);
		return ;
	}
	if(sm->linkid > ATBMWIFI__MAX_STA_IN_AP_MODE){
		wifi_printk(WIFI_DBG_ERROR,"hostapd_4_way_handshake_err linkid %d \n\r",sm->linkid);
		return;
	}
	IrqState =atbm_local_irq_save();
	hostapd->sta_list[sm->linkid-1]->timeout = STA_HANDSHAKE;
	atbm_local_irq_restore(IrqState);
	eloop_register_task(priv,hostapd->sta_list[sm->linkid-1]);
}
int hostapd_4_way_handshake_process(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	int res = 0;

	if (sm->TimeoutCtr >
	 (int) dot11RSNAConfigPairwiseUpdateCount)
	{
		wifi_printk(WIFI_DBG_ERROR,"hostapd err Timeout %d>%d\n\r",sm->TimeoutCtr,dot11RSNAConfigPairwiseUpdateCount);
		hostapd_4_way_handshake_err(priv,sm);
		return res;
	}
	
	switch(sm->wpa_ptk_state)
	{
		case ATBM_WPA_PTK_DISCONNECT:

			break;
		case ATBM_WPA_PTK_INITIALIZE:
			
			if(atbmwifi_get_config(priv)->key_mgmt== ATBM_WPA_KEY_MGMT_PSK)
			{
				hostapd_eapol_init(priv,sm);
			}
			
			break;
		case ATBM_WPA_PTK_PTKSTART:

			res = hostapd_send_4_of_1_msg(priv,sm);

			break;
			
		case ATBM_WPA_PTK_PTKINITNEGOTIATING:
			
			wifi_printk(WIFI_DBG_MSG,"start 3/4\n\r");
			res = hostapd_send_4_of_3_msg(priv,sm);

			break;
			
		case ATBM_WPA_PTK_PTKINITDONE:
			hostapd_handshake_over(priv,sm);
			res = -1;
			break;
		default:
			res = -1;
			break;
	}

	return res;
}

int hostapd_send_1_of_group(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	atbm_uint8 rsc[ATBM_WPA_KEY_RSC_LEN];
	struct atbmwifi_wpa_group *gsm = sm->group;
	atbm_uint8 *kde, *pos, hdr[2];
	atbm_size_t kde_len;
//	atbm_uint8 *gtk, dummy_gtk[32];
	atbm_uint8 *gtk;
	sm->GTimeoutCtr++;
	if (sm->GTimeoutCtr > (int) dot11RSNAConfigGroupUpdateCount) {
		/* No point in sending the EAPOL-Key - we will disconnect
		 * immediately following this. */
		return -1;
	}

	if (sm->wpa == ATBM_WPA_VERSION_WPA)
		sm->PInitAKeys = ATBM_FALSE;
	sm->TimeoutEvt = ATBM_FALSE;
	/* Send EAPOL(1, 1, 1, !Pair, G, RSC, GNonce, MIC(PTK), GTK[GN]) */
	atbm_memset(rsc, 0, ATBM_WPA_KEY_RSC_LEN);
//	if (gsm->wpa_group_state == WPA_GROUP_SETKEYSDONE)
//		wpa_auth_get_seqnum(sm->wpa_auth, NULL, gsm->GN, rsc);
/*
	wpa_auth_logger(sm->wpa_auth, sm->addr, LOGGER_DEBUG,
			"sending 1/2 msg of Group Key Handshake");
*/
	gtk = gsm->GTK[gsm->GN - 1];
#if 0
	if (0) {
		/*
		 * Provide unique atbm_os_random GTK to each STA to prevent use
		 * of GTK in the BSS.
		 */
		if (os_get_random(dummy_gtk, gsm->GTK_len) < 0)
			return -1;
		gtk = dummy_gtk;
	}
#endif
	if (sm->wpa == ATBM_WPA_VERSION_WPA2) {
		kde_len = 2 + ATBM_RSN_SELECTOR_LEN + 2 + gsm->GTK_len +
			atbmwifi_ieee80211w_kde_len(sm);
		kde = atbm_kmalloc(kde_len,GFP_KERNEL);
		if (kde == ATBM_NULL)
			return -1;

		pos = kde;
		hdr[0] = gsm->GN & 0x03;
		hdr[1] = 0;
		pos = wpa_add_kde(pos, ATBM_RSN_KEY_DATA_GROUPKEY, hdr, 2,
				  gtk, gsm->GTK_len);
		pos = atbmwifi_ieee80211w_kde_add(sm, pos);
	} else {
//		wifi_printk(WIFI_DBG_MSG,"hostapd_send_1_of_group:ATBM_WPA_VERSION_WPA\n\r");
		kde = gtk;
		pos = kde + gsm->GTK_len;
	}
	wifi_printk(WIFI_WPA,"tx g 1/2\n\r");
	wpa_send_eapol(atbmwifi_get_config(priv), sm,
		       ATBM_WPA_KEY_INFO_SECURE | ATBM_WPA_KEY_INFO_MIC |
		       ATBM_WPA_KEY_INFO_ACK |
		       (!sm->Pair ? ATBM_WPA_KEY_INFO_INSTALL : 0),
		       rsc, gsm->GNonce, kde, pos - kde, gsm->GN, 1);
	
	
	if (sm->wpa == ATBM_WPA_VERSION_WPA2)
	{
//		wifi_printk(WIFI_DBG_MSG,"atbm_kfree(kde)\n\r");
		atbm_kfree(kde);
	}
	return 0;
}
int hostapd_2_way_group_err(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	return 0;
}
int hostapd_2_way_group_process(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	int res = 0;
	
	if (sm->GTimeoutCtr > (int) dot11RSNAConfigGroupUpdateCount) {
					/* No point in sending the EAPOL-Key - we will disconnect
					 * immediately following this. */
		sm->wpa_ptk_group_state = ATBM_WPA_PTK_GROUP_KEYERROR;

		res = -1;

		return res;

	}
	switch(sm->wpa_ptk_group_state)
	{
		case ATBM_WPA_PTK_GROUP_IDLE:

			break;
		case ATBM_WPA_PTK_GROUP_REKEYNEGOTIATING:

			hostapd_send_1_of_group(priv,sm);
			break;
		case ATBM_WPA_PTK_GROUP_REKEYESTABLISHED:
		{
			atbm_uint8 *gtk;
			struct atbmwifi_wpa_group *group = sm->group;
			struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
			group->changed = ATBM_TRUE;
			
			eloop_cancel_timeout(wpa_send_eapol_timeout,(atbm_void *)sm,ATBM_NULL);
			group->wpa_group_state = ATBM_WPA_GROUP_SETKEYSDONE;
			gtk = group->GTK[group->GN - 1];
			res = wpa_common_install_gtk(priv,gtk,config->group_cipher,group->GN);

			if(res == 0)
			{
				wifi_printk(WIFI_WPA,"finish g 2/2\n\r");
				sm->wpa_ptk_group_state = ATBM_WPA_PTK_GROUP_KEYINSTALLED;
				priv->connect.encrype = 1;
				priv->connect_ok = 1;
				atbmwifi_event_uplayer(priv,ATBM_WIFI_JOIN_EVENT,sm->addr);
				
			}
			else
			{
				sm->wpa_ptk_group_state = ATBM_WPA_PTK_GROUP_REKEYNEGOTIATING;
			}
			
		}
			break;

		case ATBM_WPA_PTK_GROUP_KEYERROR:
			res = hostapd_2_way_group_err(priv,sm);
			break;
		default:
			res = -1;
			break;
	}
	return res;
}
atbm_void hostapd_run_handshake(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	int res = 0 ;
	//wifi_printk(WIFI_DBG_MSG,"hostapd_run_handshake:processing\n\r");
retry:
	if(sm->wpa_ptk_state != ATBM_WPA_PTK_INSTALL)
	{
		
		res = hostapd_4_way_handshake_process(priv,sm);
	}
	else
	{
		if(sm->wpa_ptk_group_state != ATBM_WPA_PTK_GROUP_KEYINSTALLED)
		{
			res = hostapd_2_way_group_process(priv,sm);
		}else {
			struct atbmwifi_wpa_group *group = sm->group;
//			struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
			
			eloop_cancel_timeout(wpa_send_eapol_timeout,(atbm_void *)sm,ATBM_NULL);
			group->wpa_group_state = ATBM_WPA_GROUP_SETKEYSDONE;
			priv->connect.encrype = 1;
			priv->connect_ok = 1;
			atbmwifi_event_uplayer(priv,ATBM_WIFI_JOIN_EVENT,sm->addr);
			res = 0;
		}
	}
	
	if(res<0)
	{
		goto retry;
	}
}
FLASH_FUNC atbm_void hostapd_run(struct atbmwifi_vif *priv,struct hostapd_sta_info *sta)
{
	struct hostapd_data *hostapd = (struct hostapd_data *)(priv->appdata);
#ifdef CONFIG_WPS
	//struct hostapd_sta_info *sta = hostapd->sta_list[hostapd->num_sta-1];
	struct atbmwifi_ieee802_1x_hdr *hdr = ATBM_NULL;
	atbm_size_t datalen = 0;
	atbm_size_t len = 0;
	struct atbm_eap_hdr *eap_headr = 0;

	wpa_printf(MSG_DEBUG, "hostapd run start wps = %d", hostapd->wps_last_rx_data?1:0);
	if(hostapd->wps_last_rx_data)
	{
		datalen = hostapd->wps_last_rx_data->used;
		hdr = (struct atbmwifi_ieee802_1x_hdr *)wpabuf_head_u8(hostapd->wps_last_rx_data);
		if(hdr)
		{
			switch(hdr->type){
				case ATBM_IEEE802_1X_TYPE_EAP_PACKET:
					handle_eap((struct hostapd_data *)priv->appdata, sta, (atbm_uint8 *)(hdr + 1), datalen);
					break;

				case ATBM_IEEE802_1X_TYPE_EAPOL_START:
					wpa_printf(MSG_DEBUG, "received EAPOL-Start from STA\n");
					len = sizeof(struct atbmwifi_ieee802_1x_hdr) + sizeof(struct atbm_eap_hdr) + 1;
					hdr = atbm_kmalloc(len, GFP_KERNEL);
					if(hdr == ATBM_NULL)
						goto wps_out;
					hdr->version = EAPOL_VERSION;
					hdr->type = ATBM_IEEE802_1X_TYPE_EAP_PACKET;
					hdr->length = atbm_host_to_be16(sizeof(struct atbm_eap_hdr) + 1);
					eap_headr = (struct atbm_eap_hdr *)(hdr + 1);

					eap_headr->code = EAP_CODE_REQUEST;
					eap_headr->identifier = 0;
					eap_headr->length = atbm_host_to_be16(sizeof(struct atbm_eap_hdr) + 1);
					*(atbm_uint8 *)(eap_headr + 1) = ATBM_EAP_TYPE_IDENTITY;

					hostapd_send_eapol(priv, sta->addr, ATBM_ETH_P_EAPOL, (atbm_uint8 *)hdr, len);
					atbm_kfree(hdr);
					hdr = ATBM_NULL;
					break;
				default:
					break;
			}
		}
wps_out:
		wpabuf_free(hostapd->wps_last_rx_data);
		hostapd->wps_last_rx_data = ATBM_NULL;
		return;
	}
#endif

	switch(sta->timeout)
	{
		case STA_START:
		{	
			sta->atbmwifi_wpa_sm->linkid = sta->aid;
			hostapd_run_handshake(priv,sta->atbmwifi_wpa_sm);
			break;
		}
		case STA_DISASSOC:
		case STA_HANDSHAKE:
		{

			atbmwifi_ieee80211_send_deauth_disassoc(priv, sta->addr,priv->bssid,
				       ATBM_IEEE80211_STYPE_DEAUTH,
				       ATBM_WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY,
				       ATBM_NULL, ATBM_TRUE);

			//hostapd->num_sta = 0;
			wifi_printk(WIFI_WPA,"hostapd deauth\n");
			
			atbmwifi_ap_deauth(priv, sta->addr);
//			priv->extra_ie = priv->bss.information_elements;
//			priv->extra_ie_len = priv->bss.len_information_elements;
//			atbmwifi_ap_start_beacon(priv);
//			priv->extra_ie = NULL;
//			priv->extra_ie_len = 0;
			break;
		}
		default:
		{
			wifi_printk(WIFI_WPA,"hostap:time(%d),stanum(%d)\n\r",sta->timeout,hostapd->num_sta);
		}
	}
}
FLASH_FUNC int hostapd_derive_psk(struct atbmwifi_cfg *config)
{
	if(config->psk_set == 1)
	{
		return 0;
	}
	atbm_pbkdf2_sha1((const char*)config->password,
		    (const char*)config->ssid, config->ssid_len,
		    4096, config->psk, ATBM_PMK_LEN);//pmk=psk;
	config->psk_set = 1;
	return 0;
}
FLASH_FUNC int hostapd_eapol_init(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm)
{
	if (sm->Init) {
		/* Init flag is not cleared here, so avoid busy
		 * loop by claiming nothing changed. */
		sm->changed = ATBM_FALSE;
	}

	sm->keycount = 0;
	if (sm->GUpdateStationKeys)
		sm->group->GKeyDoneStations--;
	sm->GUpdateStationKeys = ATBM_FALSE;
	if (sm->wpa == ATBM_WPA_VERSION_WPA)
		sm->PInitAKeys = ATBM_FALSE;
	if (1 /* Unicast cipher supported AND (ESS OR ((IBSS or WDS) and
	       * Local AA > Remote AA)) */) {
		sm->Pair = ATBM_TRUE;
	}
	//ADD CLEAR KRY
#if 0
	wpa_auth_set_eapol(sm->wpa_auth, sm->addr, WPA_EAPOL_portEnabled, 0);
	wpa_remove_ptk(sm);
	wpa_auth_set_eapol(sm->wpa_auth, sm->addr, WPA_EAPOL_portValid, 0);
	sm->TimeoutCtr = 0;
	if (atbmwifi_wpa_key_mgmt_wpa_psk(sm->wpa_key_mgmt)) {
		wpa_auth_set_eapol(sm->wpa_auth, sm->addr,
				   WPA_EAPOL_authorized, 0);
		}
#endif

	atbm_memset(&sm->PTK, 0, sizeof(sm->PTK));
	sm->PTK_valid = ATBM_FALSE;
	sm->AuthenticationRequest = ATBM_FALSE;
	sm->req_replay_counter_used = 0;
	sm->TimeoutCtr = 0;

	return 0;
}
FLASH_FUNC atbm_void hostapd_link_sta_sm(struct atbmwifi_vif *priv,
		  struct atbmwifi_sta_priv *sta_priv,atbm_uint8* mac)
{
	struct hostapd_sta_info *sta;

	sta = ap_get_sta((struct hostapd_data *)priv->appdata, mac);

	if(ATBM_NULL == sta)
	{
		return;
	}

	sta_priv->reserved = sta;
}
FLASH_FUNC struct hostapd_data *init_hostapd(struct atbmwifi_vif *priv)
{
	struct hostapd_data *hostapd;
	
	hostapd = atbm_kzalloc(sizeof(struct hostapd_data),GFP_KERNEL);
	g_hostapd = hostapd;
	hostapd->priv = priv;
	//wpa_timer_init();
	return hostapd;
}

FLASH_FUNC atbm_void free_hostapd(struct atbmwifi_vif *priv)
{

	if(priv->appdata){
#ifdef CONFIG_WPS
		hostapd_deinit_wps(priv->appdata);
#endif
		atbm_kfree(priv->appdata);
		priv->appdata = ATBM_NULL;
		g_hostapd = ATBM_NULL;
	}

}
 

 
FLASH_FUNC int hostapd_start(struct atbmwifi_vif *priv,const char *ssid,int ssid_len,char *key,int key_len,int key_mgmt)
{
	struct atbmwifi_cfg *config = atbmwifi_get_config(priv);
	struct hostapd_data *hostapd = (struct hostapd_data *)priv->appdata;
//#ifdef WPA_HOST_DEBUG
//	wifi_printk(WIFI_DBG_INIT,"hostapd start name(%s) key(%d)\n",name,key_mgmt);
//#endif
	if(atbmwifi_iee80211_check_combination(priv,config->channel_index) == ATBM_FALSE){
		wifi_printk(WIFI_ALWAYS,"channel combination err,please check\n");
		return -1;
	}
	if(ssid != ATBM_NULL)
	{
		atbm_memcpy(config->ssid,ssid,ssid_len);
		config->ssid_len = ssid_len;
		priv->ssid_length = config->ssid_len;
		atbm_memcpy(priv->ssid,config->ssid ,config->ssid_len);
		
		priv->ssid[config->ssid_len] = 0;
	}
	
	if((key != ATBM_NULL)&&(key_len != 0))
	{
		atbm_memcpy(config->password,key,key_len);
		config->password_len = key_len;
		priv->ssid_length = config->ssid_len;
	}

	//TO DO CLEAN KEY
	switch(key_mgmt)
	{
		case ATBM_KEY_WEP:
		case ATBM_KEY_WEP_SHARE:
		{
			config->auth_alg = (key_mgmt == ATBM_KEY_WEP) ? ATBM_WLAN_AUTH_OPEN : ATBM_WLAN_AUTH_SHARED_KEY;
			config->key_mgmt = ATBM_WPA_KEY_MGMT_WEP;
			config->key_id=0;

			if(key_len == 5)
			{
				config->group_cipher = ATBM_WPA_CIPHER_WEP40;
				config->pairwise_cipher = ATBM_WPA_CIPHER_WEP40;
			}
			else if(key_len == 13)
			{
				config->group_cipher = ATBM_WPA_CIPHER_WEP104;
				config->pairwise_cipher = ATBM_WPA_CIPHER_WEP104;
			}
			break;
		}
		case ATBM_KEY_WPA:
		case ATBM_KEY_WPA2:
			{
				atbm_uint8 keytype = (key_mgmt == ATBM_KEY_WPA) ? 0 : 1;

				config->auth_alg = ATBM_WLAN_AUTH_OPEN;
				config->key_mgmt = ATBM_WPA_KEY_MGMT_PSK;
				config->group_cipher = keytype ? ATBM_WPA_CIPHER_CCMP : ATBM_WPA_CIPHER_TKIP;
				config->pairwise_cipher = config->group_cipher;
				config->wpa = keytype ? ATBM_WPA_PROTO_RSN : ATBM_WPA_PROTO_WPA;				
				wifi_printk(WIFI_DBG_INIT,"hostapd key_mgmt(%d) wpa(%d)\n",config->key_mgmt,config->wpa);
				break;
			}
		case ATBM_KEY_MIX:
			{
				config->auth_alg = ATBM_WLAN_AUTH_OPEN;
				config->key_mgmt = ATBM_WPA_KEY_MGMT_PSK;
				config->group_cipher = ATBM_WPA_CIPHER_TKIP;
				config->pairwise_cipher = ATBM_WPA_CIPHER_CCMP;
				config->wpa = ATBM_WPA_PROTO_RSN;//can do it				
				break;
			}
		case ATBM_KEY_NONE:
			{
				config->auth_alg =  ATBM_WLAN_AUTH_OPEN;
				config->key_mgmt =ATBM_WPA_KEY_MGMT_NONE;
				config->group_cipher = ATBM_WPA_CIPHER_NONE;
				config->pairwise_cipher = ATBM_WPA_CIPHER_NONE;
				config->wpa =0;

				break;
			}
		default:
			{
				wifi_printk(WIFI_DBG_ERROR,"<ERROR> hostapd key_mgmt(%d)\n",key_mgmt);
				return -1;
				//break;
			}
	}

	if(config->key_mgmt== ATBM_WPA_KEY_MGMT_PSK)
	{
//		hostapd_eapol_init(config,(struct hostapd_data *)priv->appdata->);
//		wifi_printk(WIFI_DBG_INIT,"hostapd driver psk\n",config->key_mgmt);
		config->psk_set = 0;
		hostapd_derive_psk(config);
/*
		wifi_printk(WIFI_DBG_MSG, "pmk[0](%d),pmk[10](%d),pmk[16](%d),pmk[20](%d)\n"
							  "pmk[25](%d),pmk[28](%d),pmk[30](%d),pmk[31](%d)\n",
							   config->psk[0], config->psk[10], config->psk[16], config->psk[20],
							   config->psk[25], config->psk[28], config->psk[30], config->psk[31]);
*/
		
	}
	hostapd_init_extra_ie(priv);

	wifi_printk(WIFI_WPA,"hostapd(%s) start to beacon\n",priv->ssid);
	wpa_group_init(config,&hostapd->group,0);
	
	if(config->group_cipher != ATBM_WPA_CIPHER_NONE){
		iot_printf("atbmwifi_start_ap set group_cipher \n");
		wpa_common_install_gtk(priv,hostapd->group.GTK[hostapd->group.GN-1],config->group_cipher,hostapd->group.GN);
	}
	atbm_start_ap(priv);
	
	atbm_kfree(priv->extra_ie);
	priv->extra_ie = ATBM_NULL;
	priv->extra_ie_len = 0;

#ifdef CONFIG_WPS
	hostapd_init_wps(priv);
#endif
	return 0;
}




