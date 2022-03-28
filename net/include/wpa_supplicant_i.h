/**************************************************************************************************************
 * altobeam RTOS WSM host interface (HI) implementation
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#ifndef WPA_SUPPLICANT_I_H
#define WPA_SUPPLICANT_I_H

#ifdef CONFIG_WPS
#include "wps_main.h"
#include "wps.h"
#endif
//#include "../../include/net/hmac_com.h"
//#include "../hostapd/driver.h"
#if 0
struct wps_ap_info {
	atbm_uint8 bssid[ATBM_ETH_ALEN];
	atbm_uint8 ssid[ATBM_IEEE80211_MAX_SSID_LEN];
	atbm_uint8 ssid_len;
	enum wps_ap_info_type {
		WPS_AP_NOT_SEL_REG,
		WPS_AP_SEL_REG,
		WPS_AP_SEL_REG_OUR
	} type;
	atbm_uint8 wpa:1,
	   wps:1,
	   ssid_wildcard_ok:1,
	   p2p:1,
	   bcm_ap:1;
	atbm_int8 rssi;
	atbm_uint16 freq;
	atbm_uint16 caps;
	atbm_uint16 tries;
	//struct os_time last_attempt;
	atbm_void * bss; /*struct atbmwifi_cfg80211_bss **/
};
#endif
/**
 * struct wpa_config - wpa_supplicant configuration data
 *
 * This data structure is presents the per-interface (radio) configuration
 * data. In many cases, there is only one struct wpa_config instance, but if
 * more than one network interface is being controlled, one instance is used
 * for each.
 */
struct wpa_config {
	/**
	 * ssid - Head of the global network list
	 *
	 * This is the head for the list of all the configured networks.
	 */
	struct wpa_ssid *ssid;
	atbm_uint8 		ap_scan;
	int    fast_reauth;
};


struct wpa_supplicant {
	struct atbmwifi_vif *priv;
	int countermeasures;
	atbm_uint8 *own_addr;
	atbm_uint8 bssid[ATBM_ETH_ALEN];
#if 0
	atbm_uint8 pending_bssid[ATBM_ETH_ALEN]; /* If wpa_state == WPA_ASSOCIATING, this
				     * field contains the targer BSSID. */
#endif
	atbm_uint8 reassociate; /* reassociation requested */
	atbm_uint8 disconnected; /* all connections disabled; i.e., do no reassociate
			   * before this has been cleared */
	atbm_uint8 connect_retry;
	atbm_uint8 ap_ies_from_associnfo;
//	struct wpa_ssid *current_ssid;
	struct wpa_bss *current_bss;/*****原来被屏蔽掉邋******/
	unsigned int assoc_freq;

	/* Selected configuration (based on Beacon/ProbeResp WPA IE) */

	int pairwise_cipher;
	int group_cipher;
	int key_mgmt;
	int mgmt_group_cipher;
	int scan_runs; /* number of scan runs since WPS was started */
	atbm_uint32 wps_pin_start_time;
#if 0	
	atbm_void *drv_priv; /* private data used by driver_ops */
#endif
#define WILDCARD_SSID_SCAN ((struct wpa_ssid *) 1)

	struct atbmwifi_wpa_sm *wpa;
//	struct eapol_sm *eapol;

	enum atbm_wpa_states wpa_state;
#if 0
	atbm_uint8 scanning;
	atbm_uint8 sched_scanning;
	atbm_uint8 sched_scan_timed_out;
	int new_connection;/****原来被屏蔽掉****/
//	int reassociated_connection;
#endif
	int eapol_received; /* number of EAPOL packets received after the
			     * previous association event */

	unsigned char last_eapol_src[ATBM_ETH_ALEN];
	unsigned int drv_flags;

#ifdef CONFIG_WPS
	struct eap_wsc_data *wsc_data;
	atbm_uint8 *pin;
	enum {
		WPS_MODE_UNKNOWN = 0,
		WPS_MODE_PBC,
		WPS_MODE_PIN,
	} wps_mode;
	atbm_uint8 wps_ap_cnt;
#endif

#if 0
#ifdef CONFIG_WPS
	struct wps_context *wps;
	int wps_success; /* WPS success event received */
	struct wps_er *wps_er;
	int blacklist_cleared;
#endif /*CONFIG_WPS*/

struct ibss_rsn *ibss_rsn;

#ifdef CONFIG_SME
	struct {
		atbm_uint8 ssid[32];
		atbm_size_t ssid_len;
		int freq;
		atbm_uint8 assoc_req_ie[80];
		atbm_size_t assoc_req_ie_len;
		int mfp;
		int ft_used;
		atbm_uint8 mobility_domain[2];
		atbm_uint8 *ft_ies;
		atbm_size_t ft_ies_len;
		int auth_alg;
	} sme;
#endif /* CONFIG_SME */
#endif
#if 0
#ifdef CONFIG_AP
	struct hostapd_iface *ap_iface;
	atbm_void (*ap_configured_cb)(atbm_void *ctx, atbm_void *data);
	atbm_void *ap_configured_cb_ctx;
	atbm_void *ap_configured_cb_data;
#endif /* CONFIG_AP */

#ifdef CONFIG_P2P_SELF

	struct wifidirect_info *p2p_info;
#ifdef CONFIG_WIFI_DISPLAY
	struct wifi_display_info *wfd_info;
#endif

	unsigned int sta_scan_pending:1,
			p2p_auto_join:1,
			p2p_auto_pd:1,
			p2p_persistent_group:1,
			p2p_fallback_to_go_neg:1,
			p2p_pd_before_go_neg:1,
			p2p_go_ht40:1,
			p2p_cb_on_scan_complete:1;

#endif /*CONFIG_P2P_SELF*/

#ifdef CONFIG_P2P
	atbm_uint32 p2p_enable:1,
		off_channel_freq:1,
		show_group_started:1,
		pending_pd_before_join:1;
	atbm_uint16 max_remain_on_chan;
	struct p2p_go_neg_results *go_params;
	unsigned int pending_listen_freq;
	unsigned int pending_listen_duration;
	enum {
		NOT_P2P_GROUP_INTERFACE,
		P2P_GROUP_INTERFACE_PENDING,
		P2P_GROUP_INTERFACE_GO,
		P2P_GROUP_INTERFACE_CLIENT
	} p2p_group_interface;
	struct p2p_group *p2p_group;
	int p2p_long_listen; /* remaining time in long Listen state in ms */
	char p2p_pin[10];
	enum p2p_wps_method p2p_wps_method;
	atbm_uint8 p2p_auth_invite[ATBM_ETH_ALEN];
	atbm_uint16 p2p_in_provisioning;
	atbm_uint16 auto_pd_scan_retry;
	atbm_uint8 go_dev_addr[ATBM_ETH_ALEN];
	atbm_uint8 p2p_dev_addr[ATBM_ETH_ALEN];
	atbm_uint8 join_dev_name[CONFIG_MAX_NAME_LEN];
	//atbm_uint8 pending_join_iface_addr[ATBM_ETH_ALEN];
	//atbm_uint8 pending_join_dev_addr[ATBM_ETH_ALEN];
	atbm_uint8 pending_join_wps_method;
	atbm_uint16 p2p_join_scan_count;
	atbm_uint16 pending_pd_config_methods;
	enum {
		NORMAL_PD, AUTO_PD_GO_NEG, AUTO_PD_JOIN
	} pending_pd_use;

	/*
	 * Whether cross connection is disallowed by the AP to which this
	 * interface is associated (only valid if there is an association).
	 */
	int cross_connect_disallowed;


	unsigned int sta_scan_pending:1,
				p2p_auto_join:1,
				p2p_auto_pd:1,
				p2p_persistent_group:1,
				p2p_fallback_to_go_neg:1,
				p2p_pd_before_go_neg:1,
				p2p_go_ht40:1,
				p2p_cb_on_scan_complete:1;
	int p2p_persistent_go_freq;
	//int p2p_persistent_id;
	int p2p_go_intent;
	int p2p_connect_freq;
	struct noa_attr noa_attr;

#if defined(ENABLE_STE_CHANGES) && defined(CONFIG_WIFI_DISPLAY)
	atbm_uint8 wfd_enable;
	atbm_uint8 session_avail;
	atbm_uint16 rtsp_ctrlport;
	atbm_uint8 wfd_device_type;
#endif //CONFIG_WIFI_DISPLAY
	struct p2p_data *p2p_data;
#endif /* CONFIG_P2P */

	//struct wpa_ssid *connect_without_scan;
#ifdef CONFIG_WPS
	struct wps_ap_info *wps_ap;
	atbm_size_t num_wps_ap;
	int wps_ap_iter;

	int after_wps;
	int known_wps_freq;
	unsigned int wps_freq;
	int wps_fragment_size;
#endif /*CONFIG_WPS*/
	unsigned int last_michael_mic_error;
	unsigned int pending_mic_error_report;
	unsigned int pending_mic_error_pairwise;
	unsigned int mic_errors_seen;
	struct wps_ap_info *connect_without_scan;
#endif
};

#endif /*WPA_SUPPLICANT_I_H*/
