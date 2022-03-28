/**************************************************************************************************************
 * altobeam RTOS WSM host interface (HI) implementation
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#ifndef _HOSTAPD_MAIN_H
#define _HOSTAPD_MAIN_H
#include "wpa_auth_i.h"

#ifdef CONFIG_WPS
#include "wps.h"
#include "wps_i.h"
#endif

typedef enum {
	WPA_AUTH, WPA_ASSOC, WPA_DISASSOC, WPA_DEAUTH, WPA_REAUTH,
	WPA_REAUTH_EAPOL, WPA_ASSOC_FT
} wpa_event;

#define WPA_SEND_EAPOL_TIMEOUT 5 //second
/**
 * struct hostapd_data - hostapd per-BSS data structure
 */

struct hostapd_data {
    struct atbmwifi_vif *priv;
	atbm_uint8 own_addr[ATBM_ETH_ALEN];
	
	struct atbmwifi_wpa_group group;

	int num_sta; /* number of entries in sta_list */
	struct hostapd_sta_info *sta_list[ATBMWIFI__MAX_STA_IN_AP_MODE]; /* STA info list head */

//#define AID_WORDS ((ATBMWIFI__MAX_STA_IN_AP_MODE + 31) / 32)
	//atbm_uint32 sta_aid[AID_WORDS];

//	time_t michael_mic_failure;
	int michael_mic_failures;
	int tkip_countermeasures;
	
//	int beacon_set_done;
#ifdef CONFIG_WPS
	struct wps_context *wps;
//int beacon_set_done
	struct wpabuf *wps_beacon_ie;
	struct wpabuf *wps_probe_resp_ie;
	struct wps_data *wpsdata;
	struct wpabuf *wps_last_rx_data;
	struct atbmwifi_ieee802_1x_hdr *wps_tx_hdr;
	int wps_tx_hdr_len;
#endif

#if 0
#ifdef CONFIG_WPS	
    struct wps_context *wps;

	struct wpabuf *wps_beacon_ie;
	struct wpabuf *wps_probe_resp_ie;
	unsigned int ap_pin_failures;
	unsigned int ap_pin_failures_consecutive;
	unsigned int ap_pin_lockout_time;
#if 0
	struct hostapd_probereq_cb *probereq_cb;
#endif
	atbm_size_t num_probereq_cb;
	
	atbm_void (*wps_reg_success_cb)(atbm_void *ctx, const atbm_uint8 *mac_addr,
				   const atbm_uint8 *uuid_e);
	atbm_void *wps_reg_success_cb_ctx;

	atbm_void (*wps_event_cb)(atbm_void *ctx, enum wps_event event,
				 union wps_event_data *data);
	atbm_void *wps_event_cb_ctx;
#endif /* CONFIG_WPS */

	atbm_void (*public_action_cb)(atbm_void *ctx, const atbm_uint8 *buf, atbm_size_t len,
				 int freq);
	atbm_void *public_action_cb_ctx;

	int (*vendor_action_cb)(atbm_void *ctx, const atbm_uint8 *buf, atbm_size_t len,
				int freq);
	atbm_void *vendor_action_cb_ctx;

	atbm_void (*sta_authorized_cb)(atbm_void *ctx, const atbm_uint8 *mac_addr,
				  int authorized, const atbm_uint8 *p2p_dev_addr);
	atbm_void *sta_authorized_cb_ctx;

	atbm_void (*setup_complete_cb)(atbm_void *ctx);
	atbm_void *setup_complete_cb_ctx;


#ifdef CONFIG_P2P
	struct p2p_data *p2p;
	struct p2p_group *p2p_group;
	struct wpabuf *p2p_beacon_ie;
	struct wpabuf *p2p_probe_resp_ie;

	/* Number of non-P2P association stations */
	int num_sta_no_p2p;

	/* Periodic NoA (used only when no non-P2P clients in the group) */
	int noa_enabled;
	int noa_start;
	int noa_duration;
	int noa_interval;

	/* P2P power save parameters */
	int legacy_ps;
	int opp_ps;
	int ctwindow;
#endif /* CONFIG_P2P */
#endif
};

atbm_void hostap_sta_del(struct atbmwifi_vif *priv,atbm_uint8 * staMacAddr);
#define hostapd_send_eapol(priv,da,proto,buf,len)  wpa_drv_send_eapol(priv,da,proto,buf,len)
#define hostapd_init_extra_ie(priv) wpa_comm_init_extra_ie(priv)

#endif
