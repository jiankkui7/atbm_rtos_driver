/**************************************************************************************************************
 * altobeam RTOS WSM host interface (HI) implementation
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#ifndef WPA__I_H
#define WPA__I_H
/*
****************************************************************
*
*wpa_supplicant and hostapd extern function
*
****************************************************************
*/
//#include "wpa_auth_i.h"
#include "atbm_type.h"
extern int eapol_input(struct atbmwifi_vif *priv,struct atbm_buff *skb);
extern atbm_void wpa_prepare_auth(struct atbmwifi_vif *priv);
extern struct wpa_supplicant * init_wpa_supplicant(struct atbmwifi_vif *priv);
extern atbm_void wpa_prepare_assciating(struct atbmwifi_vif *priv);
extern int wpa_connect_ap(struct atbmwifi_vif *priv,atbm_uint8 *essid,int essid_len,atbm_uint8 *key,int key_len,int key_mgmt,int keyid);
extern atbm_void wpa_supplicant_event_assoc(struct atbmwifi_vif *priv,atbm_uint16 res);
extern int hostapd_start(struct atbmwifi_vif *priv,const char *ssid,int ssid_len,char *key,int key_len,int key_mgmt);
extern struct hostapd_data *init_hostapd(struct atbmwifi_vif *priv);
extern atbm_void free_hostapd(struct atbmwifi_vif *priv);
extern atbm_void hostapd_run(struct atbmwifi_vif *priv,struct hostapd_sta_info *sta);
extern int hostapd_rx_assoc_req(struct atbmwifi_vif *priv,struct atbm_buff *skb);
//extern void hostapd_rx_auth(struct atbmwifi_vif *priv,struct atbm_buff *skb);
atbm_void wpa_disconnect(struct atbmwifi_vif *priv);
atbm_void wpa_event_run(struct atbmwifi_vif *priv);
atbm_void wpa_timer_free(atbm_void);
atbm_void hostapd_setup_4_way_handshake(struct atbmwifi_vif *priv,atbm_uint8 *da);
atbm_void wpa_supplicant_event_disauthen(struct atbmwifi_vif *priv,atbm_uint16 res);
FLASH_FUNC atbm_void wpa_supplicant_event_disassoc(struct atbmwifi_vif *priv);
FLASH_FUNC atbm_void free_wpa_supplicant(struct atbmwifi_vif *priv);
int eloop_register_task(atbm_void *user_data1,atbm_void *user_data2);
atbm_uint16 check_ssid(struct atbmwifi_cfg *config, 
		      const atbm_uint8 *ssid_ie, atbm_size_t ssid_ie_len);


#endif /*WPA_SUPPLICANT_I_H*/
