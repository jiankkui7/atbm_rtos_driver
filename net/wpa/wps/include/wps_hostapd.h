/*
 * hostapd / WPS integration
 * Copyright (c) 2008-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPS_HOSTAPD_H
#define WPS_HOSTAPD_H

#ifdef CONFIG_WPS

int hostapd_init_wps(struct atbmwifi_vif *priv);
int hostapd_init_wps_complete(struct hostapd_data *hapd);
void hostapd_deinit_wps(struct hostapd_data *hapd);
int hostapd_cancel_wps(struct hostapd_data *hapd);
void hostapd_wps_timeout(void *eloop_ctx, atbm_void *timeout_ctx);

//void hostapd_wps_eap_completed(struct hostapd_data *hapd);
int hostapd_wps_button_pushed(struct hostapd_data *hapd, atbm_void* ctx);

void hostapd_wps_ap_pin_disable(struct hostapd_data *hapd);
//const char * hostapd_wps_ap_pin_get(struct hostapd_data *hapd);
//int hostapd_wps_ap_pin_set(struct hostapd_data *hapd, const char *pin,int timeout);
//int hostapd_wps_config_ap(struct hostapd_data *hapd, char *ssid,const char *auth, const char *encr, const char *key);
//int hostapd_wps_nfc_tag_read(struct hostapd_data *hapd,const struct wpabuf *data);
//struct wpabuf * hostapd_wps_nfc_config_token(struct hostapd_data *hapd,int ndef);
//struct wpabuf * hostapd_wps_nfc_hs_cr(struct hostapd_data *hapd, int ndef);
//int hostapd_wps_nfc_report_handover(struct hostapd_data *hapd,const struct wpabuf *req,const struct wpabuf *sel);
//struct wpabuf * hostapd_wps_nfc_token_gen(struct hostapd_data *hapd, int ndef);
//int hostapd_wps_nfc_token_enable(struct hostapd_data *hapd);
//void hostapd_wps_nfc_token_disable(struct hostapd_data *hapd);
int wps_add_pin(struct hostapd_data *hapd, atbm_void *ctx);

#endif /* CONFIG_WPS */
#endif /* WPS_HOSTAPD_H */
