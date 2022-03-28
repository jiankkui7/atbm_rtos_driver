/*
 * wpa_supplicant/hostapd - Default include files
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This header file is included into all C files so that commonly used header
 * files can be selected with OS specific ifdef blocks in one place instead of
 * having to have OS/C library specific selection in many files.
 */

#ifndef INCLUDES_H
#define INCLUDES_H


#include "atbm_hal.h"
#include "wpa_main.h"
//#include "hmac_main.h"
#include "wpabuf.h"
#include "atbm_skbuf.h"
#include "atbm_debug.h"
#include "wpa_common.h"
#include "wpa_auth_i.h"
//#include "sha1.h"
#include "hostapd_main.h"
#include "hostapd_sta_info.h"
#include "wpa_supplicant_i.h"
#include "wpa_supplicant_i.h"
#include "wpa_main.h"
#include "wpa_common.h"
#include "wpa_timer.h"
//#include "oled/oled.h"
//#include "hmac_wifi_api.h"
#ifdef CONFIG_WPS
#include "wps_i.h"
#endif
//#include "mbedtls/config_atbm.h"
#include "wps_debug.h"

#include "crypto.h"
#include "sha256.h"
#include "wps_hostapd.h"
#include "eap_common.h"

#endif /* INCLUDES_H */
