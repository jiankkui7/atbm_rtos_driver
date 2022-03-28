/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#ifndef ATBM_CFG_H_
#define ATBM_CFG_H_

#undef ARP_OFFLOAD
#undef CONFIG_INET
#undef CONFIG_ATBMWIFI__TESTMODE
#undef CONFIG_ATBMWIFI__ITP
#undef CONFIG_ATBMWIFI__DEBUGFS
#undef CONFIG_BT_COEX
#undef ROAM_OFFLOAD
#undef CONFIG_WAPI
#undef CONFIG_WIFI_IBSS
#undef CONFIG_ACTTION_RETURN
#undef CONFIG_P2P_PS
#undef CONFIG_SMPS
#undef CONFIG_NET_NS
/*may need define */
#undef CONFIG_WEP_SHARE_KEY
#undef DOWNLOAD_FW
#undef CONFIG_80211D
#undef CONFIG_COMBS_IFACE
/*5G support*/
#undef CONFIG_ATBMWIFI__5GHZ_SUPPORT
#undef CONFIG_5G_SUPPORT
#undef CONFIG_MONITOR
/*hostapd*/
#define NEED_AP_MLME
#define CONFIG_IEEE80211N
#define CONFIG_ATBMWIFI__USE_STE_EXTENSIONS
#define CONFIG_HT_MCS_STREAM_MAX_STREAMS	1
#define ATBM_ARRAY_SIZE(_array) (sizeof(_array)/sizeof(_array[1]))
#define ATBM_RX_TASK 1
#define TEST_KEY_TYPE		0
/*WPS*/
#define CONFIG_WPS
//#define CONFIG_WPS2
//#define CONFIG_P2P
/*
wep_40  len = 5
wep_104  len = 13
tkip 16+8+8
aes  32
wapi 32
*/
#define TEST_KEY_LEN		0
/*
*/
#define TEST_KEY_DATA		0x01,0x02

#define RATE_INDEX_B_1M           0
#define RATE_INDEX_B_2M           1
#define RATE_INDEX_B_5_5M         2
#define RATE_INDEX_B_11M          3
#define RATE_INDEX_PBCC_22M       4     // not supported/unused
#define RATE_INDEX_PBCC_33M       5     // not supported/unused
#define RATE_INDEX_A_6M           6
#define RATE_INDEX_A_9M           7
#define RATE_INDEX_A_12M          8
#define RATE_INDEX_A_18M          9
#define RATE_INDEX_A_24M          10
#define RATE_INDEX_A_36M          11
#define RATE_INDEX_A_48M          12
#define RATE_INDEX_A_54M          13
#define RATE_INDEX_N_6_5M         14
#define RATE_INDEX_N_13M          15
#define RATE_INDEX_N_19_5M        16
#define RATE_INDEX_N_26M          17
#define RATE_INDEX_N_39M          18
#define RATE_INDEX_N_52M          19
#define RATE_INDEX_N_58_5M        20
#define RATE_INDEX_N_65M          21
#define RATE_INDEX_N_MCS32_6M        22
#define RATE_INDEX_MAX         		23
#define TEST_RATE_AUTOCTRL 0xff
/*max num is 0xf*/
#define TEST_BASIC_RATE		(BIT(0)|BIT(1)|BIT(2)|BIT(3)|BIT(6)|BIT(8)|BIT(10)|BIT(11))
#define TEST_LONG_RETRY_NUM		4
#define TEST_SHORT_RETRY_NUM	7
/*short 1:long 0*/
#define TEST_LONG_PREAMBLE		0
#define TEST_SHORT_PREAMBLE		1
/*0 - Mixed, 1 - Greenfield*/
#define MODE_11N_MIXED			0
#define MODE_11N_GREENFIELD		1

#define	TEST_RX_NO_COUNT		0
#define TEST_RX_COUNT			1

/*set 1 ,if need send this AC queue data frame*/
#define TEST_SEND_AC_0			1
#define TEST_SEND_AC_1			0
#define TEST_SEND_AC_2			0
#define TEST_SEND_AC_3			0
#define TEST_BEACON_INTV    	100
#define TEST_DTIM_INTV    		3
#define TEST_CHANNEL_VALUE    	1
#define TEST_AP_SSID "wifi_test_ap11"
#define TEST_AP_PWD "1234567890"
#define TEST_AP_KEYMGM ATBM_KEY_WPA2
#define DEFAULT_BEACON_LOSS_CNT      40
#define ATBMWIFI__KEEP_ALIVE_PERIOD	(4)
#define ATBM_USB_BUS 0
#define ATBM_SDIO_BUS 1
#define ATBM_PKG_REORDER 1
#define BW_40M_SUPPORT  0
#define USE_MAIL_BOX 0
#define ATBM_RX_TASK_QUEUE 1
#define ATBM_TCPIP_BUFFER_FAST_FREE 0

#define RATE_CONTROL_MODE 1//1:pid ,2 minstrel

#define FAST_CONNECT_MODE 1
#define FAST_CONNECT_NO_SCAN 1
#define ATBM_SUPPORT_SMARTCONFIG 1
#define ATBM_HW_CHECKSUM 0
#define WLAN_ZERO_COPY 0
#if (ATBM_SDIO_BUS)
#define ATBM_TX_SKB_NO_TXCONFIRM 0
#endif

#if (ATBM_USB_BUS)
#define ATBM_TX_SKB_NO_TXCONFIRM 1
#define CONFIG_USB_AGGR_URB_TX 0
#define ATBM_IMMD_RX 1
#define ATBM_DIRECT_TX 1
#define HI_RX_MUTIL_FRAME 0
#endif
#define NEW_SUPPORT_PS 0
#define TEST_DCXO_DPLL_CONFIG 0
#define ATBM_WSM_SDIO_TX_MULT 0
#define ATBM_AP_MODE        1
#define STM32_UCOS 1

/*=============WIFI CHIP Info Start==============*/
#define ATHENA_LITE 0
#define ATHENA_B	1
#define ARES_A  	 2
#define ARES_B  	 3

#ifndef PROJ_TYPE
#define PROJ_TYPE  ARES_B
#endif
/*=============WIFI CHIP Info End==============*/

/*CUSTOM SELECT */
#define JIANRONG_RTOS_3298 0
#define JIANRONG_RTOS_3268 1
#define ALI_RTOS 2
#define AK_RTOS_200 3
#define AK_RTOS_300 4
#define AK_RTOS_37D 5

#define PLATFORM AK_RTOS_300


#endif /*ATBM_CFG_H_*/

