#ifndef _WIFI_H_
#define _WIFI_H_

#include "lwip/ip_addr.h"

/** Character, 1 byte */
typedef signed char t_s8;
/** Unsigned character, 1 byte */
typedef unsigned char t_u8;

/** Short integer */
typedef signed short t_s16;
/** Unsigned short integer */
typedef unsigned short t_u16;

/** Integer */
typedef signed int t_s32;
/** Unsigned integer */
typedef unsigned int t_u32;

/** Long long integer */
typedef signed long long t_s64;
/** Unsigned long long integer */
typedef unsigned long long t_u64;

/** Void pointer (4-bytes) */
typedef void t_void;


//set wifi module
typedef enum
{
	WIFI_MODE_AP = 0, 
	WIFI_MODE_STA,
	WIFI_MODE_ADHOC,
	WIFI_MODE_UNKNOWN
	
}AK_WIFI_MODE;

#define MAC_ADDR_LEN  	6
#define MAX_SSID_LEN 	32
#define MIN_KEY_LEN  	8
#define MAX_KEY_LEN  	64
#define MAX_AP_COUNT 	100
#define MAX_STA_COUNT 	16
#if 0
enum wifi_security 
{
    SECURITY_OPEN               = 0,
    SECURITY_WPA_AES_PSK        = 1, // WPA-PSK AES
    SECURITY_WPA2_AES_PSK       = 2, // WPA2-PSK AES
    SECURITY_WEP_PSK            = 3, // WEP+OPEN
    SECURITY_WEP_SHARED         = 4, // WEP+SHARE
    SECURITY_WPA_TKIP_PSK       = 5, // WPA-PSK TKIP
    SECURITY_WPA2_TKIP_PSK      = 6, // WPA2-PSK TKIP
    SECURITY_WPA2_MIXED_PSK     = 7  // WPA2-PSK AES & TKIP MIXED
} wifi_security_e;
#endif
typedef enum
{
	KEY_NONE = 0, KEY_WEP, KEY_WPA, KEY_WPA2, KEY_MAX_VALUE
} SECURITY_TYPE;

typedef struct _WIFI_INITPARAM{
	unsigned int size;
	unsigned char *cache;
}T_WIFI_INITPARAM, *T_pWIFI_INITPARAM;

extern struct net_device *wifi_dev;

#define WIFI_MAX_CLIENT_DEFAULT 4


#if 0
#define DOT11N_ENABLE 1
#define DOT11N_DISABLE 0
#define DEFAULT_MAX_TX_PENDING 100

#define UDP_MTU  (1460) 
#endif



#define SECURITY_STR(val) 				(( val == SECURITY_OPEN ) ? "Open" : \
								         ( val == SECURITY_WEP_PSK ) ? "WEP" : \
								         ( val == SECURITY_WPA_TKIP_PSK ) ? "WPA TKIP" : \
								         ( val == SECURITY_WPA_AES_PSK ) ? "WPA AES" : \
								         ( val == SECURITY_WPA2_AES_PSK ) ? "WPA2 AES" : \
								         ( val == SECURITY_WPA2_TKIP_PSK ) ? "WPA2 TKIP" : \
								         ( val == SECURITY_WPA2_MIXED_PSK ) ? "WPA2 Mixed" : \
                						 "Unknown")



struct _apcfg
{
	unsigned char mac_addr[MAC_ADDR_LEN];
	unsigned char ssid[MAX_SSID_LEN];
	unsigned int  ssid_len;
	unsigned char mode;    // bg, bgn, an,...
	unsigned char channel;
	unsigned char txpower; //0 means max power
	unsigned int  enc_protocol; // encryption protocol  eg.wep, wpa, wpa2 
	unsigned char key[MAX_KEY_LEN];
	unsigned int  key_len;
	
};

typedef struct wifi_ap_info {
    t_u8   ssid[MAX_SSID_LEN];
    t_u8   bssid[MAC_ADDR_LEN];
    t_u32  channel;
    t_u32  security;
    t_u32  rssi;
} wifi_ap_info_t;

typedef struct wifi_ap_list
{
	t_u16  ap_count;
	wifi_ap_info_t ap_info[MAX_AP_COUNT];
}wifi_ap_list_t;

typedef struct wifi_sta_info 
{
    t_u8  mac_address[MAC_ADDR_LEN];
	t_u8  rssi;
	t_u8  rate;
} wifi_sta_info_t;

typedef struct wifi_sta_list
{
	t_u16  sta_count;
	wifi_sta_info_t sta_info[MAX_STA_COUNT];
} wifi_sta_list_t;


#define WAKEUP_PKT_MAX  512
#define KEEP_ALIVE_PKT_MAX 128  /*can not enlarge this value as the lower layer have limitation*/

typedef struct _net_wakeup_cfg{	
	unsigned int   wakeup_data_offset; /*offset  of  the head of  ethernet II*/
	unsigned int   wakeup_data_len;
	unsigned char  wakeup_data[WAKEUP_PKT_MAX];
}net_wakeup_cfg_t;


typedef struct _power_save_t {
	unsigned int ps_mode; /*0:disable, 1: Auto mode, 2: PS-Poll mode, 3: PS Null mode */
	unsigned int delay_to_ps;
	unsigned int dtim_interval;
	unsigned int ps_null_interval;
} power_save_t;

typedef struct _keep_alive_t {
	unsigned char enable;
	unsigned short send_interval; // send interval in second
	unsigned short retry_interval;// retry interval in second
	unsigned short retry_count;
	unsigned long  dst_ip;
	unsigned short dst_port;
	unsigned short payload_len;
	unsigned char payload[KEEP_ALIVE_PKT_MAX];
} keep_alive_t;


typedef struct _smc_ap_info_t
{
	unsigned char  ssid[33]; /*max ssid 32 + \0*/
	unsigned char  bssid[6];
	unsigned char  channel;
	unsigned char  security;
	unsigned char  security_key_length;
	unsigned char  security_key[65]; /*max key 64 + \0*/
} smc_ap_info_t;

enum dhcp_mode{
    DHCP_MODE_STATIC,           // static every time
    DHCP_MODE_DYNAMIC_FIRST,    // dhcp first at wifi init, get ip from back at wifi resume  
    DHCP_MODE_DYNAMIC_EVERY,    // dhcp every time
};

#if 1
typedef struct ip_info
{
	ip_addr_t ipaddr;
	ip_addr_t netmask;
	ip_addr_t gw;
}ip_info_t;
#else
typedef struct ip_info
{
	unsigned int ipaddr;
	unsigned int netmask;
	unsigned int gw;
}ip_info_t;
#endif

/* Max WPA2 passphrase can be upto 64 ASCII chars */
#define PSK_MAX_LENGTH		64
#define PMK_LENGTH		   32


typedef struct bss_descriptor{
	uint16_t 	essid_len;
	uint8_t 	essid[32];  		// essid
	uint8_t 	bssid[6];  			//mac地址
	uint8_t     mode;                //mode infra or adhoc
	uint8_t		proto;   			//安全认证类型
	uint8_t		cipher;   			//加密模式
	uint8_t		channel;   			//频道
	uint32_t	freq;				//频率
	uint32_t	rssi;				//信号强度
	uint8_t     psk[PSK_MAX_LENGTH]; //Pre-shared key (network password). max len 64 
	uint32_t    psk_len;             //psk length
	uint8_t 	pmk[PMK_LENGTH];  	 //pmk
	uint32_t    bss_ds_size;         //bss decriptor info size 
	uint8_t		bss_ds_buf[512]; //buf to store bss decriptor info scanned
}bss_descriptor_t;

struct wifi_info
{
	ip_info_t ip_info;
	bss_descriptor_t bss_descriptor;
};


//user interface to control wifi
char *wifi_get_version();
/**
 * @brief  wifi_get_mode, get wifi mode
 * @param  : 
 * @retval AK_WIFI_MODE
 */
int wifi_get_mode();

/**
 * @brief  wifi_set_mode, set wifi mode.
 * ap_wifi_dev and sta_wifi_dev are two different device, set mode just set the global variable wifi_dev
 * @param  : 
 * @retval AK_WIFI_MODE
 */
int wifi_set_mode(int type);  

/**
 * @brief  wifi_connect, wifi connect to ap 
 * @param  : ssid, key
 * @retval 0 - send connect msg ok , -1 - some error happen 
 */		
int wifi_connect(char *ssid, char *password);

/**
 * @brief  wifi_quick_connect, wifi connect to ap in quick mode
 * @param  : [in]ssid, 
 * @param  : [in]key, 
 * @param  : [in/out]bss_saved, if essid and key is equal to value in bss_saved, 
 			 driver will connect with saved bss. If not equal driver will connect 
 			 with essid and save the bss info in bss_saved
 * @return:  0 - connected success, -1 failed 
 */
int wifi_quick_connect( unsigned char *essid,unsigned char *key, struct bss_descriptor *bss_saved);

/**
 * @brief  wifi_wps_connect, wifi connect to ap in wps mode
 * @param :[out] bss_connected,  if connected will return the AP info include ssid, psk etc.
 * @retval  0 - connected success, -1 failed 
 */

int wifi_wps_connect(struct bss_descriptor *bss_connected);


/**
 * @brief  wifi_isconnected, return wifi connect status
 * @param  : 
 * @retval 1 - connect , 0 - not connected 
 */  
int wifi_disconnect();

/**
 * @brief  wifi_isconnected, return wifi connect status
 * @param  : 
 * @retval 1 - connect , 0 - not connected 
 */
int wifi_isconnected(); 
/**
 * @brief  wifi_create_ap, destroy
 * @param  : 
 * @retval AK_WIFI_MODE
 */  	
int wifi_create_ap(struct _apcfg *ap_cfg);

/**
 * @brief  wifi_destroy_ap, destroy
 * @param  : 
 * @retval AK_WIFI_MODE
 */
int wifi_destroy_ap();

//kernel interface for lwip interface
int wifi_get_mac(unsigned char *mac_addr);
int wifi_init(int fast_link);
int wifi_set_txpower(unsigned char dbm);
int wifi_sleep();
int wifi_wakeup();

int wifi_netif_init(void);
int wifistation_netif_init(void);
int wifistation_netif_deinit(void);
int wifistation_netif_set_dhcp(enum dhcp_mode mode,const char *ip_str);
int wifistation_netif_get_ip(void);

/**
 * @brief  配置省电模式,在保持连接的情况下可达到很可观省电效果
 *		省电模式下的耗电量由数据收发量决定
 *		此外用户可以配置更加细节的电源管理参数,比如DTIM间隔
 *		一般情况下使用此函数已经够用
 *
 * @param  power_save_level : 取值 0,1,2; 
 *	0 PM0 No power save
 *	1 PM1
 *  2 PM2 with sleep delay
 * @param  mac : 指向需要获取的station的地址
 */
int wifi_power_cfg(unsigned char power_save_level);

int wifi_ps_status();

int wifi_keepalive_set(keep_alive_t *keep_alive);
int wifi_keepalive_get(keep_alive_t *keep_alive);
 

int wifi_smc_start(smc_ap_info_t *ret_ap_info);
 

int wifi_smc_stop();


int wifi_sleep();

int wifi_wakeup(void);
int wifi_check_wakeup_status(void);

int wifi_list_station(wifi_sta_list_t *sta_list);
int wifi_scan(wifi_ap_list_t *ap_list);

char wifi_init_check();

int wifi_get_tx_pending();
int wifi_set_max_tx_pending(unsigned char max_tx_pending);
int wifi_get_max_tx_pending();

/**
 * @brief  wifi_netif_init, init wifi netif dev ap mode
 * @param  : 
 * @retval AK_WIFI_MODE
 */
int wifi_netif_init();

/**
 * @brief  wifi_netif_init, init wifi netif dev for station mode
 * @param  : 
 * @retval AK_WIFI_MODE
 */
int wifistation_netif_init();

/*
*
*@brief start scan to find the target ssid,
*@param: in_ssid, desired ssid prefix
*@param: out_ssid, scanned ssid match the prefix,  the strongest signal strength
*@param: try_cnt the desired try count
*/
int ak_wifi_scan_dest_ssid(unsigned char *in_ssid, wifi_ap_info_t *out_ssid, int try_cnt);

/*
*
*@brief connect to the target ssid,
*it will do connect more than one time
*@param: ssid, desired ssid prefix
*@param: key, desired password
*@param: try_cnt, try connect count
*@retval: 0 - wifi connect ok , -1 - some error happen
*/
int ak_wifi_connect(char *essid, char *key, int try_cnt);

#endif
