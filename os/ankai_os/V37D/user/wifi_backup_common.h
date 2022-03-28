/**
 * @file 
 * @brief: 
 *
 * This file describe 
 * Copyright (C) 2010 Anyka (GuangZhou) Software Technology Co., Ltd.
 * @author  
 * @date    2017-9-15
 * @version 1.0
 */

#ifndef _WIFI_BACKUP_COMMON_H_
#define _WIFI_BACKUP_COMMON_H_

#include "wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "ip_addr.h"

#define SDIO_BACK_DATA_MAX_SIZE 1024

#define MODE_READ    0
#define MODE_WRITE   1

#define MAC_ADDR_LEN  	6
#define MAX_SSID_LEN 	32
#define MIN_KEY_LEN  	8
#define MAX_KEY_LEN  	64
#define MAX_AP_COUNT 	100
#define MAX_STA_COUNT 	16


#if 0

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
	uint8_t 	pmk[32];  			//pmk
	uint32_t    bss_ds_size;        //bss decriptor info size 
	uint8_t		bss_ds_buf[512]; //buf to store bss decriptor info scanned
}bss_descriptor_t;


struct wifi_info
{
	ip_info_t ip_info;
	bss_descriptor_t bss_descriptor;
};
#endif


struct _conn_param
{
	unsigned char essid[MAX_SSID_LEN];
	unsigned char password[MAX_KEY_LEN];
};

struct server_info
{
	unsigned char essid[MAX_SSID_LEN]; /*ap ssid*/
	unsigned char password[MAX_KEY_LEN];/*ap password*/
	unsigned int server_ip;             /*p2p server ip*/
	unsigned short server_port;         /*p2p server port*/ 

};

//unsigned char wifi_backup_flash_value(char mode, char *data, int len);

int sdio_backup_flash_value(char mode, char *data, int len);

/**
 * wifi_backup_usr_data - backup/restore user data on flash 
 * @param partition - partition name
 * @param mode -  1 -write, 0 -read.
 * @param data - data pointer
 * @param len  -  data len
 * @return 0 - success -1 failed
 */
int wifi_backup_usr_data(int mode, struct wifi_info *info, int len);

/*
*@brief restore sdio data
*@return 0 - restore ok, -1 others 
*/
int wifi_restore_sdio_data();

/*
*@brief backup sdio data
*@return 0 - backup ok, -1 others 
*/

int wifi_backup_sdio_data();

/**
 * backup IP address configuration for a network interface (including netmask
 * and default gateway).
 *
 * @param ip_info the network interface if infomation including ip gw netmask
 */
int wifi_back_ip_info(struct ip_info *t_ip_info);
/**
 * resrote IP address configuration for a network interface (including netmask
 * and default gateway).
 *
 * @param ip_info the network interface if infomation including ip gw netmask
 */
int wifi_restore_ip_info(struct ip_info *t_ip_info);


/*@}*/
#ifdef __cplusplus
}
#endif

#endif //#ifndef _WIFI_BACKUP_COMMON_H_




