#include <stdio.h>
#include <stdlib.h>
#include "atbm_os_app_api.h"
#include "atbm_hal.h"

#include "generalWifi.h"

static int wifi_inited = 0;

extern struct atbmwifi_common g_hw_prv;

extern struct wpa_supplicant *g_wpa_s;
#define STR2MAC		"%02x:%02x:%02x:%02x:%02x:%02x"
//#define MAC2STR(a)  a[0],a[1],a[2],a[3],a[4],a[5]

//#ifdef RT_USING_FINSH
typedef struct{
	char id;
	unsigned char ssid[33];
	unsigned char ssid_len;
	unsigned char psk[33];
	unsigned char psk_len;
	unsigned char key_mgmt;
	unsigned char used_flag;
	unsigned char active_stat;
}wpa_cfg_t;

typedef struct{
	FH_CHAR *ssid;
	FH_UINT32 ssid_len;
	FH_UINT32 start_chan;
	FH_UINT32 end_chan;
	FH_UINT32 max_ap_number;
}scan_param_t;




const char * wpa_supplicant_state_txt(enum atbm_wpa_states state)
{
	switch (state) {
	case ATBM_WPA_DISCONNECTED:
		return "DISCONNECTED";
	case ATBM_WPA_INACTIVE:
		return "INACTIVE";
	case ATBM_WPA_INTERFACE_DISABLED:
		return "INTERFACE_DISABLED";
	case ATBM_WPA_SCANNING:
		return "SCANNING";
	case ATBM_WPA_AUTHENTICATING:
		return "AUTHENTICATING";
	case ATBM_WPA_ASSOCIATING:
		return "ASSOCIATING";
	case ATBM_WPA_ASSOCIATED:
		return "ASSOCIATED";
	case ATBM_WPA_4WAY_HANDSHAKE:
		return "4WAY_HANDSHAKE";
	case ATBM_WPA_GROUP_HANDSHAKE:
		return "GROUP_HANDSHAKE";
	case ATBM_WPA_COMPLETED:
		return "COMPLETED";
	default:
		return "UNKNOWN";
	}
}

const char * wpa_key_mgmt_txt(int key_mgmt, int proto)
{
	switch (key_mgmt) {
	case ATBM_WPA_KEY_MGMT_IEEE8021X:
		if (proto == (ATBM_WPA_PROTO_RSN | ATBM_WPA_PROTO_WPA))
			return "WPA2+WPA/IEEE 802.1X/EAP";
		return proto == ATBM_WPA_PROTO_RSN ?
			"WPA2/IEEE 802.1X/EAP" : "WPA/IEEE 802.1X/EAP";
	case ATBM_WPA_KEY_MGMT_PSK:
		if (proto == (ATBM_WPA_PROTO_RSN | ATBM_WPA_PROTO_WPA))
			return "WPA2-PSK+WPA-PSK";
		return proto == ATBM_WPA_PROTO_RSN ?
			"WPA2-PSK" : "WPA-PSK";
	case ATBM_WPA_KEY_MGMT_NONE:
		return "NONE";
	case ATBM_WPA_KEY_MGMT_WPA_NONE:
		return "WPA-NONE";
	case ATBM_WPA_KEY_MGMT_IEEE8021X_NO_WPA:
		return "IEEE 802.1X (no WPA)";
#ifdef CONFIG_IEEE80211R
	case ATBM_WPA_KEY_MGMT_FT_IEEE8021X:
		return "FT-EAP";
	case ATBM_WPA_KEY_MGMT_FT_PSK:
		return "FT-PSK";
#endif /* CONFIG_IEEE80211R */
#ifdef CONFIG_IEEE80211W
	case ATBM_WPA_KEY_MGMT_IEEE8021X_SHA256:
		return "WPA2-EAP-SHA256";
	case ATBM_WPA_KEY_MGMT_PSK_SHA256:
		return "WPA2-PSK-SHA256";
#endif /* CONFIG_IEEE80211W */
	case ATBM_WPA_KEY_MGMT_WPS:
		return "WPS";
	default:
		return "UNKNOWN";
	}
}
const char * wpa_cipher_txt(int cipher)
{
	switch (cipher) {
	case ATBM_WPA_CIPHER_NONE:
		return "NONE";
	case ATBM_WPA_CIPHER_WEP40:
		return "WEP-40";
	case ATBM_WPA_CIPHER_WEP104:
		return "WEP-104";
	case ATBM_WPA_CIPHER_TKIP://WPA
		return "TKIP";
	case ATBM_WPA_CIPHER_CCMP://RSN
		return "CCMP";
	case ATBM_WPA_CIPHER_CCMP | ATBM_WPA_CIPHER_TKIP:
		return "CCMP+TKIP";
	case ATBM_WPA_CIPHER_GCMP:
		return "GCMP";
	default:
		return "UNKNOWN";
	}
}


/*
 * func: power up and recognize wifi, then initialize firmware
 * para1: mode (0: staion, 1: AP)
 * para2: sleep_flag (0: for common state, 1: for low power state)
 * XXX: multi-thread context
 * NOTE: w_start()/w_stop() should be called in the same thread
 
 运行sta/ap
 mode:
	0 station
	1 ap
sleep_flag:
	不支持休眠，驱动强制设置为0
 */

FH_SINT32 atbm_start(FH_UINT32 mode, FH_UINT32 sleep_flag)
{

	if(!wifi_inited){
		atbm_wifi_hw_init();
		wifi_inited = 1;
#ifndef WIFI_SDIO
		rt_thread_delay(150);
#endif
	}
/*
	atbm_wifi_off(mode1);
	rt_thread_delay(150);
*/
	
	atbm_wifi_on(mode);
	
	return 0;
}
/*
 * func: stop wifi according to mode, including resource release of wifi and protocol stack
 * para1: mode (0: staion, 1: AP)
 * NOTE: w_start()/w_stop() should be called in the same thread
 
 wifi 进入idle状态
 
 */

FH_SINT32 atbm_stop(FH_UINT32 mode)
{
	
	if(!wifi_inited){
		atbm_wifi_hw_init();
		wifi_inited = 1;
#ifndef WIFI_SDIO
		rt_thread_delay(150);
#endif
	}
	/*
	i32current_mode =	atbm_wifi_get_current_mode_vif(mode);
	if(i32current_mode != mode){
		wifi_printk(WIFI_DBG_ERROR,"ERROR : current mode(%d),stop mode(%d) \n",i32current_mode,mode);
		return -1;
	}
	*/
	atbm_wifi_off(mode);
	
	return 0;
}
FH_SINT32 atbm_get_conn_ssid(char *buff)
{
	struct atbmwifi_vif *priv;
	if(!g_wpa_s){
		wifi_printk(WIFI_DBG_ERROR,"sta application(wpa_supplicant) not running \n");
		return -1;
	}
	//atbm_wifi_get_connected_info
	priv = g_wpa_s->priv;
	if (!atbmwifi_is_sta_mode(priv->iftype)){
		wifi_printk(WIFI_DBG_ERROR,"not sta mode \n");
		return -1;
	}
	if(buff){
		memcpy(buff,priv->config.ssid,priv->config.ssid_len);
		return 0;
	}else{
		wifi_printk(WIFI_DBG_ERROR,"atbm_sta_status:buff is NULL \n");
		return -1;
	}
}


	
FH_SINT32 atbm_sta_status(FH_VOID)
{
	struct atbmwifi_vif *priv ;
	if(!g_wpa_s){
		wifi_printk(WIFI_DBG_ERROR,"sta application(wpa_supplicant) not running \n");
		return -1;
	}
	//atbm_wifi_get_connected_info
	priv = g_wpa_s->priv;
	if (!priv && !atbmwifi_is_sta_mode(priv->iftype)){
		wifi_printk(WIFI_DBG_ERROR,"not sta mode \n");
		return -1;
	}
	if(g_wpa_s->wpa_state == ATBM_WPA_COMPLETED){
		wifi_printk(WIFI_DBG_ERROR,"IFNAME	= %s\n",priv->if_name);
		wifi_printk(WIFI_DBG_ERROR,"MacAddr	= "STR2MAC"\n",MAC2STR(priv->mac_addr));
		wifi_printk(WIFI_DBG_ERROR,"AP ssid	= %s\n",priv->config.ssid);
		wifi_printk(WIFI_DBG_ERROR,"AP mac	= "STR2MAC"\n",MAC2STR(priv->bssid));
		wifi_printk(WIFI_DBG_ERROR,"Channel	= %d\n",priv->config.channel_index);
		wifi_printk(WIFI_DBG_ERROR,"Rssi	= %d\n",atbm_wifi_get_rssi_avg());
		wifi_printk(WIFI_DBG_ERROR,"pairwise_cipher	= %s\n",wpa_cipher_txt(priv->config.pairwise_cipher));
		wifi_printk(WIFI_DBG_ERROR,"group_cipher	= %s\n",wpa_cipher_txt(priv->config.group_cipher));
		wifi_printk(WIFI_DBG_ERROR,"KeyMgmt	= %s\n",wpa_key_mgmt_txt(priv->config.key_mgmt,priv->config.wpa));
	}
	wifi_printk(WIFI_DBG_ERROR,"Status	= %s\n",wpa_supplicant_state_txt(g_wpa_s->wpa_state));	
	return 0;
}


FH_SINT32 atbm_rssi_get(FH_SINT16 *rssi)
{
	int rssi_val = 0;
	if(!g_wpa_s || !rssi){
		wifi_printk(WIFI_DBG_ERROR,"sta application(wpa_supplicant) not running or parameters is NULL \n");
		return -1;
	}
	if(g_wpa_s->wpa_state == ATBM_WPA_COMPLETED){
		rssi_val = atbm_wifi_get_rssi_avg();		
	}else{
		wifi_printk(WIFI_DBG_ERROR,"current status is [%s] \n",wpa_supplicant_state_txt(g_wpa_s->wpa_state));
		rssi_val=  0;
	}
	wifi_printk(WIFI_DBG_ERROR,"current rssi is [%d] \n",rssi_val);
	*rssi = rssi_val;
	return 0;
}








/*
	print current save BSS cfg
	return max id
*/
/*
	(1) 调用格式：fread(buf,sizeof(buf),1,fp);
读取成功时：当读取的数据量正好是sizeof(buf)个Byte时，返回值为1(即count)
                       否则返回值为0(读取数据量小于sizeof(buf))
(2)调用格式：fread(buf,1,sizeof(buf),fp);
读取成功返回值为实际读回的数据个数(单位为Byte)
*/
#define ATBM_CFG_FILE "atbm_cfg.txt"
#define SAVE_MAX_COUNT 5
wpa_cfg_t p_wpa_cfg[SAVE_MAX_COUNT];
/*

rw_flag:
	true : read file
	false: write file

*/
FH_SINT32 atbm_read_write_file(const char *file_name,char r_flag)
{
	FILE *file_fd;
	int read_num = -1,write_num = -1;
//	wifi_printk(WIFI_DBG_ERROR,"0----- \n");

	if(r_flag == 1){
		file_fd = fopen(file_name,"rb+");
	}else{
		file_fd = fopen(file_name,"wb+");
	}
	if(!file_fd){
		wifi_printk(WIFI_DBG_ERROR,"open %s error  \n",file_name);
		return -1;
	}
	if(r_flag == 1){
		read_num = fread(p_wpa_cfg,1,sizeof(wpa_cfg_t) * SAVE_MAX_COUNT,file_fd);
		if(read_num <= 0){
			wifi_printk(WIFI_DBG_ERROR,"read %s error  \n",ATBM_CFG_FILE);
			fclose(file_fd);
			return -1;
		}

	}else{
		write_num = fwrite(p_wpa_cfg,1,sizeof(wpa_cfg_t) * SAVE_MAX_COUNT,file_fd);
		if(write_num <= 0){
			wifi_printk(WIFI_DBG_ERROR,"write %s error  \n",ATBM_CFG_FILE);
			fclose(file_fd);
			return -1;
		}

	}
	fclose(file_fd);
	return 0;
}



FH_SINT32 atbmListCfg(FH_VOID)
{
	struct atbmwifi_vif *priv = NULL;
	int i = 0,ret = 0,sta_status = 0;
	
	if(g_wpa_s){
		wifi_printk(WIFI_DBG_ERROR,"Status	= %s\n",wpa_supplicant_state_txt(g_wpa_s->wpa_state));
		sta_status = g_wpa_s->wpa_state;
		if(g_wpa_s->wpa_state == ATBM_WPA_COMPLETED){
			priv = g_wpa_s->priv;
		}
	}
	
	if((ret = atbm_read_write_file(ATBM_CFG_FILE,1)) == 0){
	
		wifi_printk(WIFI_DBG_ERROR,"id		ssid		key	flags\n");
		for(i=0;i<SAVE_MAX_COUNT;i++){
			if(p_wpa_cfg[i].used_flag){
				if(priv){//connect success
					if(memcmp(p_wpa_cfg[i].ssid,priv->config.ssid,priv->config.ssid_len) == 0)
						p_wpa_cfg[i].active_stat = 1;
					else
						p_wpa_cfg[i].active_stat = 0;
				}else{
					p_wpa_cfg[i].active_stat = 0;
				}
				wifi_printk(WIFI_DBG_ERROR,"%d		%s		%d	%s\n",
				p_wpa_cfg[i].id - 1,p_wpa_cfg[i].ssid,p_wpa_cfg[i].key_mgmt,p_wpa_cfg[i].active_stat?"[CURRENT]":"");		
			}else{
				p_wpa_cfg[i].id = -1;
			}
		}	
	}
	
	return ret;
}
/*
 * func: add or delete a NULL profile of AP with specific id (Please refer to wpa_cli in linux)
 * para1: id (id for different APs)
 * para2: add (0: delete, 1: add)
 sta 模式下，需要多个ap信息，添加新的 ap 信息，或者删除旧的ap信息，类似 
 wpa_cli add_network id
 wpa_cli remove_network id
 */

FH_SINT32 atbmStaCfg_ap(FH_UINT32 id, FH_UINT32 add)
{
	int ret;
	if(id >= SAVE_MAX_COUNT){
		wifi_printk(WIFI_DBG_ERROR,"id[%d] not allow,max id %d \n",id,SAVE_MAX_COUNT-1);
		return -1;
	}
	memset(&p_wpa_cfg[id],0,sizeof(wpa_cfg_t));
	if(add){
		p_wpa_cfg[id].id = id+1;
		p_wpa_cfg[id].used_flag = 0;
	}else{
		if((ret = atbm_read_write_file(ATBM_CFG_FILE,0)) < 0){
			wifi_printk(WIFI_DBG_ERROR,"save file fail! delete %s fail! \n",p_wpa_cfg[id].ssid);
			return -1;
		}
	}
	
	wifi_printk(WIFI_DBG_ERROR,"atbmStaCfg_ap : id[%s] [%d] \n",add?"add":"delete",p_wpa_cfg[id].id);
	return 0;
}
/*
 * func: configure the ssid for a profile of AP with specific id (Please refer to wpa_cli in linux)
 * para1: id (id for different APs)
 * para2: ssid
 接着上一个函数的
 wpa_cli set_network id ssid xxx
 */

FH_SINT32 atbmStaCfg_ssid(FH_UINT32 id, FH_CHAR *ssid)
{
	int ssid_len;

	if(id >= SAVE_MAX_COUNT){
		wifi_printk(WIFI_DBG_ERROR,"id[%d] not allow,max id %d \n",id,SAVE_MAX_COUNT-1);
		return -1;
	}
	ssid_len = strlen(ssid);
	if(p_wpa_cfg[id].id == (id+1)){
		if(ssid_len < 33){
			memcpy(p_wpa_cfg[id].ssid,ssid,ssid_len);
			p_wpa_cfg[id].ssid_len = ssid_len;
			if(p_wpa_cfg[id].ssid_len != 0){
				p_wpa_cfg[id].used_flag = 1;
			}
		}else{
			wifi_printk(WIFI_DBG_ERROR,"ssid[%s],ssid len[%d] > 32\n",ssid,p_wpa_cfg[id].ssid_len);
			return -1;
		}
	}else{
		wifi_printk(WIFI_DBG_ERROR,"please need add id[%d]\n",id);
		return -1;
	}
	return 0;
}
/*
 * func: configure the passwd for a profile of AP with specific id (Please refer to wpa_cli in linux)
 * para1: id (id for different APs)
 * para2: passwd(NULL: open, WEP?)
 接着上一个函数的
 wpa_cli set_network id psk xxxxx
 */

FH_SINT32 atbmStaCfg_psk(FH_UINT32 id, FH_CHAR *passwd)
{
	
	int psk_len;

	if(id >= SAVE_MAX_COUNT){
		wifi_printk(WIFI_DBG_ERROR,"id[%d] not allow,max id %d \n",id,SAVE_MAX_COUNT-1);
		return -1;
	}
	psk_len = strlen(passwd);
	if(p_wpa_cfg[id].id == (id+1)){
		if(psk_len < 33){
			memcpy(p_wpa_cfg[id].psk,passwd,psk_len);
			p_wpa_cfg[id].psk_len = psk_len;
			p_wpa_cfg[id].key_mgmt = 1;
			if((p_wpa_cfg[id].ssid_len!=0) && (p_wpa_cfg[id].psk!=0)){
				p_wpa_cfg[id].used_flag = 1;
			}
		}else{
			wifi_printk(WIFI_DBG_ERROR,"passwd[%s],passwd len[%d] > 32\n",passwd,p_wpa_cfg[id].psk_len);
			return -1;
		}
	}else{
		wifi_printk(WIFI_DBG_ERROR,"please need add id[%d]\n",id);
		return -1;
	}
	return 0;
}
/*
 * func: connect AP with a profile id of AP(Please refer to wpa_cli in linux)
 * para1: id (configured id for different APs)
 选择这个ap 进行连接
 wpa_cli enable_network id
 */


FH_SINT32 atbmStaConn_ap(FH_UINT32 id)
{
	int ret;
	int retry = 100;

	int i = 0,mode;

	
	if(id >= SAVE_MAX_COUNT){
		wifi_printk(WIFI_DBG_ERROR,"id[%d] not allow,max id %d \n",id,SAVE_MAX_COUNT-1);
		return -1;
	}
	
	if(p_wpa_cfg[id].used_flag == 0){
		wifi_printk(WIFI_DBG_ERROR,"id[%d]  is NULL \n",id);
		return -1;
	}
	
	
	if(!wifi_inited){
		atbm_wifi_hw_init();
		wifi_inited = 1;
#ifndef WIFI_SDIO
		rt_thread_delay(150);
#endif
	}
	for(i = 0;i < 2;i++){
		if((mode = atbm_wifi_get_current_mode_vif(i)) >= 0){
			atbm_wifi_off(mode);
			rt_thread_delay(150);
			break;
		}
	}
	
	atbm_wifi_on(0);
	wifi_printk(WIFI_DBG_ERROR,"join--ap:\n");
	if(p_wpa_cfg[id].key_mgmt)
    	ret = atbm_wifi_sta_join_ap(p_wpa_cfg[id].ssid, RT_NULL, 4, 0, p_wpa_cfg[id].psk);
	else
		ret = atbm_wifi_sta_join_ap(p_wpa_cfg[id].ssid, RT_NULL, 0, 0, RT_NULL);
    if (ret)
    {
        wifi_printk(WIFI_DBG_ERROR,"%s-%d fail, ret %d\n", __func__, __LINE__, ret);
		return -1;
    }
	atbm_read_write_file(ATBM_CFG_FILE,0);
	while(retry--){
		if(atbm_wifi_isconnected(0)){
			for(i = 0;i<SAVE_MAX_COUNT;i++){
				p_wpa_cfg[i].active_stat = 0;
			}
			wifi_printk(WIFI_DBG_ERROR,"connect %s success  \n",p_wpa_cfg[id].ssid);
			p_wpa_cfg[id].active_stat = 1;	
			atbm_read_write_file(ATBM_CFG_FILE,0);
			break;
		}
		rt_thread_delay(10);
	}
	
	return 0;
	
}
/* disconnect ap and delete cfg ap in station mode
	sta模式下断开和ap的连接并且删除配置
 */

FH_SINT32 atbmStaDel_ap(FH_UINT32 id)
{
	int ret = 0;
	char ssid[33]={0};
	if(atbm_get_conn_ssid(ssid) < 0 || p_wpa_cfg[id].active_stat == 0){
		wifi_printk(WIFI_DBG_ERROR,"atbmStaDel_ap : not connect!  \n");
		return -1;
	}
	if(memcmp(p_wpa_cfg[id].ssid,ssid,p_wpa_cfg[id].ssid_len) == 0){
		if((ret = atbm_wifi_sta_disjoin_ap()) < 0){
			wifi_printk(WIFI_DBG_ERROR,"connect %s sunncess  \n",p_wpa_cfg[id].ssid);
			return ret;
		}
		memset(&p_wpa_cfg[id],0,sizeof(wpa_cfg_t));
		if((ret = atbm_read_write_file(ATBM_CFG_FILE,0)) < 0){
			wifi_printk(WIFI_DBG_ERROR,"save file fail! delete %s fail! \n",p_wpa_cfg[id].ssid);
			return -1;
		}
	}else{
		wifi_printk(WIFI_DBG_ERROR,"connect ap[%s],del ssid[%s] \n",ssid,p_wpa_cfg[id].ssid);
	}
	return 0;
}

/*
强制断开连接

*/
FH_SINT32 atbmStaDis_ap(FH_UINT32 id)
{
	int i,ret;
	
	atbm_wifi_sta_disjoin_ap();
	for(i=0;i<SAVE_MAX_COUNT;i++){
		if(p_wpa_cfg[i].used_flag)
			p_wpa_cfg[i].active_stat = 0;		
	}	
	if((ret = atbm_read_write_file(ATBM_CFG_FILE,0)) < 0){
		wifi_printk(WIFI_DBG_ERROR,"save file fail! delete %s fail! \n",p_wpa_cfg[id].ssid);
		return -1;
	}
	return 0;
}



int atbmwifi_scan_triger(struct atbmwifi_vif *priv,scan_param_t * scan_param)
{
	int ret;
	int i;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	struct wsm_ssid ssids;
    struct wsm_scan scan;

	atbm_memset(&ssids, 0, sizeof(struct wsm_ssid));
	atbm_memset(&scan, 0, sizeof(struct wsm_scan));

	atbm_uint8 all_channel[14] = {1,2,3,4,5, 6,7,8,9,10,11,12,13,14};


	if (!priv)
	{
		wifi_printk(WIFI_SCAN,"atbm_scan_work");
	}
	scan.scanType = WSM_SCAN_TYPE_FOREGROUND;
	scan.scanFlags =0;
	scan.numOfProbeRequests = 2;
	scan.probeDelay = 100;
	scan.numOfChannels = scan_param->end_chan - scan_param->start_chan + 1/*atbmwifi_band_2ghz.n_channels*/;
	priv->scan.status = 0;
	priv->scan.if_id = priv->if_id;
	priv->scan.in_progress = 1;
	scan.maxTransmitRate = WSM_TRANSMIT_RATE_1;

	
	if (priv->scan.direct_probe){
		scan.maxTransmitRate = WSM_TRANSMIT_RATE_6;
	}



	scan.band =  WSM_PHY_BAND_2_4G;
	if (priv->join_status == ATBMWIFI__JOIN_STATUS_STA) {
		scan.scanType = WSM_SCAN_TYPE_BACKGROUND;
		scan.scanFlags = WSM_SCAN_FLAG_FORCE_BACKGROUND;
		if (priv->if_id)
			scan.scanFlags |= WSM_FLAG_MAC_INSTANCE_1;
		else
			scan.scanFlags &= ~WSM_FLAG_MAC_INSTANCE_1;
	}
	/*It's no need set ScanThrohold*/
	scan.autoScanInterval = (0<< 24)|(120 * 1024); /* 30 seconds, -70 rssi */
	scan.numOfSSIDs = 1;
	scan.ssids = &ssids;

#if (CONFIG_P2P == 0)
	if(priv->scan_no_connect){
		scan.ssids->length = 0;
		scan.numOfSSIDs = 0;
	}
	else 
#endif
	{
		if(scan_param->ssid_len != 0){
			atbm_memset(&priv->ssid[0],0,ATBM_IEEE80211_MAX_SSID_LEN);
			atbm_memcpy(&priv->ssid[0],scan_param->ssid,scan_param->ssid_len);
			priv->ssid_length = scan_param->ssid_len;	
		}
		atbm_memcpy(ssids.ssid ,&priv->ssid[0], priv->ssid_length);
		scan.ssids->length = priv->ssid_length;
	}
	scan.ch = (struct wsm_scan_ch *)atbm_kmalloc(sizeof(struct wsm_scan_ch)*scan.numOfChannels,GFP_KERNEL);
	if (!scan.ch) {
		priv->scan.status = -ATBM_ENOMEM;
		wifi_printk(WIFI_ALWAYS,"%s zalloc fail %d\n",__FUNCTION__,sizeof(struct wsm_scan_ch)*scan.numOfChannels);
		return 0;
	}

	/*
		set scan channel 
	*/
	for (i = 0; i < scan.numOfChannels; i++) {		
			scan.ch[i].minChannelTime = 55;//45;
			scan.ch[i].maxChannelTime = 105;//75;
			/*
				记录要扫描的信道号
			*/
			scan.ch[i].number = atbmwifi_band_2ghz.channels[all_channel[i + scan_param->start_chan - 1] - 1].hw_value;
			scan.ch[i].txPowerLevel = atbmwifi_band_2ghz.channels[all_channel[i + scan_param->start_chan - 1] - 1].max_power;
			wifi_printk(WIFI_ALWAYS,"scan channel [%d] \n",scan.ch[i].number);
	}
	wifi_printk(WIFI_ALWAYS,"atbm_scan_work if_id(%d),numOfChannels(%d),numOfSSIDs(%d)\n",priv->if_id,
		scan.numOfChannels,scan.numOfSSIDs);
	ret = wsm_scan(hw_priv, &scan, priv->if_id);
	atbm_kfree(scan.ch);

	if(ret){
		wifi_printk(WIFI_ALWAYS,"%s fail \n",__FUNCTION__);
		//add by wp ,scan fail
		priv->scan.in_progress = 0;
		priv->scan.ApScan_in_process = 0;

	}
	atbmwifi_event_uplayer(priv,ATBM_WIFI_SCANSTART_EVENT,0);
	return ret;

}




int ieee80211_internal_scan_triger(struct atbmwifi_vif *priv,scan_param_t * scan_param)
{	
	int ret;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);	
	struct wsm_template_frame frame;
	frame.frame_type = WSM_FRAME_TYPE_PROBE_REQUEST;	
	frame.disable =0; 
	frame.rate=0;
	
	if (priv->join_status == ATBMWIFI__JOIN_STATUS_AP)
		return -ATBM_EOPNOTSUPP;
	
	frame.skb = atbmwifi_ieee80211_send_probe_req(priv,ATBM_NULL,priv->extra_ie,priv->extra_ie_len,0);

	if (!frame.skb)
		return -ATBM_ENOMEM;

	ret = wsm_set_template_frame(hw_priv, &frame,
			priv->if_id);
	priv->scan.if_id = priv->if_id;
	
	//atbm_queue_work(hw_priv,priv->scan.scan_work);
	atbmwifi_scan_triger(priv,scan_param);
	
	atbm_dev_kfree_skb(frame.skb);

	return ret;
}



/****************************************************
Function Name: atbmwifi_scan_process
Return: scan status,0 success,other fail
******************************************************/
 int atbm_internal_cmd_scan_triger(struct atbmwifi_vif *priv,scan_param_t * scan_param)
{


	if(!atbmwifi_is_sta_mode(priv->iftype)) {	
		wifi_printk(WIFI_ALWAYS,"not support scan in AP mode!\n");
		return -1;		
	}
	if(!priv->enabled){
		wifi_printk(WIFI_ALWAYS,"not support not enabled!\n");
		return -2;
	}

	if(priv->scan.scan_smartconfig){
		wifi_printk(WIFI_ALWAYS,"scan_smartconfig now!please try later!\n");
		return -3;
   }
	
	if((priv->assoc_ok==0) && ( priv->join_status == ATBMWIFI__JOIN_STATUS_STA)){
		 wifi_printk(WIFI_ALWAYS,"join now!please try later!\n");
		 return -6;
	}

	if(!priv->scan.in_progress){
		if(priv->scan_ret.info == ATBM_NULL){
			priv->scan_ret.info = (struct atbmwifi_scan_result_info *)atbm_kmalloc(sizeof(struct atbmwifi_scan_result_info) * MAX_SCAN_INFO_NUM,GFP_KERNEL);
			if(priv->scan_ret.info == ATBM_NULL){
				wifi_printk(WIFI_ALWAYS,"scan malloc fail!");
				return -4;
			}
		}
		priv->scan_ret.len = 0;
		priv->scan.if_id = priv->if_id;
		priv->scan_expire = 2;
		priv->scan_no_connect_back = priv->scan_no_connect;
		priv->scan_no_connect = 1;
		return ieee80211_internal_scan_triger(priv,scan_param);
	}
	else {
		wifi_printk(WIFI_ALWAYS,"scan busy!please try later!");
		return -5;
	}
}


/****************************************************************************
* Function:   	atbm_wifi_scan_network
*
* Purpose:   	This function is used to ask driver to perform channel scan and return scan result.
*
* Parameters: scan_buf		Buffer to store the information of the found APs
*			buf_size		Size of the buffer
*
* Returns:	Returns 0 if succeed, otherwise a negative error code.
******************************************************************************/
int	atbm_wifi_scan_bss(atbm_uint8 if_id,FH_WiFi_AccessPoint_List* scan_buf, scan_param_t * scan_param)
{
	FH_WiFi_AccessPoint *bss_info;
	FH_WiFi_AccessPoint_List *pScanResult;
	struct atbmwifi_scan_result_info *info;
    atbm_int32 waitloop = 10;
	atbm_int32 i=0;
	struct atbmwifi_vif *priv=ATBM_NULL;
	priv=_atbmwifi_hwpriv_to_vifpriv(&g_hw_prv,if_id);
	if(ATBM_NULL==priv){
		return -1;
	}
	wifi_printk(WIFI_ALWAYS,"atbm_wifi_scan_network_vif(%d) \n",priv->iftype);
	
    priv->scan_no_connect_back = priv->scan_no_connect;
	priv->scan_expire = 2;
	if(atbm_internal_cmd_scan_triger(priv,scan_param)){
		return -2;
	}

	wifi_printk(WIFI_ALWAYS,"wait scan done++\n");
	//wait scan done,, wait scan complete
	while(1){
		atbm_mdelay(1000);
		if(priv->scan.in_progress == 0)
			break;
		if(waitloop-- <=0){	
			wifi_printk(WIFI_ALWAYS,"wait scan done++timeout drop\n");
			return -2;
		}
	}
	wifi_printk(WIFI_ALWAYS,"wait scan done--,scan_ret.len(%d)\n",priv->scan_ret.len);
		
	pScanResult = scan_buf;
	if(scan_param->max_ap_number == 0){
		pScanResult->ap = (FH_WiFi_AccessPoint *)atbm_kmalloc(sizeof(FH_WiFi_AccessPoint) * priv->scan_ret.len,GFP_KERNEL);
		pScanResult->count = priv->scan_ret.len;
	}else{
		pScanResult->ap = (FH_WiFi_AccessPoint *)atbm_kmalloc(sizeof(FH_WiFi_AccessPoint) * scan_param->max_ap_number,GFP_KERNEL);
		pScanResult->count = scan_param->max_ap_number;
	}
	memset(pScanResult->ap,0,sizeof(FH_WiFi_AccessPoint) * pScanResult->count);
	bss_info = (FH_WiFi_AccessPoint *)pScanResult->ap;
	//will copy to user API and delete AP list from driver's ap list. here porting for Mstar
	for(i=0;i<priv->scan_ret.len;i++){
		info = priv->scan_ret.info + i;
		//Copy ATBM scanned bss list  to platform dependent BSS list
		atbm_memcpy(bss_info->ssid, info->ssid,  info->ssidlen);
		atbm_memcpy(bss_info->bssid, info->BSSID, ATBM_ETH_ALEN);
		bss_info->channel	    = info->channel;
		bss_info->rssi 			= info->rssi;
		
		if(info->wpa)
			bss_info->security		|= ATBM_WPA_CIPHER_TKIP;
		if(info->rsn)
			bss_info->security		|= ATBM_WPA_CIPHER_CCMP;

		bss_info++;
	}
	
	priv->scan_no_connect = priv->scan_no_connect_back;

	wifi_printk(WIFI_ALWAYS,"wait scan done,pScanResult->count(%d)\n",pScanResult->count);
	return 0;
}

/*
 * 功能: 扫描周边热点,并且返回扫描到的AP列表.
 *       
 *
 * 注意: 在调用函数atbm_scan_ext之后,你必须调用函数atbm_free_scan
 *       释放扫描过程中动态分配的内存.
 *
 * 参数描述:
 * max_ap_num[IN]:        期望返回的扫描到的AP的最大数盿 0表示没有限制.
 * ssid[IN]:              带ssid的扫揿一般情况下填NULL即可.
 * scan_channel_down[IN]: 指定扫描信道的起始信避
 * scan_channel_up[IN]:   指定扫描信道的结束信避
 *      比如: scan_channel_down=4, scan_channel_up=6, 表示在[4,5,6]三个信道扫描
 *      比如: scan_channel_down=0, scan_channel_up=0, 表示全信道扫揿 *
 * 返回倿 NULL表示扫描失败, 否则表示扫描到的AP列表.
 */


FH_WiFi_AccessPoint_List* atbm_scan_ext(FH_UINT32 max_ap_num, FH_CHAR *ssid,
							FH_UINT32 scan_channel_down, FH_UINT32 scan_channel_up)
{
	FH_UINT32 i = 0;
	FH_WiFi_AccessPoint_List *AP_List=NULL;
	scan_param_t scan_param;
	FH_WiFi_AccessPoint *bss_info;
	if((scan_channel_up < scan_channel_down) ||
		(scan_channel_up < 0) || 
		(scan_channel_down<0) ||
		(max_ap_num < 0)
	){
		wifi_printk(WIFI_ALWAYS,"ERROR : start chan[%d],end chan[%d] ,max_ap_num[%d]\n",
									scan_channel_down,scan_channel_up,max_ap_num);
		return NULL;
	}

	
	if((scan_channel_down == 0) && (scan_channel_up == 0)){		
		scan_param.start_chan = 1;
		scan_param.end_chan = 14;
	}else{
		scan_param.start_chan = scan_channel_down;
		scan_param.end_chan = scan_channel_up;
	}
	
	scan_param.ssid = ssid;
	if(ssid)
		scan_param.ssid_len = strlen(ssid);
	else
		scan_param.ssid_len = 0;
	scan_param.max_ap_number = max_ap_num;
	AP_List = (FH_WiFi_AccessPoint_List *)atbm_kmalloc(sizeof(FH_WiFi_AccessPoint_List),GFP_KERNEL);
	AP_List->ap = NULL;
	AP_List->count = 0;
	if(atbm_wifi_scan_bss(0,AP_List,&scan_param) < 0){
		return NULL;
	}
	
	for(i = 0; i < AP_List->count;i++){
		bss_info = AP_List->ap + i;
		wifi_printk(WIFI_ALWAYS,"ssid		:%s\n",bss_info->ssid);
		wifi_printk(WIFI_ALWAYS,"bssid		:"STR2MAC"\n",MAC2STR(bss_info->bssid));
		wifi_printk(WIFI_ALWAYS,"RSSI		:%d\n",bss_info->rssi);
		wifi_printk(WIFI_ALWAYS,"channel		:%d\n",bss_info->channel);
		wifi_printk(WIFI_ALWAYS,"security	:%s\n",wpa_cipher_txt(bss_info->security));
		wifi_printk(WIFI_ALWAYS,"\n");	
	}
	
	wifi_printk(WIFI_ALWAYS,"AP_List addr : 0x%x,0x%x \n",AP_List,AP_List->ap);
	return AP_List;
}

FH_VOID atbm_free_scan(FH_WiFi_AccessPoint_List *aplist)
{
	wifi_printk(WIFI_ALWAYS,"AP_List addr : 0x%x \n",aplist);
	if(aplist){
		if(aplist->ap){
			wifi_printk(WIFI_ALWAYS,"AP_List->ap addr : 0x%x \n",aplist->ap);
			atbm_kfree(aplist->ap);
			aplist->ap = NULL;
		}
		atbm_kfree(aplist);
		aplist = NULL;
	}
}
/*

All-channel scan for debugging purposes

*/

FH_VOID atbm_sta_scan(FH_VOID)
{
	FH_WiFi_AccessPoint_List *aplist = NULL;
	aplist = atbm_scan_ext(0,NULL,0,0);
	if(aplist)
		atbm_free_scan(aplist);
}


/*
 * func: start and work as AP
 * para1: ssid
 * para2: passwd
 * para3: chan_id
 
 进入 ap 模式
 */

FH_SINT32 atbm_ap_on(FH_CHAR *ssid, FH_CHAR *passwd, FH_UINT32 chan_id)
{
	int ret,i,mode;
	if(!wifi_inited){
		atbm_wifi_hw_init();
		wifi_inited = 1;
#ifndef WIFI_SDIO
		rt_thread_delay(150);
#endif
	}
	
	atbm_wifi_off(1);
	rt_thread_delay(150);
	atbm_wifi_on(1);
    ret = atbm_wifi_ap_create(ssid, (passwd && passwd[0]) ? 0x4 : 0, 0, passwd, chan_id, 0);
    if (ret)
    {
        wifi_printk(WIFI_DBG_ERROR,"%s-%d fail, ret %d\n", __func__, __LINE__, ret);
		//return ret;
    }

	return ret;
}
FH_SINT32 atbm_g_sta_num(FH_VOID)
{
	int i =0,ap = 0,sta_num = 0;	
	struct atbmwifi_vif *priv; 
	for(i = 0;i < ATBM_WIFI_MAX_VIFS;i++){
		priv = g_hw_prv.vif_list[i];
		if (atbmwifi_is_ap_mode(priv->iftype)){
			ap = 1;
			break;
		}
	}
	if (!ap){
		wifi_printk(WIFI_DBG_ERROR,"w_get_assoc_num : ap not running \n");
		return -1;
	}
	
	for (i = 0; i < ATBMWIFI__MAX_STA_IN_AP_MODE; ++i) {
		if (priv->link_id_db[i].status == ATBMWIFI__LINK_HARD){
				sta_num++;
		}
	}
	wifi_printk(WIFI_DBG_ERROR,"now connect sta number [%d]  \n",sta_num);
	return sta_num;
}




//#endif

