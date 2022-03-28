#include "anyka_types.h"
#include <stdlib.h>
#include <string.h>
#include "finsh.h"
#include "atbm_wifi_driver_api.h"
#include "atbm_hal.h"
#include "atbm_wsm.h"
#include "sockets.h"

typedef void(*T_pfCMD)(int argc, char **args);


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


typedef struct _wifi_cmd_entry
{
    char cmd_name[32];
    T_pfCMD cmd_entry;
}wifi_cmd_entry_t;

extern struct atbmwifi_common g_hw_prv;
extern struct atbmwifi_vif *  g_vmac;
extern struct atbmwifi_cfg hmac_cfg;
static struct atbmwifi_cfg *hmac_cfg_p = &hmac_cfg;

extern int atbm_etf_start_tx(int channel,int rate_value,int is_40M, int greedfiled);
extern int atbm_etf_stop_tx();
extern int atbm_etf_start_rx(int channel ,int is_40M);
extern int atbm_etf_stop_rx();

#if ATBM_SUPPORT_SMARTCONFIG

#define ATBM_SMARTCONFIG_START 0
#define ATBM_SMARTCONFIG_SUCCESS 1
#define ATBM_WIFI_CONNECT_SUCCESS 2
#define ATBM_WIFI_GOT_IP 3

#define ATBM_SMARTCONFIG_TIMEOUT (200 * 1000)
#define ATBM_WIFI_CONNECT_TIMEOUT (20 * 1000)
#define ATBM_WIFI_GOTIP_TIMEOUT (20 * 1000)


int smartConfigLinkedNotify_sample(){
	int sock_id = -1;
	unsigned char i = 0;
	int ret = 0;
	char smart_msg[32] = {"smart_config"};
	char ch_mac_addr[32] = { 0 };
	unsigned char mac_addr[6] = { 0 };
	int mac_start_pos = 0;
	struct sockaddr_in addrto;
	if((sock_id = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		iot_printf("SOCK_DGRAM socket error!\n");
	}
	const int opt = 1;

	int nb = 0;
	nb = setsockopt(sock_id, SOL_SOCKET, SO_BROADCAST, (char *)&opt, sizeof(opt));
	if(nb == -1){
		iot_printf("set sock error...!\n");
		closesocket(sock_id);
	}
	bzero(&addrto, sizeof(struct sockaddr_in));
	addrto.sin_family = AF_INET;
	addrto.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	addrto.sin_port = htons(3778);
	int nlen = sizeof(addrto);
	atbm_SleepMs(2000);
	iot_printf("send start.....!\n");

	mac_start_pos = strlen(smart_msg);
	smart_msg[mac_start_pos] = ' ';
	mac_start_pos = mac_start_pos + 1;
	atbm_wifi_get_mac_address(mac_addr);
	sprintf(ch_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2], \
			mac_addr[3], mac_addr[4], mac_addr[5]);
	memcpy(&smart_msg[mac_start_pos], ch_mac_addr, strlen(ch_mac_addr));
	while(i < 60){
		ret = sendto(sock_id, smart_msg, strlen(smart_msg), 0, (struct sockaddr *)&addrto, nlen);
		if(ret < 0){
			iot_printf("send error.....!\n");
		}else{
			//
		}
		i++;
		atbm_SleepMs(10);
	}
	return 0;
}

void smart_cfg_thread(void *arg){
	struct atbmwifi_common *hw_priv = arg;
	int i = 0, connected = 0, connecting = 0;
	unsigned int time_start_ms = 0, time_st_time = 0, time_connect_ms = 0, time_getip_ms = 0;
	time_start_ms = get_tick_count();
	char cmd[100] = {0};
	int state = ATBM_SMARTCONFIG_START;
	iot_printf("##########state:%d########\n", state);
	while(1){
		switch(state){
			case ATBM_SMARTCONFIG_START:
				time_st_time = get_tick_count();
				if(hw_priv->st_status == CONFIG_ST_DONE_SUCCESS){
					iot_printf("##########state:%d########\n", state);
					state = ATBM_SMARTCONFIG_SUCCESS;
					sprintf(cmd, "%s %s %s", "wifi join", hmac_cfg_p->ssid, hmac_cfg_p->password);
					msh_exec(cmd, strlen(cmd));
					continue;
				}else{
					if((hw_priv->st_status == CONFIG_ST_DONE_FAIL) || \
						(time_st_time - time_start_ms) > ATBM_SMARTCONFIG_TIMEOUT){
						iot_printf("2hw_priv->st_status:%d time_connect_ms:%d time_st_time:%d", \
								hw_priv->st_status, time_connect_ms, time_st_time);
						goto exit;
					}
				}
				break;
			case ATBM_SMARTCONFIG_SUCCESS:
				time_connect_ms = get_tick_count();
				if(atbm_wifi_isconnected()){
					iot_printf("##########state:%d########\n", state);
					state = ATBM_WIFI_CONNECT_SUCCESS;
					continue;
				}else{
					if((time_connect_ms - time_st_time) > ATBM_WIFI_CONNECT_TIMEOUT){
						iot_printf("hw_priv->st_status:%d time_connect_ms:%d time_st_time:%d", \
							hw_priv->st_status, time_connect_ms, time_st_time);
						goto exit;
					}
				}
				break;
			case ATBM_WIFI_CONNECT_SUCCESS:
				time_getip_ms = get_tick_count();
				if(rt_wlan_is_ready()){
					iot_printf("##########state:%d########\n", state);
					state = ATBM_WIFI_GOT_IP;
					smartConfigLinkedNotify_sample();
					iot_printf("smart config complete...\n");
					return;
				}else{
					if((time_getip_ms - time_connect_ms) > ATBM_WIFI_GOTIP_TIMEOUT){
						iot_printf("3time_connect_ms:%d time_st_time:%d", \
									time_connect_ms, time_st_time);
						goto exit;
					}
				}
				break;
			default:
				break;
		}
		atbm_SleepMs(1000);
	}
exit:
	iot_printf("smartconfig timeout...\n");
	return;
}


void smart_cfg_monitor_thread(){
	atbm_createThread(smart_cfg_thread, (atbm_void*)&g_hw_prv, SMARTCONFIG_MONNITOR_TASK_PRIO);
}

static int atbm_wifi_smart_config_start(){
	struct smartconfig_config st_cfg = {0};

	if((g_vmac->iftype != ATBM_NL80211_IFTYPE_STATION)&&(g_vmac->iftype !=ATBM_NL80211_IFTYPE_P2P_CLIENT)) {	
		rt_kprintf("not support scan in AP mode!\n");
		return;		
	}
	if(g_hw_prv.scan.scan_smartconfig){
		rt_kprintf("scan_smartconfig now!please try later!");
		return;
   }	
	if(!g_vmac->enabled){
		rt_kprintf("not support not enabled!\n");
		return;
	}

	{
		st_cfg.type = CONFIG_TP_ATBM_SMART;
		st_cfg.magic_cnt = 1;
		st_cfg.magic_time = 70;
		st_cfg.payload_time = 12000;
	};
	atbm_ht_smt_setting();
    smartconfig_start(&st_cfg);
}
#endif

static void UartCmd_StartTx(int argc, char **args){
	t_u32 uiChannel, uiRate, is_40M, uiGreenfield;
	t_s32 flag = 0, i = 0, j = 0;
	char uiRatePtr[4] = {0};
	if(argc < 6){
		rt_kprintf("need more parameter,please try again!\n");
		return;
	}
	uiChannel = atoi(args[2]);

	while(args[3][j] != '\0'){
		if(args[3][j] == '.'){
			flag = 1;
		}else{
			uiRatePtr[i++] = args[3][j];
		}
		j++;
	}

	uiRate = flag? atoi(uiRatePtr) : atoi(uiRatePtr) * 10;
	is_40M = atoi(args[4]);
	uiGreenfield = atoi(args[5]);
	rt_kprintf("Ch : %d, Rate : %d, is_40M : %d greenfiled: %d\n", uiChannel, uiRate, is_40M, uiGreenfield);
	if(atbm_etf_start_tx(uiChannel, uiRate, is_40M/*40M*/, uiGreenfield/*greedfiled*/) < 0){
		rt_kprintf("start tx failed!\n");
	}
}

static void UartCmd_StopTx(int argc, char **args){
	atbm_etf_stop_tx();
}

static void UartCmd_StartRx(int argc, char **args){
	t_u32 uiChannel, is_40M;
	if(argc < 4){
		rt_kprintf("need more parameter,please try again!\n");
		return;
	}
	uiChannel = atoi(args[2]);
	is_40M = atoi(args[3]);
	rt_kprintf("Ch : %d is_40M: %d\n", uiChannel, is_40M);
	if(atbm_etf_start_rx(uiChannel, is_40M/*40M*/) < 0){
		rt_kprintf("start etf rx failed!\n");
		return -1;
	}
}

static void UartCmd_StopRx(int argc, char **args){
	atbm_etf_stop_rx();
}

static void UartCmd_StartCCAMeas(int argc, char **args){
	atbmwifi_enable_lmaclog(1);
	wsm_write_mib(&g_hw_prv, WSM_MIB_ID_FW_CMD,"ccastart ", 9, g_vmac->if_id);
}

static void UartCmd_StopCCAMeas(int argc, char **args){
	atbmwifi_enable_lmaclog(0);
	wsm_write_mib(&g_hw_prv, WSM_MIB_ID_FW_CMD,"ccastop ", 8, g_vmac->if_id);
}

static void UartCmd_Set_Freq(int argc, char **args){
	char cmd[20] = {0};
	if(argc < 4){
		rt_kprintf("need more parameter,please try again!\n");
		return;
	}
	sprintf(cmd, "set_freq %s %s ", args[2], args[3]);
	rt_kprintf("cmd: %s\n", cmd);
	wsm_write_mib(&g_hw_prv, WSM_MIB_ID_FW_CMD, cmd, strlen(cmd), g_vmac->if_id);
}

#if ATBM_SUPPORT_SMARTCONFIG
static void UartCmd_StartSmartconfig(int argc, char **args){
	atbm_wifi_smart_config_start();
	smart_cfg_monitor_thread();
}

static void UartCmd_StopSmartconfig(int argc, char **args){
	if((g_vmac->iftype != ATBM_NL80211_IFTYPE_STATION)&&(g_vmac->iftype !=ATBM_NL80211_IFTYPE_P2P_CLIENT)) {	
		wifi_printk(WIFI_ALWAYS,"not support scan in AP mode!\n");
		return;		
	}	
	if(!g_vmac->enabled){
		wifi_printk(WIFI_ALWAYS,"not support not enabled!\n");
		return;
	}
	if(g_hw_prv.scan.scan_smartconfig){
		smartconfig_stop();
   }
}
#endif

#ifdef CONFIG_WPS
static void UartCmd_WPS_Control(int argc, char **args){
	if(argc < 3){
		wifi_printk(WIFI_ALWAYS,"need more param!\n");
	}
	if(!strcmp("PBC", args[2]) || !strcmp("pbc", args[2])){
		iot_printf("WPS:start PBC\n");
		atbmwps_start_pbc(g_vmac, NULL);
	}else if(!strcmp("PIN", args[2]) || !strcmp("pin", args[2]) && argc >= 4){
		iot_printf("WPS:start PIN %s\n", args[3]);
		atbmwps_start_pin(g_vmac, args[3], NULL, 0);
	}else if(!strcmp("STOP", args[2]) || !strcmp("stop", args[2])){
		iot_printf("WPS: stop\n");
		atbmwps_cancel(g_vmac);
	}
}
#endif

static void UartCmd_EnterWiFiMFGMode(int argc, char **args)
{
//	nhw_set_wifi_mfg(1);
	return 0;
}

static void UartCmd_MFGTxBG(int argc, char **args)
{
    t_u32 uiChannel, uiRate, uiPowerValue;
    t_s32  iError;

	uiChannel = atoi(args[2]);
	uiRate = atoi(args[3]);
	uiPowerValue = atoi(args[4]);

    rt_kprintf("Ch : %d, Rate : %d, PowerValue : %d \n", uiChannel, uiRate, uiPowerValue);

    iError = atbm_wifi_mfg_set_pktTxBG(uiChannel, uiRate, uiPowerValue);

    rt_kprintf("Tx BG Status : %d \n", iError);
}

static void UartCmd_MFGTxN(int argc, char **args)
{
    t_u32 uiChannel, uiRate, uiPowerValue;
    t_s32  iError;

	uiChannel = atoi(args[2]);
	uiRate = atoi(args[3]);
	uiPowerValue = atoi(args[4]);

    rt_kprintf("Ch : %d, Rate : %d, PowerValue : %d \n", uiChannel, uiRate, uiPowerValue);

    iError = atbm_wifi_mfg_set_PktTxN(uiChannel,uiRate, uiPowerValue);

    rt_kprintf("Tx N Status : %d \n", iError);
}

static void UartCmd_MFGRx(int argc, char **args)
{
    t_u32 uiChannel;
    t_s32  iError;

    uiChannel = atoi(args[2]);

    rt_kprintf("Ch : %d \n", uiChannel);

    iError = atbm_wifi_mfg_set_PktRxMode(uiChannel);

    rt_kprintf("Rx Status : %d \n", iError);
}

static void UartCmd_MFGRxGetPkt(int argc, char **args)
{
    t_u32 uiCount;
    t_s32  iError;

    iError = atbm_wifi_mfg_get_RxPkt(&uiCount);

    rt_kprintf("RxGetPkt Status : %d, Count : %d \n", iError, uiCount);
}

static void UartCmd_MFGCarrierTone(int argc, char **args)
{
    t_u32 uiChannel;
    t_s32  iError;

    uiChannel = atoi(args[2]);

    rt_kprintf("Ch : %d \n", uiChannel);

    iError = atbm_wifi_mfg_CarrierTone(uiChannel);

    rt_kprintf("CarrierTone Status : %d \n", iError);
}

static void UartCmd_MFGStop(int argc, char **args)
{
    t_s32  iError;

    iError = atbm_wifi_mfg_stop();

    rt_kprintf("Stop Status : %d\n", iError);
}

static void UartCmd_MFGConTxBG(int argc, char **args)
{
	t_u32 uiChannel, uiRate, uiPowerValue;
	t_s32 iError;

	uiChannel = atoi(args[2]);
	uiRate = atoi(args[3]);
	uiPowerValue = atoi(args[4]);

	rt_kprintf("Ch : %d, Rate : %d, PowerValue : %d \n", uiChannel, uiRate, uiPowerValue);
	iError = atbm_wifi_mfg_set_pktTxBG(uiChannel,uiRate, uiPowerValue);
	rt_kprintf("Continuous Tx BG Status : %d \n", iError);
}

static void UartCmd_MFGConTxN(int argc, char **args)
{
	t_u32 uiChannel, uiRate, uiPowerValue;
	t_s32 iError;

	uiChannel = atoi(args[2]);
	uiRate = atoi(args[3]);
	uiPowerValue = atoi(args[4]);

	rt_kprintf("Ch : %d, Rate : %d, PowerValue : %d \n", uiChannel, uiRate, uiPowerValue);
	iError = atbm_wifi_mfg_set_PktTxN(uiChannel,uiRate, uiPowerValue);
	rt_kprintf("Continuous Tx N Status : %d \n", iError);
}

static void UartCmd_MFGPT_Test(int argc, char **args)
{
	t_s32 iError;
	t_s32 isWriteEfuse = 0;

	if(argc < 3)
	{
		rt_kprintf("ERROR MSG:Need one parameter\n");
		return;
	}
	isWriteEfuse = atoi(args[2]);
	if((isWriteEfuse != 0) && (isWriteEfuse != 1))
	{
		rt_kprintf("ERROR MSG:Invalid parameter\n");
		return;
	}
	iError = atbm_wifi_mfg_PT_Test(/*targetFreq, rssiFilter, evmFilter, cableLoss, */isWriteEfuse);
    rt_kprintf("Product Test: %d \n", iError);
}

static void atbm_wifi_efuse_set(int argc, char **args)
{
	int i;
	t_s32 iError;
	struct efuse_headr efuse_data_local;
	struct atbmwifi_vif *vif=g_vmac;
	struct atbmwifi_common *hw_priv = vif->hw_priv;
	memset(&efuse_data_local, 0, sizeof(struct efuse_headr));
	iError = wsm_get_efuse_data(hw_priv, &efuse_data_local, sizeof(struct efuse_headr));
	if(iError){
		rt_kprintf("set efuse data error!!\n");
		return;
	}
	if(argc < 4){
		rt_kprintf("need more params!!\n");
		return;
	}
	if(memcmp(args[2], "setEfuse_dcxo", 13) == 0)
	{
		efuse_data_local.dcxo_trim = atoi(args[3]);
		rt_kprintf("set efuse data is dcxo[%d]\n",efuse_data_local.dcxo_trim);
	}
	else if(memcmp(args[2], "setEfuse_deltagain", 18) == 0)
	{
		if(argc < 6){
			rt_kprintf("setEfuse_deltagain need more params!!\n");
			return;
		}
		efuse_data_local.delta_gain1 = atoi(args[3]);
		efuse_data_local.delta_gain2 = atoi(args[4]);
		efuse_data_local.delta_gain3 = atoi(args[5]);
		
		rt_kprintf("set efuse data is delta_gain[%d,%d,%d]\n",
			efuse_data_local.delta_gain1,efuse_data_local.delta_gain2,efuse_data_local.delta_gain3);
	}
	else if(memcmp(args[2], "setEfuse_mac", 12) == 0)
	{
		if(argc < 9){
			rt_kprintf("setEfuse_mac need more params!!\n");
			return;
		}
		for(i = 0; i < 6; i++){
			efuse_data_local.mac[i] = (t_u8)hex2byte(args[i+3]);
		}
		rt_kprintf("set efuse data is mac[%02x:%02x:%02x:%02x:%02x:%02x]\n",
					efuse_data_local.mac[0],efuse_data_local.mac[1],efuse_data_local.mac[2],
					efuse_data_local.mac[3],efuse_data_local.mac[4],efuse_data_local.mac[5]);
	}
	iError = atbm_save_efuse(hw_priv, &efuse_data_local);
	if(iError){
		rt_kprintf("set efuse data failed:%d!!!\n", iError);
	}
}


static void atbm_wifi_efuse_get(int argc, char **args)
{
	t_s32 iError;
	struct efuse_headr efuse_data_local;
	struct atbmwifi_vif *vif=g_vmac;
	struct atbmwifi_common *hw_priv = vif->hw_priv;
	memset(&efuse_data_local, 0, sizeof(struct efuse_headr));
	iError = wsm_get_efuse_data(hw_priv, &efuse_data_local, sizeof(struct efuse_headr));
	if(iError){
		rt_kprintf("get efuse data error!!\n");
	}else{
		rt_kprintf("efuse data:\n");
		dump_mem(&efuse_data_local, sizeof(struct efuse_headr));
	}
}

static int cmd_entry_check(wifi_cmd_entry_t * cmd_table, int argc, char **args)
{
    int i,ret;

    //find the right cmd name
    for(i = 0; cmd_table[i].cmd_entry != NULL; i++)
    {
        if (strcmp(cmd_table[i].cmd_name, args[1]) == 0)
        {
            //find and execute entry function
            cmd_table[i].cmd_entry(argc, args);
            return 0;
        }
    }

    //set_error_no(ERROR_TYPE_INVALID_ARG);
    return -1;
}

static void wifi_test_help(){
	rt_kprintf("wifi_test_help\n");
}

/* wifi test command entry table, we can add new cmd hear */
static wifi_cmd_entry_t s_test_cmd_table[] = 
{
/* WIFI test cmd start*/
	{"start_tx",       UartCmd_StartTx},
	{"stop_tx",       UartCmd_StopTx},
	{"start_rx",       UartCmd_StartRx},
	{"stop_rx",       UartCmd_StopRx},
	{"mfgcarriertone",       UartCmd_MFGCarrierTone},
	{"start_ccameas",       UartCmd_StartCCAMeas},
	{"stop_ccameas",       UartCmd_StopCCAMeas},
	{"set_freq",		UartCmd_Set_Freq},
#if ATBM_SUPPORT_SMARTCONFIG
	{"start_smartconfig",     UartCmd_StartSmartconfig},
	{"stop_smartconfig",     UartCmd_StopSmartconfig},
#endif
#ifdef CONFIG_WPS
	{"wps_mode", UartCmd_WPS_Control},
#endif
#if 1
    {"mfgen",       UartCmd_EnterWiFiMFGMode},
    {"mfgtxbg",       UartCmd_MFGTxBG},
    {"mfgtxn",       UartCmd_MFGTxN},
    {"mfgrx",       UartCmd_MFGRx},
    {"mfgrxgetpkt",       UartCmd_MFGRxGetPkt},
    {"mfgstop",       UartCmd_MFGStop},
    {"mfgcontxbg",       UartCmd_MFGConTxBG},
    {"mfgcontxn",       UartCmd_MFGConTxN},
    {"WifiTest_iw",      UartCmd_MFGPT_Test},
    {"efuse_set",       atbm_wifi_efuse_set},
    {"efuse_get",       atbm_wifi_efuse_get},
#endif
    {0,0,0,0}
};

static void atbm_wifi_test(int argc, char **args)
{
	int i = 0;
	if(!g_vmac){
		rt_kprintf("wifi not inited!\n");
	}
    if(cmd_entry_check(s_test_cmd_table, argc, args) != 0)
    {       
		wifi_test_help();
    }
	
}

MSH_CMD_EXPORT(atbm_wifi_test, altobeam wifi txrx test);


