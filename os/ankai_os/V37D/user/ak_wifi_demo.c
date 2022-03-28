/*
*wifi_demo.c    wifi operation demo
*/
#include "anyka_types.h"
#include <stdlib.h>
#include <string.h>
#include "finsh.h"  
#include "rtthread.h"
#include "rtdef.h"
#include "dev_info.h"
#include "platform_devices.h"
#include <stdint.h>
#include "wifi.h"
//#include "wifi_netif.h"
//#include "moal_wifi.h"
#include "wifi_backup_common.h"
//#include "command.h"
//#include "ak_common.h"
//#include "ak_thread.h"
//#include "ak_partition.h"
#include "akos_error.h"
#include "lwip/ip_addr.h"
#include "anyka_types.h"
//#include "drv_gpio.h"
//#include "ak_ini.h"
#include "mlanutl.h"
#include "atbm_wifi_driver_api.h"
#include "atbm_os_mutex.h"
#include "wlan_dev.h"

/********************************************************
*			 Macro
********************************************************/

#define SDIO_BACK_PARTI          "SDIOPA"
//#define SERVER_IP_PARTI			 "SERVER"


/******************************************************
*                    Constant         
******************************************************/
#define        AK_FALSE            0
#define        AK_TRUE             1
/** Max Ie length */
#define MAX_IE_SIZE             256
#define MKEEP_ALIVE_IP_PKT_MAX  256
typedef void(*T_pfCMD)(int argc, char **args);


/******************************************************
*                    Type Definitions         
******************************************************/

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

/** Type definition of mlan_ds_ps_cfg for MLAN_OID_PM_CFG_PS_CFG */
typedef struct _mlan_ds_ps_cfg {
    /** PS null interval in seconds */
	t_u32 ps_null_interval;
    /** Multiple DTIM interval */
	t_u32 multiple_dtim_interval;
    /** Listen interval */
	t_u32 listen_interval;
    /** Adhoc awake period */
	t_u32 adhoc_awake_period;
    /** Beacon miss timeout in milliseconds */
	t_u32 bcn_miss_timeout;
    /** Delay to PS in milliseconds */
	t_s32 delay_to_ps;
    /** PS mode */
	t_u32 ps_mode;
} mlan_ds_ps_cfg, *pmlan_ds_ps_cfg;

typedef struct _mlan_ds_auto_assoc
{
	/*1/2/3 driver auto assoc/driver auto re-connect/FW auto re-connect		                   
	auto assoc takes effect in new connection (e.g. iwconfig essid),		                   
	driver will auto retry if association failed;		                   
	auto re-connect takes effect when link lost, driver/FW will try		                   
	to connect to the same AP
	*/
	t_u8 auto_assoc_type;
	/*1/0 on/off*/
	t_u8 auto_assoc_enable;
	/*0x1-0xff The value 0xff means retry forever (default 0xff)*/
	t_u8 auto_assoc_retry_count;
	/*0x0-0xff Time gap in seconds (default 10)*/
	t_u8 auto_assoc_retry_interval;
	/*: Bit 0:		                   
	Set to 1: Firmware should report link-loss to host if AP rejects	
	authentication/association while reconnecting		                  
	Set to 0: Default behavior: Firmware does not report link-loss		                             
	to host on AP rejection and continues internally		                   
	Bit 1-15: Reserved		                  
	The parameter flag is only used for FW auto re-connect
	*/
	t_u8 auto_assoc_flags;
}mlan_ds_auto_assoc, *pmlan_ds_auto_assoc;

typedef struct _mlan_ds_smc_chan_list {
	/** channel number*/
	t_u8 chan_number;
	/** channel width 0: 20M, 1: 10M, 2: 40M, 3: 80Mhz*/
	t_u8 chanwidth;
	/** min scan time */
	t_u16 minScanTime;
	/**max scan time */
	t_u16 maxScanTime;
} mlan_ds_smc_chan_list;
typedef struct _mlan_ds_smc_frame_filter {
	/** destination type */
	t_u8 destType;
	/** Frame type */
	t_u8 frameType;
} mlan_ds_smc_frame_filter;
typedef struct _mlan_ds_smc_mac_addr {
	/** start address */
	t_u8 startaddr[MLAN_MAC_ADDR_LENGTH];
	/**end address */
	t_u8 endaddr[MLAN_MAC_ADDR_LENGTH];
	/** filter type */
	t_u16 filterType;
} mlan_ds_smc_mac_addr;
typedef struct _mlan_ds_smc {
	/** smc action, 0: get, 1: set, 2: start, 3: stop */
	t_u16 action;
	/** channel list number*/
	t_u8 chan_num;
	/**channel list*/
	mlan_ds_smc_chan_list chanlist[MAX_CHANNEL_LIST];
	/** frame filter set*/
	t_u8 filterCount;
	/**frame filter */
	mlan_ds_smc_frame_filter framefilter[MAX_FRAME_FILTER];
	/** address range set */
	t_u8 addrCount;
	/** multi address */
	mlan_ds_smc_mac_addr addr[MAX_ADDR_FILTER];
	/** ssid length */
	t_u8 ssid_len;
	/** ssid */
	t_u8 ssid[32];
	/** beacon period */
	t_u16 beaconPeriod;
	/** beacon of channel */
	t_u8 beaconOfChan;
	/** probe of channel */
	t_u8 probeOfChan;
	/** customer ie */
	t_u8 customer_ie[MAX_IE_SIZE];
	/** IE len */
	t_u8 ie_len;
} mlan_ds_smc;


typedef struct _mlan_ds_misc_keep_alive {
	t_u8 mkeep_alive_id;
	t_u8 enable;
	t_u8 start;
	t_u16 send_interval;
	t_u16 retry_interval;
	t_u16 retry_count;
	t_u8 dst_mac[MLAN_MAC_ADDR_LENGTH];
	t_u8 src_mac[MLAN_MAC_ADDR_LENGTH];
	t_u16 pkt_len;
	t_u8 packet[MKEEP_ALIVE_IP_PKT_MAX];
} mlan_ds_misc_keep_alive;


typedef struct _wifi_cmd_entry
{
    char cmd_name[32];
    T_pfCMD cmd_entry;
}wifi_cmd_entry_t;
 
/******************************************************
*                    Global Variables         
******************************************************/
void* cfg_handle;

/******************************************************
*			 Local Variables
******************************************************/
static char *help_ap[]={
	"wifi ap tools\n",
	"usage:ap start [ch][mode: 0 bg, 1 bgn] [ssid] <security_type: 0 open, 1 WEP, 2 WPA, 3 WPA2> <password> \n"
	"	   ap stop\n"
};
static char *help_sta[]={
	"wifi sta tools\n",
	"usage: cmd_wifi_sta init\n"
	"	cmd_wifi_sta conn [ssid] <password>\n"
	"	cmd_wifi_sta sleep\n",
	"	cmd_wifi_sta fastlink\n"
	"	cmd_wifi_sta disconn\n"
	"	cmd_wifi_sta status, get connection status\n",
	"	cmd_wifi_sta config [ssid] [password] [IP] [port]\n"
	"	cmd_wifi_sta clearcfg, clear server config\n",
	"	cmd_wifi_sta hscfg [condigion] [gpio] [gap] [ind_gpio] [level] \n"
	"	cmd_wifi_sta mefcfg, set mef with default\n",
	"	cmd_wifi_sta keepalive start/stop\n"
	"	cmd_wifi_sta dhcp, get ip by dhcp\n",
	"	cmd_wifi_sta clearip, clear ip in flash\n"
	"	cmd_wifi_sta wakeup\n"
	"	cmd_wifi_sta scan\n"
};
static char *help_sdio[]={
	"sdio back test\n",
	"usage: sdio resetflag 0/1\n"
	"		sdio back  \n"
	"		sdio restore \n"
			
};

static int sta_reconn_flag = AK_TRUE;
static rt_thread_t  g_sta_conn_thread_id = AK_INVALID_TASK;
static struct _conn_param conn_param;

  
/******************************************************
*                    Function prototype                           
******************************************************/
static int sdio_flag_set(uint32_t reset_flag);
static int sdio_flag_get(uint32_t *reset_flag);
extern char wifi_get_init_status(void);
extern char wifi_init_check();

/******************************************************
*		        Local Function Declarations
******************************************************/

static void wifi_sta_help(void)
{
	int i = 0;
	for(i = 1; i <= 6; i++)
	{
		rt_kprintf(" %s", help_sta[i]);
	}
	
}

/*keep  connection thread*/
static void sta_conn_thread(void *args)
{
	struct _conn_param *conn_param = (struct _conn_param*)args;
	
	while(sta_reconn_flag == AK_TRUE)
	{
		if (!wifi_isconnected())
		{	
			rt_kprintf("Connect to SSID: < %s >  with password:%s\n", conn_param->essid,  conn_param->password);
			wifi_connect(conn_param->essid, conn_param->password);
			if (wifi_isconnected())
			{
				rt_kprintf("wifi Association ok\n");
				//wifi_power_cfg(0); //wmj for test
				wifistation_netif_init();
                wifistation_netif_set_dhcp(DHCP_MODE_DYNAMIC_EVERY,NULL);
                wifistation_netif_get_ip();
				//break;				
			}
		}
		drv_os_msleep(1000);
	}
	rt_kprintf("sta conn thread exit.\n");
	//ak_thread_exit();
}


/******************************************************
*		        Local Function Declarations
******************************************************/
// add by charlie for quick connect

/*keep quick connection thread*/
extern int wifi_get_fast_connect_info(struct bss_descriptor *bss_saved);
static void sta_quick_conn_thread(void *args)
{
	int connecting = 0;
	struct _conn_param *conn_param = (struct _conn_param*)args;

	struct wifi_info wifi_info_saved;	
    memset(&wifi_info_saved, 0, sizeof(struct wifi_info));

    wifi_backup_usr_data(0, &wifi_info_saved,  sizeof(wifi_info_saved));
	rt_kprintf("[%s]-line:%d\n",__FUNCTION__, __LINE__);	
	while(sta_reconn_flag == AK_TRUE)
	{
		if (!wifi_isconnected() && !connecting)
		{
			rt_kprintf("Connect to SSID: < %s > ", conn_param->essid);
			rt_kprintf("with password:%s\n",conn_param->password);
			wifi_quick_connect(conn_param->essid, conn_param->password, &wifi_info_saved.bss_descriptor);
			connecting = 1;
		}else if(wifi_isconnected()){
			rt_kprintf("atbm6031 sdio wifi Association ok\n");
			wifi_get_fast_connect_info(&wifi_info_saved.bss_descriptor);
			wifi_backup_usr_data(1, &wifi_info_saved,  sizeof(wifi_info_saved));
			wifistation_netif_init();
			rt_kprintf("[%s]-line:%d\n",__FUNCTION__, __LINE__);
	        wifistation_netif_set_dhcp(DHCP_MODE_STATIC, "192.168.1.187");
			//wifistation_netif_set_dhcp(DHCP_MODE_DYNAMIC_FIRST, NULL);
			//wifistation_netif_set_dhcp(DHCP_MODE_DYNAMIC_EVERY, NULL);
	        wifistation_netif_get_ip();
			break;
		}
		drv_os_msleep(20);
	}
	rt_kprintf("sta conn thread exit.\n");
	//ak_thread_exit();
}

/**
 * get configuration for camview (including ssid password ip port and port).
 *
 * @param ip_info the network interface if infomation including ip gw netmask
 */

int wifi_set_config(struct server_info *t_server_info)
{
	void *handle = NULL;
	char str_buf[30]={0};
	int ret = -1;

	return ret;	
}


/**
 * get configuration for camview (including ssid password ip port and port).
 *
 * @param ip_info the network interface if infomation including ip gw netmask
 */

int wifi_get_config(struct server_info *t_server_info)
{
	int ret = -1;
	char str_buf[30]={0};

	return ret;	
}


static unsigned char magic_mef_conf[] = 
	"mefcfg={\n"\
		"Criteria=3\n"\
		"NumEntries=1\n"\
		"mef_entry_0={\n"\
			"mode=1\n"\
			"action=3\n"\
			"filter_num=3\n"\
			"RPN=Filter_0 && Filter_1 || Filter_2\n"\
			"Filter_0={\n"\
				"type=0x42\n"\
				"pattern=80\n"\
				"offset=44\n"\
				"numbyte=2\n"\
			"}\n"\
			"Filter_1={\n"\
				"type=0x41\n"\
				"repeat=1\n"\
				"byte=c0:a8:01:68\n"\
				"offset=34\n"\
			"}\n"\
			"Filter_2={\n"\
				"type=0x41\n"\
				"repeat=16\n"\
				"byte=00:50:43:21:be:14\n"\
				"offset=56\n"\
			"}\n"\
		"}\n"\
	"}\n";

/*****************************************
 * @brief wifi connect function test
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
#ifdef WFII_MLANUTL
extern int process_aggrpriotbl(int argc, char *argv[]);
extern int process_addbareject(int argc, char *argv[]);
extern int process_memrdwr(int argc, char *argv[]);


//wmm para,use for improve the competitive power of occupy wifi channel 
static wifi_wmm_para_t wmm_para=
{
	//BE para
	.aci0 = 0,
	.aifsn0 = 2,
	.ecwmax0 = 3,
	.ecwmin0 = 2,
	.txop0 = 150,

	//BK para
	.aci1 =1,
	.aifsn1 = 2,
	.ecwmax1 = 3,
	.ecwmin1 = 2,
	.txop1 = 150,

	//VI para
	.aci2 =2,
	.aifsn2 = 2,
	.ecwmax2 = 2,
	.ecwmin2 = 1,
	.txop2 = 360,

	//VO para
	.aci3 =3,
	.aifsn3 = 2,
	.ecwmax3 = 3,
	.ecwmin3 = 2,
	.txop3 = 150
};							//wmm para,use for improve the competitive power of occupy wifi channel 
#endif
static void wifi_sta_fastlink(int argc, char **args)
{
	int ret = -1, connecting = 0, t1, t2;
	if (argc != 3 && argc != 4)
	 {
		 wifi_sta_help();
		 return;
	 }
	 if(strlen(args[2]) > MAX_SSID_LEN)
	 {
		 rt_kprintf("ssid should less than 32 characters\n");
		 return;
	 }
	 if(argc == 4 && strlen(args[3]) > MAX_KEY_LEN)
	 {
		 rt_kprintf("password should less than 64 characters\n");
		 return;
	 }
	 
	 strcpy(conn_param.essid, args[2]);
	 
	 if(argc == 4)
	 {
		 strcpy(conn_param.password, args[3]);
	 }
	 else
	 {
		 memset(conn_param.password, 0, MAX_KEY_LEN);
	 }

	struct wifi_info wifi_info_saved;	
    memset(&wifi_info_saved, 0, sizeof(struct wifi_info));

    wifi_backup_usr_data(0, &wifi_info_saved,  sizeof(wifi_info_saved));
	t1 = get_tick_count();
	//rt_kprintf("start init wifi\n");//,%ld\n", get_tick_count());
    if(wifi_init_check())
    {
        rt_kprintf("wifi has inited!\r\n");
    }
	else {
		rt_kprintf("sky37d rtt start init wifi\n");//,%ld\n", get_tick_count());
		wifi_init(0);
	}
	//rt_kprintf("start init wifi ok\n");//,%ld\n", get_tick_count());
	wifi_set_mode(WIFI_MODE_STA);
	
	while(sta_reconn_flag == AK_TRUE)
	{
		if (!wifi_isconnected() && !connecting)
		{
			rt_kprintf("fastlink Connect to SSID: < %s >  with password:%s\n", conn_param.essid,  conn_param.password);
			wifi_quick_connect(conn_param.essid, conn_param.password, &wifi_info_saved.bss_descriptor);
			connecting = 1;
		}else if(wifi_isconnected()){
			t2 = get_tick_count();
			rt_kprintf("fastlink wifi Association ok,t:%ld\n",t2-t1);
			wifi_get_fast_connect_info(&wifi_info_saved.bss_descriptor);
			wifi_backup_usr_data(1, &wifi_info_saved,  sizeof(wifi_info_saved));
			rt_kprintf("wifi backup usr data ok!\r\n");
			wifistation_netif_init();
			wifistation_netif_set_dhcp(DHCP_MODE_STATIC, "192.168.1.187");
			//wifistation_netif_set_dhcp(DHCP_MODE_DYNAMIC_FIRST, NULL);
			//wifistation_netif_set_dhcp(DHCP_MODE_DYNAMIC_EVERY, NULL);
	        wifistation_netif_get_ip();
			break;
		}
		drv_os_msleep(10);
	}
	
    //wifi_connect(conn_param.essid,conn_param.password);
}

#if 0
int  wifi_sta_fastlink1(char *ssid, char *bssid, WLAN_AUTH_MODE authMode, WLAN_ENCRYPTION encryption, const char *key)
{
	int ret = -1, connecting = 0, t1, t2;


	struct wifi_info wifi_info_saved;	
    memset(&wifi_info_saved, 0, sizeof(struct wifi_info));

    wifi_backup_usr_data(0, &wifi_info_saved,  sizeof(wifi_info_saved));
	t1 = get_tick_count();
	rt_kprintf("start init wifi%ld\n",  get_tick_count());//,%ld\n", get_tick_count());
	//wifi_set_mode(WIFI_MODE_STA);
	//rt_kprintf("start init wifi ok\n");//,%ld\n", get_tick_count());
	
	while(sta_reconn_flag == AK_TRUE)
	{
		if (!wifi_isconnected() && !connecting)
		{
			FAST_LINK_INFO *finfo = (FAST_LINK_INFO *)&wifi_info_saved.bss_descriptor;
			rt_kprintf("fastlink Connect ......\n");
			if(strcmp(ssid, (char *)(&finfo->config[finfo->ssid_offset])) || strcmp(key, (char *)(&finfo->config[finfo->psk_offset]))){
				memset(finfo, 0, sizeof(FAST_LINK_INFO));
				strcpy(finfo->config, ssid);
				strcpy(finfo->bss, key);
				memset((u8_t *)finfo - sizeof(ip_info_t), 0, sizeof(ip_info_t));
			}
			atbm_wifi_fast_link_noscan(finfo);
			connecting = 1;
		}
		if(wifi_isconnected()){
			t2 = get_tick_count();
			rt_kprintf("fastlink wifi Association ok,t:%ld\n",t2-t1);
			wifi_get_fast_connect_info(&wifi_info_saved.bss_descriptor);
			wifi_backup_usr_data(1, &wifi_info_saved,  sizeof(wifi_info_saved));
			rt_kprintf("wifi backup usr data ok!\r\n");
			break;
		}
		drv_os_msleep(10);
	}
	rt_kprintf("sta fastlink conn thread exit.%ld\n",  get_tick_count());
	//rt_kprintf("sta fastlink conn thread exit.\n");
	return 0;
    //wifi_connect(conn_param.essid,conn_param.password);
}
#else
void  wifi_sta_fastlink1(void *args)
{
	int ret = -1, connecting = 0, t1, t2;
	struct rt_sta_info *sta_info = (struct rt_sta_info *)args;
	char *ssid = (char *)sta_info->ssid.val;
	char *key = (char *)sta_info->key.val;

	struct wifi_info wifi_info_saved;	
    memset(&wifi_info_saved, 0, sizeof(struct wifi_info));

    wifi_backup_usr_data(0, &wifi_info_saved,  sizeof(wifi_info_saved));
	t1 = get_tick_count();
	rt_kprintf("start init wifi%ld\n",  get_tick_count());//,%ld\n", get_tick_count());
	//wifi_set_mode(WIFI_MODE_STA);
	//rt_kprintf("start init wifi ok\n");//,%ld\n", get_tick_count());
	
	while(sta_reconn_flag == AK_TRUE)
	{
		if (!wifi_isconnected() && !connecting)
		{
			FAST_LINK_INFO *finfo = (FAST_LINK_INFO *)&wifi_info_saved.bss_descriptor;
			rt_kprintf("fastlink Connect ......\n");
			if(strcmp(ssid, (char *)(&finfo->config[finfo->ssid_offset])) || strcmp(key, (char *)(&finfo->config[finfo->psk_offset]))){
				memset(finfo, 0, sizeof(FAST_LINK_INFO));
				strcpy(finfo->config, ssid);
				strcpy(finfo->bss, key);
				memset((u8_t *)finfo - sizeof(ip_info_t), 0, sizeof(ip_info_t));
			}
			atbm_wifi_fast_link_noscan(finfo);
			connecting = 1;
		}
		if(wifi_isconnected()){
			t2 = get_tick_count();
			rt_kprintf("fastlink wifi Association ok,t:%ld\n",t2-t1);
			wifi_get_fast_connect_info(&wifi_info_saved.bss_descriptor);
			wifi_backup_usr_data(1, &wifi_info_saved,  sizeof(wifi_info_saved));
			rt_kprintf("wifi backup usr data ok!\r\n");
			break;
		}
		drv_os_msleep(10);
	}
	rt_kprintf("sta fastlink conn thread exit.%ld\n",  get_tick_count());
	//rt_kprintf("sta fastlink conn thread exit.\n");
}

#endif
static void wifi_sta_conn(int argc, char **args)
{
    int ret = -1;
    if (argc != 3 && argc != 4)
    {
		wifi_sta_help();
        return;
    }
    if(strlen(args[2]) > MAX_SSID_LEN)
    {
        rt_kprintf("ssid should less than 32 characters\n");
        return;
    }
    if(argc == 4 && strlen(args[3]) > MAX_KEY_LEN)
    {
        rt_kprintf("password should less than 64 characters\n");
        return;
    }
    
    strcpy(conn_param.essid, args[2]);
    
    if(argc == 4)
    {
        strcpy(conn_param.password, args[3]);
    }
    else
    {
        memset(conn_param.password, 0, MAX_KEY_LEN);
    }

    if(wifi_init_check())
    {
        printk("wifi has inited!\r\n");
    }
	else {
		rt_kprintf("sky37d rtt start init wifi\n");//,%ld\n", get_tick_count());
		wifi_init(0);
	}
#if 0
    wifi_connect(conn_param.essid,conn_param.password);
#else
    /*create a task to connetc AP,  so the STA can reconnect AP case the AP unavailable temporily for some reason*/
    if(g_sta_conn_thread_id == AK_INVALID_TASK)
    {
		ret = wifi_set_mode(WIFI_MODE_STA);
		rt_kprintf("[%s]line:%d,WIFI_MODE_STA done,ret=%d\n",__FUNCTION__, __LINE__,ret);
        if(ret == -1)
            return;
            
        sta_reconn_flag = AK_TRUE;
        //ak_thread_create(&g_sta_conn_thread_id , (void*)sta_quick_conn_thread , &conn_param, 4096, 10);
		g_sta_conn_thread_id = rt_thread_create("atbm6031", sta_quick_conn_thread, (void *)&conn_param, 4096, 10, 5);
		ret = rt_thread_startup(g_sta_conn_thread_id);
    }
    else
    {
        rt_kprintf("sta is connecting, please disconnect it first\n");
    }
#endif
    
}

/*****************************************
 * @brief wifi disconnect function test
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_sta_disconn(int argc, char **args)
{
	if (argc != 2)
	{
		wifi_sta_help();
		return;
	}

	rt_kprintf("disconnect wifi \n");
	
	sta_reconn_flag = AK_FALSE;
	wifi_disconnect();
	if(g_sta_conn_thread_id != AK_INVALID_TASK)
	{
		atbm_stopThread(&g_sta_conn_thread_id);
		g_sta_conn_thread_id = AK_INVALID_TASK;
	}
	
}

static void wifi_sta_status(int argc, char **args)
{
	if (argc != 2)
	{
		wifi_sta_help();
		return;
	}
	if(wifi_isconnected())
	{
		rt_kprintf("wifi connected\n");
	}
	else
	{
		rt_kprintf("wifi disconnected\n");
	}
}    

/*****************************************
 * @brief set wifi info config
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_info_config(int argc, char **args)
{

	unsigned short port = 0;

}

static void wifi_config_clear(int argc, char **args)
{
    struct server_info t_server_info;
    memset(&t_server_info, 0, sizeof(struct server_info));
    wifi_set_config(&t_server_info);
}

/*****************************************
 * @brief dhcp function test
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_sta_dhcp(int argc, char **args)
{
    if (argc != 2)
	{
		wifi_sta_help();
		return;
	}
	if (!wifi_isconnected())
    {
        rt_kprintf("please connect to ap first\n");
        return;
    }   
        
    wifistation_netif_init();
    wifistation_netif_set_dhcp(DHCP_MODE_DYNAMIC_EVERY,NULL);
    wifistation_netif_get_ip();
}

extern int prepare_buffer(t_u8 * buffer, t_s8 * cmd, t_u32 num, char *args[]);
extern int process_host_cmd_resp(char *cmd_name, t_u8 * buf);


/*****************************************
 * @brief wifi driver init test
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_sta_init(int argc, char **args)
{    
    if(argc == 2)
    {
	     if(wifi_init_check())
	    {
	        printk("wifi has inited!\r\n");
	        return 0;
	    }
		else {
			rt_kprintf("sky37d rtt start init wifi\n");
			wifi_init(0);
		}
    }
    else
    {
		wifi_sta_help();
    }    
}

static void wifi_sta_wakeup(int argc, char **args)
{
    wifi_wakeup();
}

static void wifi_sta_sleep(int argc, char **args)
{
    wifi_sleep(5,30);
}

/*****************************************
 * @brief wifi keepalive function test
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_sta_keepalive(int argc, char **args)
{
    int ret = -1;
	
}

/*
* wildcast ssid in ap_list table
* return: 1 match a ssid, 0 no ssid matched 
*/
static int wifi_match_ssid(unsigned char *in_ssid, unsigned char *out_ssid, wifi_ap_list_t *ap_list)
{
	int ssid_len = strlen(in_ssid);
	int i;
	for(i = 0; i < ap_list->ap_count; i++)
	{
		if(strncmp(in_ssid, ap_list->ap_info[i].ssid, ssid_len) == 0)
		{
			rt_kprintf("match ssid:%s, channel:%d, rssi:%d ,security:%d\n", 
            ap_list->ap_info[i].ssid,ap_list->ap_info[i].channel, ap_list->ap_info[i].rssi,ap_list->ap_info[i].security);
            
			strcpy(out_ssid, ap_list->ap_info[i].ssid);
			return 1;
		}
	}
    rt_kprintf("can not find %s, pls try again\n", in_ssid);
	return 0;
}


/*****************************************
 * @brief wifi keepalive function test
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_scan_demo(int argc, char **args)
{
    wifi_ap_list_t ap_list;
    int ret, scan_cnt = 5;
    unsigned char out_ssid[MAX_SSID_LEN];

    //check wifi driver init status
    if(!wifi_init_check())
    {
    	ret = wifi_init(0);
    }
    if(ret != 0)
    {
		rt_kprintf("wifi init fail!\n");
        return;
    }
    wifi_set_mode(WIFI_MODE_STA);
    do
    {           
        wifi_scan(&ap_list);

        if(argc == 3)
        {
            if( wifi_match_ssid(args[2], out_ssid, &ap_list) == 1)
                break;

            scan_cnt--;
            drv_os_msleep(1000);
        }
        else
            return;        
    }while(scan_cnt > 0);

    return;
}
static void wifi_start_log(int argc, char **args)
{
	if(strcmp(args[1], "1") == 0)
	{
		_wifi_start_log(1);
	}
	else if(strcmp(args[1], "0") == 0)
	{
		_wifi_start_log(0);
	}

}
static void sdio_dump(int argc, char **args){

	atbm_sdio_dump();

}
#ifdef WPS_SUPPORT

static void wifi_wps_demo(int argc, char **args)
{
	int ret;
	struct bss_descriptor bss_connected;
	ret =  wifi_init(0);
#ifdef WIFI_MLANUTL
	process_param_config(23, &wmm_para);
	process_aggrpriotbl(3, NULL);
	process_aggrpriotbl(2, NULL);
	
	process_addbareject(11, NULL);
	process_addbareject(2, NULL);
#endif
    if(ret != 0)
        return;
	wifi_set_mode(WIFI_MODE_STA);
	ret = wifi_wps_connect(&bss_connected);
	if(ret == 0)
	{
		wifistation_netif_init();
    	wifistation_netif_set_dhcp(DHCP_MODE_DYNAMIC_EVERY,NULL);
    	wifistation_netif_get_ip();
	}
}
#endif

#if DRIVER_TEST
extern int moal_wifi_set_txpower(uint8_t dbm);
extern int wifi_set_pscfg(power_save_t  *pscfg);
extern int wifi_get_pscfg(power_save_t  *pscfg);
extern int moal_wifi_get_fastlink_enable(void);
extern int moal_wifi_get_hscfg(mlan_ds_hs_cfg *hscfg);
extern int moal_wifi_set_hscfg(mlan_ds_hs_cfg *hscfg);
extern int moal_wifi_set_fastlink_enable(unsigned char fastlink_enable);
extern int moal_wifi_set_auto_reconnect(mlan_ds_auto_assoc *auto_reconnect);
extern int moal_wifi_get_pscfg(power_save_t *pscfg);
extern int moal_wifi_get_auto_reconnect(mlan_ds_auto_assoc *auto_reconnect);

/*****************************************
 * @brief sta fast link function test
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
#if 0 //charlie add
static void wifi_sta_fastlink(int argc, char **args)
{
    int fastlink;
        
    //sdio_flag_set(1);
    //sdio_backup(SDIO_BACK_PARTI);
    if(argc == 1)
    {
        fastlink = moal_wifi_get_fastlink_enable();
        rt_kprintf("fast link status %d\n", fastlink);
    }
    else
    {
        if(strcmp(args[1], "1") == 0)
        {
            moal_wifi_set_fastlink_enable(1);
        }
        else if(strcmp(args[1], "0") == 0)
        {
            moal_wifi_set_fastlink_enable(0);
        }
        else
        {
            rt_kprintf("wrong args\n");
        }
    } 
}
#endif
/*****************************************
 * @brief sta host config set
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_sta_hscfg(int argc, char **args)
{
    mlan_ds_hs_cfg hscfg;
    /* hs config*/
    if(argc == 1)/*get*/
    {
        moal_wifi_get_hscfg(&hscfg);
        /* GET operation */
        rt_kprintf("HS Configuration:\n");
        rt_kprintf("  Conditions: %d\n", (int)hscfg.conditions);
        rt_kprintf("  GPIO: %d\n", (int)hscfg.gpio);
        rt_kprintf("  GAP: %d\n", (int)hscfg.gap);
        rt_kprintf("  Indication GPIO: %d\n", (int)hscfg.ind_gpio);
        rt_kprintf("  Level for normal wakeup: %d\n", (int)hscfg.level);
        
    }
    else if(argc == 4 )
    {
        hscfg.is_invoke_hostcmd = MTRUE;
        hscfg.conditions = atoi(args[1]);
        hscfg.gpio = atoi(args[2]);
        hscfg.gap = atoi(args[3]);
        hscfg.hs_wake_interval = 0;
        hscfg.ind_gpio = 0;
        hscfg.level = 0;
        moal_wifi_set_hscfg(&hscfg);
    }        
}

static void wifi_sta_ps(int argc, char **args)
{
    int ps_enable;
    if(argc == 2)
    {
        ps_enable = atoi(args[1]);
        rt_kprintf("set sta ps %d\n", ps_enable);
        wifi_power_cfg(ps_enable);
    }
    else
    {
        rt_kprintf(" sta ps 0/1\n");
    }
}

/*****************************************
 * @brief sta power save config set
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_sta_pscfg(int argc, char **args)
{
    power_save_t pscfg;
    if(argc == 1)/*get*/
    {
        moal_wifi_get_pscfg(&pscfg);
        rt_kprintf("PS Configuration:\n");
        rt_kprintf("  ps_null_interval: %d\n", (int)pscfg.ps_null_interval);
        rt_kprintf("  multiple_dtim_interval: %d\n", (int)pscfg.dtim_interval);
        rt_kprintf("  delay_to_ps: %d\n", (int)pscfg.delay_to_ps);
        rt_kprintf("  ps_mode: %d\n", (int)pscfg.ps_mode);
    }
    else if(argc > 1)
    {
        
        pscfg.ps_null_interval = atoi(args[1]);
        pscfg.dtim_interval = 3;
        pscfg.delay_to_ps = 500;
        pscfg.ps_mode = 1;
        
        if(argc > 2)
        {
            if(!strncmp(args[2], "0x", 2)) 
            {
                pscfg.dtim_interval = strtol(args[2], NULL, 16);
            }
            else
            {
                pscfg.dtim_interval = atoi(args[2]);
            }
        }
        if(argc > 3)
        {
            pscfg.delay_to_ps = atoi(args[3]);
        }
        if(argc > 4)
        {
            pscfg.ps_mode = atoi(args[4]);
        }

        wifi_set_pscfg(&pscfg);    
    }
}

/*****************************************
 * @brief sta auto_reconnect set
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_sta_reconnect(int argc, char **args)
{
	mlan_ds_auto_assoc auto_reconnect;

    if(argc == 1)/*option get*/
    {
        moal_wifi_get_auto_reconnect(&auto_reconnect);
        
    }
    else
    {
        if(strcmp(args[1], "1") == 0)
        {
            auto_reconnect.auto_assoc_enable = 1;
        }
        else if(strcmp(args[1], "0") == 0)
        {
            auto_reconnect.auto_assoc_enable = 0;
        }
        else
        {
            rt_kprintf("wrong args\n");
            return;
        }
        auto_reconnect.auto_assoc_type = 3;
        auto_reconnect.auto_assoc_retry_count = 0xff;
        auto_reconnect.auto_assoc_retry_interval= 10; /* 10 second*/
        auto_reconnect.auto_assoc_flags = 0;
        
        moal_wifi_set_auto_reconnect(&auto_reconnect);
    }
}

static void wifi_sta_txpower(int argc, char **args)
{
    if(argc == 2)
    {
        uint8_t dbm = atoi(args[1]);
        if(dbm > 0 && dbm < 18)
        {
            moal_wifi_set_txpower(dbm);
        }
    }
    else
    {
        rt_kprintf("argument error\n");
    }
}
#endif

/*****************************************
 * @brief start wifi ap
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_ap_start(int argc, char **args)
{

    rt_kprintf("%s",help_ap[1]);

}

/*****************************************
 * @brief stop wifi ap
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void wifi_ap_stop(int argc, char **args)
{
    if (argc != 1)
    {
        rt_kprintf("%s",help_ap[1]);
        return;
    }
    rt_kprintf("stop wifi ap...\n");
}


/* wifi command entry table, we can add new cmd hear */
static wifi_cmd_entry_t s_sta_cmd_table[] = 
{
/* STA cmd start*/
    {"conn",       wifi_sta_conn},
    {"fastlink",   wifi_sta_fastlink},
    {"disconn",    wifi_sta_disconn},
    {"status",     wifi_sta_status},
    {"dhcp",       wifi_sta_dhcp},
    {"config",     wifi_info_config},
    {"clearcfg",   wifi_config_clear},
    {"wakeup",     wifi_sta_wakeup},
    {"sleep",      wifi_sta_sleep},
    {"init",       wifi_sta_init},
    {"keepalive",  wifi_sta_keepalive},
    {"scan",       wifi_scan_demo},
    {"log",       wifi_start_log},
    {"sdio",       sdio_dump},
#ifdef WPS_SUPPORT
	{"wps", 	   wifi_wps_demo},  
#endif    
/* add for driver test*/
#if DRIVER_TEST
//    {"fastlink",   wifi_sta_fastlink},
    {"hscfg",      wifi_sta_hscfg},
    {"ps",         wifi_sta_ps},
    {"pscfg",      wifi_sta_pscfg},
    {"auto_reconn",wifi_sta_reconnect},
    {"txpower",    wifi_sta_txpower},
#endif
    {"NULL",       NULL}

};

static wifi_cmd_entry_t s_ap_cmd_table[] = 
{
/* ap cmd start*/
    {"start",      wifi_ap_start},
    {"stop",       wifi_ap_stop},
    {"NULL",       NULL}
};

/*****************************************
 * @brief wifi cmd entry check
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return int 0 on success, -1 on faild
 *****************************************/
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

/*****************************************
 * @brief wifi config function
 * 测试WIFI连接,
 * 连接到指定名字的路由器，加密模式和频道自动适应
 * 密码长度在WPA或WPA2模式下8 <= len <= 64;在WEP模式下必须为5或13
 * @param arc[in]  the cmd param number
 * @param arg[in]  the cmd param
 * @return void
 *****************************************/
static void cmd_wifi_sta(int argc, char **args)
{
	int i = 0;
    if(cmd_entry_check(s_sta_cmd_table, argc, args) != 0)
    {       
		wifi_sta_help();
    }
	
}

MSH_CMD_EXPORT(cmd_wifi_sta, cmd_wifi_sta test);

