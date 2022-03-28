/*
 * wifi API for application
 *
 */

#include "rtthread.h"
#include "atbm_wifi_driver_api.h"

#include <stdint.h>
//#include "moal_wifi.h"
//#include "wifi.h"
#include "akos_api.h"
#include "akos_error.h"

//#include "drv_api.h"
#include "platform_devices.h"
//#include "dev_info.h"
#include "drv_gpio.h"

#include "wlan_mgnt.h"
#include "wlan_dev.h"
#include "wifi_backup_common.h"
#include "atbm_config.h"

#if 1
#define wifi_dbg(fmt, ...) rt_kprintf(fmt, ##__VA_ARGS__)
#else
#define wifi_dbg(_fmt, ...)
#endif

/* Suppress unused parameter warning */
#ifndef UNUSED_PARAMETER
#define UNUSED_PARAMETER( x ) ( (void)(x) )
#endif
#define PACK_STRUCT_FIELD(x) x

typedef void					T_VOID;		/* void */

#define SSID_MAX_LEN 32
#define KEY_MAX_LEN 64

static char wifi_init_state = 0; 
static struct rt_wlan_device * s_wlan_dev = NULL;

/* Here are some info for the INT8 Action value setting.

Bits      Bits Name     Description 
7:4       Tx_action      Action[7:4] = 0   No response 
                         Action[7:4] = 1   ARP Response
                         Action[7:4] = 2   Ping Response
3:2       Reserved 

1:0       Rx_action      On matching Rx pkt and filter during Hostsleep mode:
                         Action[1:0] = 00  Discard and not wake host
                         Action[1:0] = 01  Discard and wake host 
                         Action[1:0] = 10  Invalid
                         Action[1:0] = 11  Allow and Wake host

#--------------------------------------------------------------------------------------------------
#	example: Disable MEF filters
#	mefcfg={
#		#Criteria: bit0-broadcast, bit1-unicast, bit3-multicast
#		Criteria=2 		# Unicast frames are received during hostsleepmode
#		NumEntries=0		# Number of activated MEF entries
#	}
*/

//charlie add 
typedef enum
{
	MOAL_WIFI_MODE_STA = 0, 
	MOAL_WIFI_MODE_AP,
	MOAL_WIFI_MODE_ADHOC,
	MOAL_WIFI_MODE_UNKNOWN
	
}MOAL_AK_WIFI_MODE;
//static unsigned char mef_conf[WAKEUP_PKT_MAX];
/** Maximum number of clients supported by AP */
#define MAX_NUM_CLIENTS         10

extern int wifi_init(int init_param);
//charlie add end

#if 0 
static unsigned char mef_conf_format[] = 
	"mefcfg={\n"\
		"Criteria=7\n"\
		"NumEntries=2\n"\
		"mef_entry_0={\n"\
			"mode=1\n"\
			"action=3\n"\
			"filter_num=1\n"\
			"RPN=Filter_0 \n"\
			"Filter_0={\n"\
				"type=0x41\n"\
				"repeat=1\n"\
				"byte=98:3b:16:f8:f3:9c\n"\
				"offset=50\n"\
			"}\n"\
		"}\n"\
		"mef_entry_1={\n"\
			"mode=1\n"\
			"action=0x10\n"\
			"filter_num=1\n"\
            "RPN=Filter_0\n"\
            "Filter_0={\n"\
				"type=0x41\n"\
				"repeat=1\n"\
				"byte=%02x:%02x:%02x:%02x\n"\
				"offset=46\n"\
			"}\n"\
		"}\n"\
	"}\n";

/*wake up data udp packet*/
/*0x983B16F8F39C*/

char wifi_init_check()
{
    if(wifi_init_state != 0xff)
    {
        return 1;
    }

    rt_kprintf("wifi not init\n");
    return 0;
}

char *wifi_get_version()
{
	return NULL;// ((char *)moal_wifi_get_version());
}

/**
 * @brief  wifi_get_mode, get wifi mode
 * @param  : 
 * @retval AK_WIFI_MODE
 */

int wifi_get_mode(void)
{
	return 0;//moal_wifi_get_mode();	
}

/**
 * @brief  wifi_set_mode, set wifi mode.
 * ap_wifi_dev and sta_wifi_dev are two different device, set mode just set the global variable wifi_dev
 * @param  : 
 * @retval AK_WIFI_MODE
 */

int wifi_set_mode(int type)
{
    if(!wifi_init_check())
        return -1;
    
	return moal_wifi_set_mode(type);
}


/**
 * @brief  wifi_isconnected, return wifi connect status
 * @param  : 
 * @retval 1 - connect , 0 - not connected 
 */

int wifi_isconnected(void)
{
    if(!wifi_init_check())
        return 0;

	return moal_wifi_isconnected();
}

/**
 * @brief  wifi_connect, wifi connect to ap 
 * @param  : ssid, key
 * @retval 0 - send connect msg ok , -1 - some error happen 
 */

int wifi_connect( char *essid, char *key)
{
    if(!wifi_init_check())
        return -1;

	return moal_wifi_connect(essid, key);
}

#if 0

/**
 * @brief  wifi_connect, wifi connect to ap 
 * @param  : ssid, key
 * @retval 0 - send connect msg ok , -1 - some error happen 
 */

int wifi_quick_connect( char *essid, char *key, struct bss_descriptor *bss_saved)
{
    if(!wifi_init_check())
        return -1;

	return moal_wifi_quick_connect(essid, key, bss_saved);
}



/**
 * @brief  wifi_disconnect, wifi disconnect from ap 
 * @param  : ssid, key
 * @retval 0 - send connect msg ok , -1 - some error happen 
 */

int wifi_disconnect(void)
{
	return moal_wifi_disconnect();
}



/**
 * @brief  wifi_create_ap, destroy
 * @param  : 
 * @retval AK_WIFI_MODE
 */

int wifi_create_ap(struct _apcfg *ap_cfg)
{
	if(!wifi_init_check())
        return -1;
	
	return moal_wifi_ap_cfg((char *)ap_cfg->ssid, (int)ap_cfg->mode, (char *)ap_cfg->key, (int)ap_cfg->enc_protocol, (int)ap_cfg->channel, WIFI_MAX_CLIENT_DEFAULT);
}

/**
 * @brief  wifi_destroy_ap, destroy
 * @param  : 
 * @retval AK_WIFI_MODE
 */

int wifi_destroy_ap(void)
{
	if(!wifi_init_check())
        return -1;

	return moal_wifi_destroy_ap();
}

int wifi_set_txpower(uint8_t dbm)
{
	if(!wifi_init_check())
        return -1;

	moal_wifi_set_txpower(dbm);

    return 0;
}


int wifi_get_pscfg(power_save_t  *pscfg)
{
	moal_power_save_t *moal_pscfg = (moal_power_save_t *)pscfg;
    return moal_wifi_get_pscfg(moal_pscfg);
}


int wifi_set_pscfg(power_save_t  *pscfg)
{
	moal_power_save_t *moal_pscfg = (moal_power_save_t *)pscfg;
	return moal_wifi_set_pscfg(moal_pscfg);
}

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
int wifi_power_cfg(uint8_t power_save_level)
{
	/*ps mode is set to 1 as default and this interface may cause some sdio cmd timeout, so comment it*/
	//return moal_wifi_power_cfg(power_save_level);
	return 0;
}



int wifi_ps_status()
{
	return 0;
}



static void send_keepalive_pre_tcp(keep_alive_t *keep_alive)
{
	struct sockaddr_in net_cfg;
	int ka_socket = -1;
	int send_len = 0;
	int err = -1;
	int tmp = 10;
	
	net_cfg.sin_family = AF_INET;
	net_cfg.sin_len = sizeof(struct sockaddr_in);
	net_cfg.sin_port = htons(keep_alive->dst_port);
	net_cfg.sin_addr.s_addr = keep_alive->dst_ip;

	printf("keepalive server ip %s, port %d\n", inet_ntoa(keep_alive->dst_ip), keep_alive->dst_port);
	ka_socket = socket(AF_INET, SOCK_STREAM, 0);//tcp socket
	if (ka_socket < 0)
	{
		printf("create socket error.\n");
	}
	else
	{
		unsigned int opt = 6000;
		setsockopt(ka_socket, SOL_SOCKET, SO_SNDTIMEO, &opt, sizeof(unsigned int)) ;
		err = connect(ka_socket, (struct sockaddr*)&net_cfg, sizeof(struct sockaddr_in));
		if (err !=0)
		{
			printf("connect keepalive server %s error\n",  inet_ntoa(keep_alive->dst_ip));
		}
		else
		{
			while (tmp-- > 0)
			{
				send_len = send(ka_socket, keep_alive->payload, keep_alive->payload_len, MSG_WAITALL);
				if (send_len < 0)
				{
					printf("send error\n");
				}
				mini_delay(1000);
			}
		}
	}
	
}


static void send_keepalive_pre_udp(keep_alive_t *keep_alive)
{
	struct sockaddr_in net_cfg;
	int ka_socket = -1;
	int send_len = 0;
	int tmp = 10;
	
	net_cfg.sin_family = AF_INET;
	net_cfg.sin_len = sizeof(struct sockaddr_in);
	net_cfg.sin_port = htons(keep_alive->dst_port);
	net_cfg.sin_addr.s_addr = keep_alive->dst_ip;

	printf("keepalive server ip %s, port %d\n", inet_ntoa(keep_alive->dst_ip), keep_alive->dst_port);
	ka_socket = socket(AF_INET, SOCK_DGRAM, 0);//tcp socket
	if (ka_socket < 0)
	{
		printf("create socket error.\n");
	}
	else
	{
		{
			while (tmp-- > 0)
			{
				send_len = sendto(ka_socket, keep_alive->payload, keep_alive->payload_len, 0, (struct sockaddr*)&net_cfg, sizeof(struct sockaddr));
				if (send_len < 0)
				{
					printf("send error\n");
				}
				mini_delay(1000);
			}
		}
	}
}


struct tcp_hdr {
  PACK_STRUCT_FIELD(u16_t src);
  PACK_STRUCT_FIELD(u16_t dest);
  PACK_STRUCT_FIELD(u32_t seqno);
  PACK_STRUCT_FIELD(u32_t ackno);
  PACK_STRUCT_FIELD(u16_t _hdrlen_rsvd_flags);
  PACK_STRUCT_FIELD(u16_t wnd);
  PACK_STRUCT_FIELD(u16_t chksum);
  PACK_STRUCT_FIELD(u16_t urgp);
} PACK_STRUCT_STRUCT;


#define ETH_HLEN 14
#define IP_HLEN  20

uint16_t checkSum(uint16_t *buff, int len)
{
	// calculate IP checksum for a buffer of bytes
	// len is number of 16-bit values
	uint32_t xsum = 0;

	while (len--)
		xsum += * buff++;

	while (xsum >> 16)
		xsum = (xsum & 0xFFFF) + (xsum >> 16);

	return (uint16_t)(~xsum);
}


int get_keepalive_pkt(keep_alive_t *keep_alive, char *keepalive_ip_pkt, int *pkt_len)
{
	struct capture_filter cap_filter;
	char *cap_buf = keepalive_ip_pkt;
	struct tcp_hdr *tcp_h;
	
	memset(&cap_filter, 0, sizeof(struct capture_filter));
	cap_filter.payload = keep_alive->payload;
	cap_filter.payload_len = keep_alive->payload_len;
	*pkt_len = lwip_capture(CAP_TX, &cap_filter, 1, cap_buf, 30);
	
	/*modify tcp ack and checkSum*/
	tcp_h = (struct tcp_hdr *)(cap_buf + ETH_HLEN + IP_HLEN);
	/*set seqno to the next seqno*/
	tcp_h ->seqno =  htonl(ntohl(tcp_h ->seqno) + keep_alive->payload_len);
	tcp_h ->chksum = htons(checkSum((uint16_t *)tcp_h, *pkt_len - ETH_HLEN - IP_HLEN));
	
	return *pkt_len;
}



#define KEEPALIVE_STACK_SIZE      (4*1024)
#define KEEPALIVE_PRIORITY      (50)

int wifi_keepalive_set(keep_alive_t *keep_alive)
{
	int pret = -1,ret = -AK_EFAILED;
	moal_keep_alive_t moal_keep_alive;
	pthread_t tid;
	unsigned long *stack_address;
	
	int eth_pkt_len;
	char *eth_pkt_buf;

	if(keep_alive->enable == 1) /*start keepalive*/
	{
		stack_address = malloc(KEEPALIVE_STACK_SIZE);
		//Note:eth_pkt_buf should set large than a ethernet pkt size
		eth_pkt_buf = malloc(1600); 

        pret = pthread_create(&tid, NULL, send_keepalive_pre_tcp, (void *)keep_alive)
		if (pret != 0)
		{
			printf("create keepalive paket task error\n");
			ret = -AK_EFAILED;
		}
		else
		{
		
			ret = get_keepalive_pkt(keep_alive, eth_pkt_buf, &eth_pkt_len);
			/*delete task*/
			if (AK_SUCCESS != AK_Terminate_Task(handle))
			{
				printf("Terminate keepalive packet task error\n");
			}
			//terminate task
			if (AK_SUCCESS != AK_Delete_Task(handle))
			{
				printf("Delete  keepalive packet task error\n");
			}
			
			if(ret > 0)
			{
				/*set keepalive to wifi fw*/
				moal_keep_alive.enable = true;
				moal_keep_alive.send_interval = keep_alive->send_interval * 1000;
				moal_keep_alive.retry_interval = keep_alive->retry_interval * 1000;
				moal_keep_alive.retry_count = keep_alive->retry_count;
				memcpy(moal_keep_alive.eth_pkt, eth_pkt_buf, eth_pkt_len);
				moal_keep_alive.eth_pkt_len = eth_pkt_len;
			#if 0
				int i;
				printf("keepalive pkt len %d:\n", moal_keep_alive.eth_pkt_len);
				for(i = 0; i < moal_keep_alive.eth_pkt_len; i++)
				{
					printf("%02x ", *(moal_keep_alive.eth_pkt + i));
				}
				printf("\n");
			#endif
				printf("start keepalive ");
				ret = moal_wifi_set_keepalive(&moal_keep_alive);
			
			}
			else
			{
				printf("No keepalive pkt captured, No keepalive set\n");
				ret = -AK_EFAILED;
			}
			
		}
		free(stack_address);
		free(eth_pkt_buf);
	}
	else /*stop keepalive*/
	{
		printf("stop keepalive ");
		moal_keep_alive.enable = false;
		ret = moal_wifi_set_keepalive(&moal_keep_alive);
	}
	printf((ret == 0) ? "Success\n" : "Fail\n");
	return ret;
}

int wifi_keepalive_get(keep_alive_t *keep_alive)
{
	return 0;
}

/*
######################### MEF Configuration command ##################
mefcfg={
	#Criteria: bit0-broadcast, bit1-unicast, bit3-multicast
	Criteria=2 		# Unicast frames are received during hostsleepmode
	NumEntries=1		# Number of activated MEF entries
	#mef_entry_0: example filters to match TCP destination port 80 send by 192.168.0.88 pkt or magic pkt.
	mef_entry_0={
		#mode: bit0--hostsleep mode, bit1--non hostsleep mode
		mode=1		# HostSleep mode
		#action: 0--discard and not wake host, 1--discard and wake host 3--allow and wake host
		action=3	# Allow and Wake host
		filter_num=3    # Number of filter
		#RPN only support "&&" and "||" operator,space can not be removed between operator.
		RPN=Filter_0 && Filter_1 || Filter_2
		#Byte comparison filter's type is 0x41,Decimal comparison filter's type is 0x42,
		#Bit comparison filter's type is  0x43
		#Filter_0 is decimal comparison filter, it always with type=0x42
		#Decimal filter always has type, pattern, offset, numbyte 4 field
                #Filter_0 will match rx pkt with TCP destination port 80
		Filter_0={
			type=0x42	# decimal comparison filter
			pattern=80	# 80 is the decimal constant to be compared
			offset=44	# 44 is the byte offset of the field in RX pkt to be compare
			numbyte=2       # 2 is the number of bytes of the field
		}
		#Filter_1 is Byte comparison filter, it always with type=0x41
		#Byte filter always has type, byte, repeat, offset 4 filed
		#Filter_1 will match rx pkt send by IP address 192.168.0.88
		Filter_1={
			type=0x41          	# Byte comparison filter
			repeat=1                # 1 copies of 'c0:a8:00:58'
			byte=c0:a8:00:58	# 'c0:a8:00:58' is the byte sequence constant with each byte
						# in hex format, with ':' as delimiter between two byte.
			offset=34               # 34 is the byte offset of the equal length field of rx'd pkt.
		}
		#Filter_2 is Magic packet, it will looking for 16 contiguous copies of '00:50:43:20:01:02' from
		# the rx pkt's offset 56
		Filter_2={
			type=0x41		# Byte comparison filter
			repeat=16               # 16 copies of '00:50:43:20:01:02'
			byte=00:50:43:20:01:02  # '00:50:43:20:01:02' is the byte sequence constant
			offset=56		# 56 is the byte offset of the equal length field of rx'd pkt.
		}
		#Filter_3 is TCP packet, it will looking for '98:3b:16:f8:f3:9c' from
		# the rx pkt's offset 62
		Filter_2={
			type=0x41		# Byte comparison filter
			repeat=1               # 
			byte=98:3b:16:f8:f3:9c  # '98:3b:16:f8:f3:9c' is the byte  constant
			offset=62		# 62 is the byte offset of the equal length field of rx'd pkt.
		}
		#Filter_4 is UDP packet, it will looking for '98:3b:16:f8:f3:9c' from
		# the rx pkt's offset 50
		Filter_2={
			type=0x41		# Byte comparison filter
			repeat=1               # 
			byte=98:3b:16:f8:f3:9c  # '98:3b:16:f8:f3:9c' is the byte  constant
			offset=50		# 50 is the byte offset of the equal length field of rx'd pkt.
		}
	}
}
*/



/**
*wifi_get_tx_pending get current tx_pending in driver.
*@return   tx_pending --success, -1 --fail
*/
int wifi_get_tx_pending(void)
{
	return moal_wifi_get_tx_pending();

}
/**
*wifi_set_max_tx_pending  set max tx_pending allowed in driver.
*@param tx_pending,  input value 
*@return   0 --success, others --fail

*/

int wifi_set_max_tx_pending(unsigned char max_tx_pending)
{
	return moal_wifi_set_max_tx_pending(max_tx_pending);
}

/**
* 
*wifi_get_max_tx_pending  get max tx_pending allowed in driver.
*@return   max_tx_pending --success, -1 --fail

*/

int wifi_get_max_tx_pending(void)
{
	return moal_wifi_get_max_tx_pending();
}


int wifi_list_station(wifi_sta_list_t *sta_list)
{
	return moal_wifi_get_sta_list(sta_list);
}

/*
*
*wifi_scan
*it will do scan for ever if target ssid does no found
*/

int wifi_scan(wifi_ap_list_t *ap_list)
{
	return moal_wifi_scan((moal_ap_list_t *)ap_list);
}


/**
 * @brief  读取mac地址，mac地址从8782芯片读取
 * @param  mac_addr : mac地址 6BYTE
 */
int wifi_get_mac(unsigned char *mac_addr)
{
	return moal_wifi_get_mac(mac_addr);
}


//0: init, 1: resume, 
char wifi_get_init_status(void)
{
    return wifi_init_state;

}
//0: normal wakeup, -1: wakeup abnormal, 
int wifi_check_wakeup_status(void)
{
    return 0;
}
#endif

void moal_wifi_input(void *buf,int len)
{
    if(s_wlan_dev && s_wlan_dev->flags != 0 )
    {
        if(s_wlan_dev->prot != NULL)
            rt_wlan_dev_report_data(s_wlan_dev, buf, len);
        else
            rt_kprintf("wlan_dev->prot == NULL !");
    }
    else
       rt_kprintf("wifi devcie not register !");   
}

extern int netif_tx(void *data);
extern void *moal_alloc_skb(char ** data, int size);

/**
 * @brief initializing wifi 
 * @author
 * @date 
 * @param [in] pParam a pointer to T_WIFI_INITPARAM type
 * @return int
 * @retval   0  initializing sucessful
 * @retval  -1 initializing fail
 */
rt_err_t atbm6031_init(struct rt_wlan_device *wlan)
{
	int ret = 1;
#if 0
	
	moal_keep_alive_t moal_keep_alive = {0};
	T_WIFI_INFO  *wifi =  NULL; //(T_WIFI_INFO *)wifi_dev.dev_data;
	unsigned long  nb;
    int fast_link = (int)wlan->user_data;

    if(wifi_init_check())
    {
        rt_kprintf(" wifi has inited \r\n");
        return 0;
    }

	wifi  = (T_WIFI_INFO *)platform_get_devices_info(DEV_WIFI);
	if(NULL == wifi)
	{
		rt_kprintf("get wifi devcie fail!");
		return 0;
	}
    

    gpio_share_pin_set( ePIN_AS_SDIO2 , wifi->sdio_share_pin);
	//rt_kprintf("=====%d %d %d\r\n",wifi->sdio_share_pin,wifi->bus_mode,wifi->clock);
	
	
	rt_kprintf("\nWifilib version:%s\n", wifi_get_version());

    wifi_init_state = fast_link;
	
	if(fast_link && wifi_restore_sdio_data() == 0)
	{
		
		rt_kprintf("reseume wifi\n");
		ret = moal_wifi_resume();
		if(!ret)
        {
    		moal_keep_alive.enable = 0;
    		moal_wifi_set_keepalive(&moal_keep_alive);
        }
    }
	else
	{
		rt_kprintf("init wifi\n");
        
        // reset wifi chip
        //#define nb 14
        nb = wifi->gpio_power.nb;
        gpio_set_pin_as_gpio(nb);
        gpio_set_pin_dir(nb, 1);
        gpio_set_pull_down_r(nb, 0);
        gpio_set_pin_level(nb, 0); 
        rt_thread_mdelay(100/5);
        gpio_set_pin_level(nb, 1); 
        
		ret = moal_wifi_init(NULL);
	}

    unsigned char mac[6] = {0,0,0,0,0,0};
	moal_wifi_get_mac(mac);
	rt_kprintf("\n mac addr=%x:%x:%x:%x:%x:%x\n\n"
		, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
 #else
 	rt_kprintf(" vvvvvvvvvvv [%s]-line:%d\n",__FUNCTION__, __LINE__);
 	wifi_init(1);
 #endif
	return ret;
}

rt_err_t atbm6031_set_mode(struct rt_wlan_device *wlan, rt_wlan_mode_t mode)
{
    int type = -1;
    
    if(!wifi_init_check())
            return -1;

    if( mode == RT_WLAN_AP)
        type = MOAL_WIFI_MODE_AP;
    else if ( mode == RT_WLAN_STATION)
        type = MOAL_WIFI_MODE_STA;

    rt_kprintf(" %s, mode %d \n",__FUNCTION__, type);
    return moal_wifi_set_mode(type);

}

rt_err_t atbm6031_scan(struct rt_wlan_device *wlan, struct rt_scan_info *scan_info)
{
    
    struct rt_wlan_info info;
    struct rt_wlan_buff buff;
#if 0  
    moal_ap_list_t *ap_list = malloc(sizeof(moal_ap_list_t));
    int i;

    wifi_dbg(" atbm6031_scan \n");

    moal_wifi_scan(ap_list);

    wifi_dbg(" atbm6031_scan done %d \n", ap_list->ap_count);

    buff.data = &info;
    buff.len = sizeof(info);

    for(i = 0; i < ap_list->ap_count; i++)
    {
        memset(&info, 0 , sizeof(info));

        strcpy((char *)info.ssid.val, (const char *)ap_list->ap_info[i].ssid);
        strcpy((char *)info.bssid, (const char *)ap_list->ap_info[i].bssid);
        info.ssid.len = strlen((const char *)ap_list->ap_info[i].ssid);
        info.security = ap_list->ap_info[i].security;
        info.channel = ap_list->ap_info[i].channel;
        info.rssi = ap_list->ap_info[i].rssi;
        
        rt_wlan_dev_indicate_event_handle(wlan, RT_WLAN_DEV_EVT_SCAN_REPORT, &buff);
        if(scan_info != NULL && (strncmp((const char *)scan_info->ssid.val,(const char *) ap_list->ap_info[i].ssid, scan_info->ssid.len)) == 0)
        {
            break;
        }
    }
        
    free(ap_list);
#endif
    return 0;
}

rt_err_t atbm6031_join(struct rt_wlan_device *wlan, struct rt_sta_info *sta_info)
{
    if(!wifi_init_check())
        return -1;

    int ret = moal_wifi_connect((char *)sta_info->ssid.val, (char *)sta_info->key.val);
    
	return ret;

}
rt_err_t atbm6031_softap(struct rt_wlan_device *wlan, struct rt_ap_info *ap_info)
{
    if(!wifi_init_check())
        return -1;

    rt_kprintf(" ssid %s, key %s, sec %d channel %d \n ", (char *)ap_info->ssid.val, (char *)ap_info->key.val, (int)ap_info->security, (int)ap_info->channel);
    return moal_wifi_ap_cfg((char *)ap_info->ssid.val, 0, (char *)ap_info->key.val, (int)ap_info->security, (int)ap_info->channel, MAX_NUM_CLIENTS);
}

rt_err_t atbm6031_disconnect(struct rt_wlan_device *wlan)
{
	return 0;//moal_wifi_disconnect();
}
rt_err_t atbm6031_ap_stop(struct rt_wlan_device *wlan)
{
	if(!wifi_init_check())
        return -1;

	return moal_wifi_destroy_ap();
}
rt_err_t atbm6031_ap_deauth(struct rt_wlan_device *wlan, rt_uint8_t mac[])
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_scan_stop(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
int atbm6031_get_rssi(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_set_powersave(struct rt_wlan_device *wlan, int level)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
int atbm6031_get_powersave(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_cfg_promisc(struct rt_wlan_device *wlan, rt_bool_t start)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_cfg_filter(struct rt_wlan_device *wlan, struct rt_wlan_filter *filter)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_set_channel(struct rt_wlan_device *wlan, int channel)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

int atbm6031_get_channel(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_err_t atbm6031_set_country(struct rt_wlan_device *wlan, rt_country_code_t country_code)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_country_code_t atbm6031_get_country(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_err_t atbm6031_set_mac(struct rt_wlan_device *wlan, rt_uint8_t *mac)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_err_t atbm6031_get_mac(struct rt_wlan_device *wlan, rt_uint8_t *mac)
{
    //moal_wifi_get_mac(mac);
    
    return 0;
}

int atbm6031_recv(struct rt_wlan_device *wlan, void *buff, int len)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

int atbm6031_send(struct rt_wlan_device *wlan, void *buff, int len)
{
	char *p802x_hdr = NULL;
    void *tx_skb = NULL;
#if 0
    if(s_wlan_dev && (s_wlan_dev->flags != 0) )
    {
        tx_skb = (void *)moal_alloc_skb( &p802x_hdr, len);

        //wifi_dbg(" %s \n", __FUNCTION__);        
        if(tx_skb != NULL)
        {
            rt_memcpy(p802x_hdr, buff, len);            
            //the  the actual xmit interface, implement in wifi lib
            netif_tx(tx_skb);
        }
    }
#endif
    return 0;
}


rt_err_t atbm6031_sleep(struct rt_wlan_device *wlan, rt_wlan_sleep_cfg_t *sleep_cfg)
{
	int ret = -1;
#if 0	
	unsigned char my_ip[4];
	moal_power_save_t ps_cfg;
	net_wakeup_cfg_t wakeup_cfg;
    moal_ds_hs_cfg hscfg;

    if(!wifi_isconnected())
    {
		printf("wifi is net connected \n");
		return -1;
    }

	ret = wifi_backup_sdio_data();
	if(ret != 0)
	{
		printf("backup sdio data error\n");
		return -1;
	}

	/*set power save config*/
	ps_cfg.ps_mode = 1;/*(0: Unchanged, 1: Auto mode, 2: PS-Poll mode, 3: PS Null mode)*/
	ps_cfg.dtim_interval = sleep_cfg->dim;
	ps_cfg.ps_null_interval = sleep_cfg->null_data_interval; /*nul data interval for wifi connection keepalive in seconds*/
	ps_cfg.delay_to_ps = 1000; /*(0-65535: Value in milliseconds, default 1000ms)*/
    ps_cfg.bcn_miss_timeout = 15; /** Beacon miss timeout in milliseconds, default 100ms*/
	ret = moal_wifi_set_pscfg(&ps_cfg);
	if(ret != 0)
	{
		rt_kprintf("set pscfg error\n");
		return ret;
	}

    /*set host config*/
	hscfg.is_invoke_hostcmd = 0;
	hscfg.conditions = 0; /*broad cast and unicast packet will wakeup wifi*/
	hscfg.gpio = 1;
	hscfg.gap = 0;
	hscfg.hs_wake_interval = 0;//500;
	hscfg.ind_gpio = 0;
	hscfg.level = 0;
	ret = moal_wifi_set_hscfg(&hscfg);
	if(ret != 0)
	{
		rt_kprintf("set hscfg error\n");
		return ret;
	}

	/*set arp reques for me to wakeup data*/   	
	sprintf((char *)mef_conf, (const char *)mef_conf_format, my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
	//set wakeup data
	wakeup_cfg.wakeup_data_offset = 50;
	wakeup_cfg.wakeup_data_len = strlen((const char *)mef_conf);
	
	if(wakeup_cfg.wakeup_data_len > WAKEUP_PKT_MAX)
	{
		rt_kprintf("wakeup data len too long, wifi sleep error\n");
		return -1;
	}
	strcpy((char *)wakeup_cfg.wakeup_data, (const char *)mef_conf);
#endif
	return 0;//moal_wifi_sleep(wakeup_cfg.wakeup_data);	
}



#endif

static char __wifi_init_check()
{
    if(wifi_init_state != 0) {
		return 1;
    }
    printk("wifi not init\n");
    return 0;
}

/**
 * @brief initializing wifi 
 * @author
 * @date 
 * @param [in] pParam a pointer to T_WIFI_INITPARAM type
 * @return int
 * @retval   0  initializing sucessful
 * @retval  -1 initializing fail
 */
rt_err_t atbm6031_init(struct rt_wlan_device *wlan)
{
	int ret = 0;

    if(__wifi_init_check()) {
        rt_kprintf(" wifi has inited \r\n");
        return -1;
    }

#if ATBM_SDIO_BUS
	ret = atbm_akwifi_setup_sdio();
	if(ret < 0 ){
		iot_printf("atbm_akwifi_init err\n");
		return -1;
	}
#endif
	atbm_wifi_hw_init();
    
	rt_kprintf("[%s]-line:%d wifi init done!\n",__FUNCTION__, __LINE__);
 	//rt_kprintf("[%s]-line:%d\n",__FUNCTION__, __LINE__);
	//ret = wifi_init(0);

    unsigned char mac[6] = {0,0,0,0,0,0};
	atbm_wifi_get_mac_address(mac);
	rt_kprintf("\n mac addr=%x:%x:%x:%x:%x:%x\n\n"
		, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    wifi_init_state = 1;
	return ret;
}



rt_err_t atbm6031_set_mode(struct rt_wlan_device *wlan, rt_wlan_mode_t mode)
{
    int type = -1;
 
    if(!__wifi_init_check())
            return -1;

    if(mode == RT_WLAN_AP) {
        atbm_wifi_on(ATBM_WIFI_AP_MODE);
    } else if ( mode == RT_WLAN_STATION){
        atbm_wifi_on(ATBM_WIFI_STA_MODE);
    }
    rt_kprintf("atbm6031_set_mode %d \n", mode);

	return 0;

}

rt_err_t atbm6031_scan(struct rt_wlan_device *wlan, struct rt_scan_info *scan_info)
{
    #if 1
//    struct rt_wlan_info info;
    struct rt_wlan_buff buff;
	wifi_ap_list_t *ap_list = (wifi_ap_list_t *)malloc(sizeof(wifi_ap_list_t));

    char *result_buf = malloc(4096);
	memset(result_buf, 0, 4096);
	atbm_wifi_scan_network(result_buf,4096);
    WLAN_SCAN_RESULT *result = (WLAN_SCAN_RESULT *)result_buf;
    WLAN_BSS_INFO *info = result->bss_info;

	ap_list->ap_count = result->count;
	for(int i =0;i < result->count; i++)
	{
		info = info +i;
		ap_list->ap_info[i].channel = info->chanspec;
		ap_list->ap_info[i].security = 0;  
		ap_list->ap_info[i].rssi = info->RSSI;

		memcpy(ap_list->ap_info[i].ssid, info->SSID,  info->SSID_len);
		ap_list->ap_info[i].ssid[info->SSID_len] ='\0';
		
		memcpy(ap_list->ap_info[i].bssid, info->BSSID, 6);
	}
    
        
    free(result_buf);

    #endif
    
    return 0;
}

extern void  wifi_sta_fastlink1(void *args);
rt_err_t atbm6031_join(struct rt_wlan_device *wlan, struct rt_sta_info *sta_info)
{
    rt_kprintf("wifi_init_state=%d\n", wifi_init_state);

    if(!__wifi_init_check())
        return -1;
    
    rt_kprintf("atbm6031_join...\n");
    //TODO: set encryption with sta_info->security
    WLAN_AUTH_MODE authMode = WLAN_WPA_AUTH_PSK;
    WLAN_ENCRYPTION encryption = WLAN_ENCRYPT_AES;
#if 0 //chalie add 
    int ret = atbm_wifi_sta_join_ap((char *)sta_info->ssid.val,sta_info->bssid,authMode,encryption,(char *)sta_info->key.val);
#else
	struct rt_thread *thread = rt_thread_create("conn_thread", wifi_sta_fastlink1, sta_info, 4096, 10, 5);
	if(thread)
		rt_thread_startup(thread);
//	int ret = wifi_sta_fastlink1((char *)sta_info->ssid.val,sta_info->bssid,authMode,encryption,(char *)sta_info->key.val);
#endif
#if 0
	if(ret != 0 )
    {
       rt_kprintf("wifi connect fail\n");
    }
#endif
	//rt_kprintf(" xxx wifi connect success [%s]-line:%d\n",__FUNCTION__, __LINE__);
	return 0;

}
rt_err_t atbm6031_softap(struct rt_wlan_device *wlan, struct rt_ap_info *ap_info)
{

    return 0;//moal_wifi_ap_cfg((char *)ap_info->ssid.val, 0, (char *)ap_info->key.val, (int)ap_info->security, (int)ap_info->channel, MAX_NUM_CLIENTS);
}

rt_err_t atbm6031_disconnect(struct rt_wlan_device *wlan)
{
	return atbm_wifi_sta_disjoin_ap();
}
rt_err_t atbm6031_ap_stop(struct rt_wlan_device *wlan)
{
	return 0;

}
rt_err_t atbm6031_ap_deauth(struct rt_wlan_device *wlan, rt_uint8_t mac[])
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_scan_stop(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
int atbm6031_get_rssi(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_set_powersave(struct rt_wlan_device *wlan, int level)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
int atbm6031_get_powersave(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_cfg_promisc(struct rt_wlan_device *wlan, rt_bool_t start)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_cfg_filter(struct rt_wlan_device *wlan, struct rt_wlan_filter *filter)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6031_set_channel(struct rt_wlan_device *wlan, int channel)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

int atbm6031_get_channel(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_err_t atbm6031_set_country(struct rt_wlan_device *wlan, rt_country_code_t country_code)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_country_code_t atbm6031_get_country(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_err_t atbm6031_set_mac(struct rt_wlan_device *wlan, rt_uint8_t *mac)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_err_t atbm6031_get_mac(struct rt_wlan_device *wlan, rt_uint8_t *mac)
{
    rt_kprintf(" atbm6031 get mac [%s]-line:%d\n",__FUNCTION__, __LINE__);
    return wifi_get_mac(mac);
}

void atbm6031_wifi_input(void *buf,int len)
{
    //rt_kprintf("rx:");
    int err;

    if(s_wlan_dev && s_wlan_dev->flags != 0 )
    {
        if(s_wlan_dev->prot != NULL) {
            //debug
            #if 0 //charlie add 
            char *data = (char *)buf;
            int i = 0;
            for(i = 42; i < 42+16; i++){
                rt_kprintf("%c ", data[i]);
            }
            rt_kprintf("\n");
            #endif
            err = rt_wlan_dev_report_data(s_wlan_dev, buf, len);
            if(err){
				rt_kprintf("err:%d\n", err);
            }
			
        } else {
            rt_kprintf("wlan_dev->prot == NULL !");
        }
    }
    else
       rt_kprintf("wifi devcie not register !");   
}

int atbm6031_recv(struct rt_wlan_device *wlan, void *buff, int len)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}


int atbm6031_send(struct rt_wlan_device *wlan, void *buff, int len)
{
    //rt_kprintf("tx:");

    if(s_wlan_dev && (s_wlan_dev->flags != 0) )
    {
        struct atbm_buff *AtbmBuf = ATBM_NULL;
        AtbmBuf = atbm_dev_alloc_skb(len);
        if (!AtbmBuf) {
            rt_kprintf("<ERROR> tx_pkt alloc skb \n");
            return;
        }
        
        //donot use for cyc, because use pbuf_copy_partial
        char *tmp = atbm_skb_put(AtbmBuf,len);
        rt_memcpy(tmp, buff, len);   

        #if 0 //charlie add 
        int i = 0;
        for(i = 42; i < 42+16; i++){
            rt_kprintf("%c ", tmp[i]);
        }
        rt_kprintf("\n");
        #endif
        
            //
        //the the actual xmit interface, implement in wifi lib
        atbm_wifi_tx_pkt(AtbmBuf);

            
    }

    return 0;
}


rt_err_t atbm6031_sleep(struct rt_wlan_device *wlan, rt_wlan_sleep_cfg_t *sleep_cfg)
{

	return 0;//moal_wifi_sleep(wakeup_cfg.wakeup_data);	
}



const struct rt_wlan_dev_ops wlan_ops = {
    .wlan_init = atbm6031_init,
    .wlan_mode = atbm6031_set_mode,
    .wlan_scan = atbm6031_scan,
    .wlan_join = atbm6031_join,
    .wlan_softap = atbm6031_softap,
    .wlan_disconnect = atbm6031_disconnect,
    .wlan_ap_stop = atbm6031_ap_stop,
    .wlan_ap_deauth = atbm6031_ap_deauth,
    .wlan_scan_stop = atbm6031_scan_stop,
    .wlan_get_rssi = atbm6031_get_rssi,
    .wlan_set_powersave = atbm6031_set_powersave,
    .wlan_get_powersave = atbm6031_get_powersave,
    .wlan_cfg_promisc = atbm6031_cfg_promisc,
    .wlan_cfg_filter = atbm6031_cfg_filter,
    .wlan_set_channel = atbm6031_set_channel,
    .wlan_get_channel = atbm6031_get_channel,
    .wlan_set_country = atbm6031_set_country,
    .wlan_get_country = atbm6031_get_country,
    .wlan_set_mac = atbm6031_set_mac,
    .wlan_get_mac = atbm6031_get_mac,
    .wlan_recv = atbm6031_recv,
    .wlan_send = atbm6031_send,
    .wlan_set_sleep = atbm6031_sleep,
};

int rt_wifi_device_reg(void)
{

    rt_kprintf("F:%s L:%d run \n", __FUNCTION__, __LINE__);

    if(s_wlan_dev == NULL)
    {
        s_wlan_dev = rt_malloc(sizeof(struct rt_wlan_device));
        if(NULL == s_wlan_dev)
    	{
    		rt_kprintf("wifi devcie malloc fail!");
    		return -1;
    	}
    }
		    
    rt_wlan_dev_register(s_wlan_dev, "wlan0", &wlan_ops, RT_DEVICE_FLAG_RDWR, NULL);

    return 0;
}

INIT_COMPONENT_EXPORT(rt_wifi_device_reg);

void module_init(struct rt_dlmodule *module)
{
    rt_wifi_device_reg();
}


RTM_EXPORT(module_init);
