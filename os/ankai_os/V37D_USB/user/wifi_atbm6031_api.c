/*
 *  * wifi API for application
 *   *
 *    */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "rtthread.h"
//#include "platform_devices.h"
#include "wlan_mgnt.h"
#include "wlan_dev.h"

#include "atbm_wifi_driver_api.h"
#include "wifi_backup_common.h"
#include "rtthread.h"
#include "atbm_wifi_driver_api.h"
#include "wifi_types.h"
#include "drv_os.h"
#include "atbm_config.h"

 extern int ver_register(lib_info_t *lib);
#define ATBM6032_WIFI_DRV_LIB_VER    "libdrv_wifi_atbm6032 V1.0.07"

#define TX_RX_DEBUG         0

#define SCAN_BUF_SIZE       (4096)

static char wifi_init_state = 0; 
static struct rt_wlan_device * s_wlan_dev = NULL;

static const char *ver_info[] = {
    ATBM6032_WIFI_DRV_LIB_VER,
	    __DATE__
};


static lib_info_t lib_info = {
    .ver_info = (char **)&ver_info,
    .exp      = NULL,
};

static int __wifi_init_check(void)
{
    if(wifi_init_state != 0) {
		return 1;
    }
    rt_kprintf("wifi not init\n");
    return 0;
}

#if TX_RX_DEBUG
static void __print_data(char *data, int len)
{
    int i = 0;
    for(i = 0; i < len; i++){
        rt_kprintf("%c ", data[i]);
    }
    rt_kprintf("\n");
}
#endif
char *rtt_atbm6032_wifi_version(void)
{
	return ATBM6032_WIFI_DRV_LIB_VER;
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
int wifi_init_use_time = 0;
rt_err_t atbm6032_init(struct rt_wlan_device *wlan)
{
	int ret = 0;
	ver_register(&lib_info);
	rt_kprintf("atbm6032wifi lib version:%s\n", (char *)rtt_atbm6032_wifi_version());
    if(__wifi_init_check()) {
        rt_kprintf(" wifi has inited \r\n");
        return 0;
    }
	int t1,t2;
	t1 = get_tick_count();
	wifi_init_use_time = t1;
#if ATBM_SDIO_BUS
	ret = atbm_akwifi_setup_sdio();
#endif
#if ATBM_USB_BUS
	ret = atbm_akwifi_setup_usb();
#endif
	if(ret < 0 ){
		rt_kprintf("atbm_akwifi_setup_sdio error\n");
		return -1;
	}
	atbm_wifi_hw_init();
    
	rt_kprintf("[%s]-line:%d wifi init done!\n",__FUNCTION__, __LINE__);
 	//rt_kprintf("[%s]-line:%d\n",__FUNCTION__, __LINE__);
	//ret = wifi_init(0);

    unsigned char mac[6] = {0,0,0,0,0,0};
	atbm_wifi_get_mac_address(mac);
	rt_kprintf("\n mac addr=%x:%x:%x:%x:%x:%x\n\n"
		, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

    wifi_init_state = 1;
	t2 = get_tick_count();
	rt_kprintf("fixed wifi init time1 is:%ldms\n", t2-t1);
	return ret;
}



rt_err_t atbm6032_set_mode(struct rt_wlan_device *wlan, rt_wlan_mode_t mode)
{
    if(!__wifi_init_check())
            return -1;

    if(mode == RT_WLAN_AP) {
        atbm_wifi_on(ATBM_WIFI_AP_MODE);
    } else if ( mode == RT_WLAN_STATION){
        atbm_wifi_on(ATBM_WIFI_STA_MODE);
    }
    rt_kprintf("atbm6032_set_mode %d \n", mode);

	return 0;

}

rt_err_t atbm6032_scan(struct rt_wlan_device *wlan, struct rt_scan_info *scan_info)
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

int wifi_sta_fastlink(char *ssid, char *bssid, WLAN_AUTH_MODE authMode, WLAN_ENCRYPTION encryption, const char *key)
{
    rt_kprintf("atbm6032 donot support fastlink\n");
    return -1;
}

rt_err_t atbm6032_join(struct rt_wlan_device *wlan, struct rt_sta_info *sta_info)
{
    if(!__wifi_init_check())
        return -1;
    
    rt_kprintf("atbm6032_join...\n");
    //TODO: set encryption with sta_info->security
    WLAN_AUTH_MODE authMode = WLAN_WPA_AUTH_PSK;
    WLAN_ENCRYPTION encryption = WLAN_ENCRYPT_AES;
    
#if 1 //chalie add 
    int ret = atbm_wifi_sta_join_ap((char *)sta_info->ssid.val,sta_info->bssid,authMode,encryption,(char *)sta_info->key.val);
#else
#if 0
	int ret = wifi_sta_fastlink((char *)sta_info->ssid.val,sta_info->bssid,authMode,encryption,(char *)sta_info->key.val);
#else
	
#endif

#endif
	if(ret != 0 )
    {
       rt_kprintf("wifi connect fail\n");
    }
	//rt_kprintf(" xxx wifi connect success [%s]-line:%d\n",__FUNCTION__, __LINE__);
	return 0;

}
rt_err_t atbm6032_softap(struct rt_wlan_device *wlan, struct rt_ap_info *ap_info)
{

    return 0;//moal_wifi_ap_cfg((char *)ap_info->ssid.val, 0, (char *)ap_info->key.val, (int)ap_info->security, (int)ap_info->channel, MAX_NUM_CLIENTS);
}

rt_err_t atbm6032_disconnect(struct rt_wlan_device *wlan)
{
	return atbm_wifi_sta_disjoin_ap();
}
rt_err_t atbm6032_ap_stop(struct rt_wlan_device *wlan)
{
	return 0;

}
rt_err_t atbm6032_ap_deauth(struct rt_wlan_device *wlan, rt_uint8_t mac[])
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6032_scan_stop(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
int atbm6032_get_rssi(struct rt_wlan_device *wlan)
{
	  return atbm_wifi_get_rssi_avg();
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6032_set_powersave(struct rt_wlan_device *wlan, int level)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
int atbm6032_get_powersave(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6032_cfg_promisc(struct rt_wlan_device *wlan, rt_bool_t start)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6032_cfg_filter(struct rt_wlan_device *wlan, struct rt_wlan_filter *filter)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}
rt_err_t atbm6032_set_channel(struct rt_wlan_device *wlan, int channel)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

int atbm6032_get_channel(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_err_t atbm6032_set_country(struct rt_wlan_device *wlan, rt_country_code_t country_code)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_country_code_t atbm6032_get_country(struct rt_wlan_device *wlan)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_err_t atbm6032_set_mac(struct rt_wlan_device *wlan, rt_uint8_t *mac)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

rt_err_t atbm6032_get_mac(struct rt_wlan_device *wlan, rt_uint8_t *mac)
{
    rt_kprintf(" atbm6032 get mac [%s]-line:%d\n",__FUNCTION__, __LINE__);
    atbm_wifi_get_mac_address(mac);
    return 0;
}

void atbm6032_wifi_input(void *buf,int len)
{
    if(s_wlan_dev && s_wlan_dev->flags != 0 )
    {
        if(s_wlan_dev->prot != NULL) {
            
            //debug
            #if TX_RX_DEBUG
            rt_kprintf("rx:");
            char *data = (char *)buf;
            __print_data(&data[42], 16);
            #endif
            
            rt_wlan_dev_report_data(s_wlan_dev, buf, len);
        } else {
            rt_kprintf("wlan_dev->prot == NULL !");
        }
    }
    else
       rt_kprintf("wifi devcie not register !");   
}

int atbm6032_recv(struct rt_wlan_device *wlan, void *buff, int len)
{
    rt_kprintf(" %s not support \n", __FUNCTION__);
    return -1;
}

extern atbm_void atbm_wifi_tx_pkt_dir(atbm_void *buff, int len);

int atbm6032_send(struct rt_wlan_device *wlan, void *buff, int len)
{
    if(s_wlan_dev && (s_wlan_dev->flags != 0) )
    {
        //debug 
        #if TX_RX_DEBUG
        rt_kprintf("tx:");
        char *tmp = (char *)buff;
        __print_data((char *)&tmp[42], 16);
        #endif
        
    #if 0
        struct atbm_buff *AtbmBuf = ATBM_NULL;
        AtbmBuf = atbm_dev_alloc_skb(len);
        if (!AtbmBuf) {
            rt_kprintf("<ERROR> tx_pkt alloc skb \n");
            return;
        }
        
        //donot use for cyc, because use pbuf_copy_partial
        char *tmp = atbm_skb_put(AtbmBuf,len);
        rt_memcpy(tmp, buff, len);   

        //the the actual xmit interface, implement in wifi lib
        atbm_wifi_tx_pkt(AtbmBuf);
    #else
        atbm_wifi_tx_pkt_dir(buff, len);
    #endif
    
            
    }

    return 0;
}


rt_err_t atbm6032_sleep(struct rt_wlan_device *wlan, rt_wlan_sleep_cfg_t *sleep_cfg)
{

	return 0;//moal_wifi_sleep(wakeup_cfg.wakeup_data);	
}



const struct rt_wlan_dev_ops wlan_ops = {
    .wlan_init = atbm6032_init,
    .wlan_mode = atbm6032_set_mode,
    .wlan_scan = atbm6032_scan,
    .wlan_join = atbm6032_join,
    .wlan_softap = atbm6032_softap,
    .wlan_disconnect = atbm6032_disconnect,
    .wlan_ap_stop = atbm6032_ap_stop,
    .wlan_ap_deauth = atbm6032_ap_deauth,
    .wlan_scan_stop = atbm6032_scan_stop,
    .wlan_get_rssi = atbm6032_get_rssi,
    .wlan_set_powersave = atbm6032_set_powersave,
    .wlan_get_powersave = atbm6032_get_powersave,
    .wlan_cfg_promisc = atbm6032_cfg_promisc,
    .wlan_cfg_filter = atbm6032_cfg_filter,
    .wlan_set_channel = atbm6032_set_channel,
    .wlan_get_channel = atbm6032_get_channel,
    .wlan_set_country = atbm6032_set_country,
    .wlan_get_country = atbm6032_get_country,
    .wlan_set_mac = atbm6032_set_mac,
    .wlan_get_mac = atbm6032_get_mac,
    .wlan_recv = atbm6032_recv,
    .wlan_send = atbm6032_send,
    .wlan_set_sleep = atbm6032_sleep,
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
		    
    rt_wlan_dev_register(s_wlan_dev, "wifi", &wlan_ops, RT_DEVICE_FLAG_RDWR, NULL);

    return 0;
}

INIT_COMPONENT_EXPORT(rt_wifi_device_reg);

