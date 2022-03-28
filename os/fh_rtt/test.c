#ifndef __RT_ECOS_H__
#define __RT_ECOS_H__



//#include <cyg/io/eth/eth_drv.h> // For eth_drv_netdev
#include "atbm_hal.h"
#include "atbm_os_api.h"
#include "atbm_wifi_driver_api.h"

//#include <stdint.h> 
//#include <stddef.h>
//#include "wifi.h"
//#include "lwip/sockets.h"

//#include "../wifi_backup_common.h"

//#include "drv_api.h"
//#include "platform_devices.h"
//#include "dev_drv.h"
//#include "drv_gpio.h"
//#include "atbm_wifi_driver_api.h"

/*
*
*wifi_scan
*it will do scan in all channel
*/


#include "atbm_debug.h"
#include "atbm_hal.h"
#include "atbm_usb_hwio.h"
//#include "atbm_os_msgQ.h"
#include "atbm_os_thread.h"
#include "atbm_type.h"
#include  "atbm_os_timer.h"
#include  "atbm_os_mutex.h"
//extern atbm_int8 atbm_os_MsgQ_Send(atbm_os_msgq *pmsgQ, atbm_void *pbuf, int len, atbm_uint32 val);
extern atbm_int8 atbm_os_MsgQ_Send(atbm_os_msgq *pmsgQ, atbm_void *pbuf, atbm_uint32 val, int timeout);

extern atbm_int8 atbm_os_MsgQ_Create(atbm_os_msgq *pmsgQ, atbm_uint32 *pstack, atbm_uint32 item_size, atbm_uint32 item_num);
extern pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio);

//extern pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio,char *name);
extern int atbm_direct_read_reg_32(struct atbmwifi_common *hw_priv, atbm_uint32 addr, atbm_uint32 *val);
//#include "atbm_os_test.h"
extern struct atbmwifi_common g_hw_prv;
extern atbm_int8 atbm_os_MsgQ_Recv(atbm_os_msgq *pmsgQ, atbm_void *pbuf, atbm_uint32 val, int timeout);

struct atbm_test_item{
	char *name;
	int (*test_func)(void);
};

struct packed_test{
	char data1;
	int data2;
	short data3;
}atbm_packed;
//#define HZ  100

int atbm_packed_test(void){//0k
	if(sizeof(struct packed_test) != 7)
	{
		return -1;
		
	}
	return 0;
}

int atbm_GetOsTimeTest(void){//ok
	if((atbm_GetOsTime() <= 0) ||(atbm_GetOsTimeMs() <= 0)){
		return -1;
	}
	return 0;
}

int atbm_SleepMsTest(void){
	atbm_uint32 start, end;
	start = atbm_GetOsTime();
	wifi_printk(WIFI_ALWAYS,"start:%d\n",start);
	atbm_SleepMs(1000);
	end = atbm_GetOsTime();
	wifi_printk(WIFI_ALWAYS,"end:%d\n",end);
	if((end - start) > 110 || (end - start < 90)){
		return -1;
	}
	start = atbm_GetOsTime();
	atbm_mdelay(1000);
	end = atbm_GetOsTime();
	if((end - start) > 110 || (end - start < 90)){
		return -2;
		
	}
	wifi_printk(WIFI_ALWAYS,"atbm_SleepMsTest  ok	");
	return 0;
}

int atbm_thread_start = 0;
static int atbm_thread_arg_test_fail = 0;
void atbm_test_thread(atbm_void *p_arg){
	if(((int)p_arg) != 0x5555){
		atbm_thread_arg_test_fail = 1;
		wifi_printk(WIFI_ALWAYS,"atbm_thread_arg_test_fail	%x",(int)p_arg);
	}
	atbm_thread_start = 1;
	while(1){
		atbm_SleepMs(100);

	}
}

int atbm_thread_test(void){//ok
	int retry = 3;
	int arg = 0x5555;
	pAtbm_thread_t thread;
	thread = atbm_createThread(atbm_test_thread,arg,0);
	while((--retry) >= 0){
		if(atbm_thread_arg_test_fail){
			return -2;
		}
		if(atbm_thread_start){
			break;
		}
		atbm_SleepMs(10);
	}
	if(retry < 0){
		return -3;
	}
	if(atbm_stopThread(thread)){
		return -4;
	}
	atbm_thread_arg_test_fail = 0;
	atbm_thread_start = 0;
	return 0;
}
#define atbm_mutex rt_sem_t
atbm_mutex test_mutex;
int atbm_mutextest_thread_start = 0;
void atbm_mutextest_thread(atbm_void *p_arg){
	atbm_os_mutexLock(&test_mutex, 0xffffffff);
	atbm_mutextest_thread_start = 1;
	atbm_SleepMs(1000);
	atbm_mutextest_thread_start = 2;
	atbm_os_mutexUnLock(&test_mutex);
	atbm_SleepMs(1000);
	atbm_os_mutexLock(&test_mutex, 0xffffffff);
	atbm_mutextest_thread_start = 3;
	while(1){
		atbm_SleepMs(1000);
	}
}

int atbm_mutex_test(void){//ok
	pAtbm_thread_t thread;
	atbm_os_mutexLockInit(&test_mutex);
	thread = atbm_createThread(atbm_mutextest_thread,(char *)"atbm_mutex_test",0);
	while(!atbm_mutextest_thread_start){
		atbm_SleepMs(10);
	}
	if(atbm_mutextest_thread_start != 1){
		return -2;
	}
	atbm_os_mutexLock(&test_mutex, 10);
	atbm_os_mutexUnLock(&test_mutex);
	while(atbm_mutextest_thread_start != 3){
		atbm_SleepMs(10);
	}
	atbm_os_DeleteMutex(&test_mutex);
	atbm_stopThread(thread);
	atbm_mutextest_thread_start = 0;
	wifi_printk(WIFI_ALWAYS,"atbm_mutex_test ok");
	return 0;
}

atbm_os_wait_queue_head_t test_event;
void atbm_waitEventtest_thread(atbm_void *p_arg){
	atbm_os_wakeup_event(&test_event);
	while(1){
		atbm_SleepMs(1000);
	}
}

int atbm_waitEvent_test(void){
	int status;
	pAtbm_thread_t thread;
	atbm_uint32 start, end;

	atbm_os_init_waitevent(&test_event);
	thread = atbm_createThread(atbm_waitEventtest_thread,  (char *)"atbm_waitEvent_test",0);
	status = atbm_os_wait_event_timeout(&test_event, 10*HZ);
	if(status != 1){
		return -1;
	}
	start = atbm_GetOsTime();
	status = atbm_os_wait_event_timeout(&test_event, 1*HZ);
	if(status != 0){
		return -2;
	}
	end = atbm_GetOsTime();
	if((end - start < 90) || (end - start > 110)){
		return -3;
	}
	atbm_stopThread(thread);
	wifi_printk(WIFI_ALWAYS,"atbm_waitEvent_test ok");
	return 0;
}

void atbm_timeout_func(atbm_void * CallRef){
	atbm_os_wait_queue_head_t *event = (atbm_os_wait_queue_head_t *)CallRef;
	atbm_os_wakeup_event(event);
}

int atbm_timer_test(void){
	OS_TIMER Timer;
	atbm_os_wait_queue_head_t event;
	atbm_uint32 start, end;
	atbm_memset(&Timer,0,sizeof(Timer));
	atbm_os_init_waitevent(&event);
	if(atbm_InitTimer(&Timer, (TIMER_CALLBACK *)atbm_timeout_func, &event))
	{
		return -1;
	}
	start = atbm_GetOsTime();
	if(atbm_StartTimer(&Timer, HZ))
	{
		return -2;
	}
	atbm_os_wait_event_timeout(&event, 10*HZ);
	end = atbm_GetOsTime();
	if((end - start < 90) || (end - start > 110)){
		return -3;
	}
	wifi_printk(WIFI_ALWAYS,"atbm_timer_test ok");
	return 0;
}

atbm_uint32 msgPool[4];

void atbm_MsgQtest_thread(atbm_void *p_arg){
	int flag = 0x5555;
	atbm_os_msgq *msgQ = (atbm_os_msgq *)p_arg;
	atbm_os_MsgQ_Send(msgQ, &flag, 4, 0xffffffff);
	while(1){
		atbm_SleepMs(1000);
	}
}

int atbm_MsgQ_test(void){//ok
	atbm_os_msgq msgQ;
	pAtbm_thread_t thread;
	int flag;
	if(atbm_os_MsgQ_Create(&msgQ, msgPool, sizeof(atbm_uint32), 4))
	{
		return -1;
	}
	thread = atbm_createThread(atbm_MsgQtest_thread, &msgQ, 0);
	if(atbm_os_MsgQ_Recv(&msgQ, &flag, sizeof(int), 0xffffffff))
	{
		return -2;
	}
	if(flag != 0x5555)
	{
		return -3;
	}
	atbm_stopThread(thread);
	wifi_printk(WIFI_ALWAYS,"atbm_MsgQ_test ok");
	return 0;
}

int atbm_timesync_test(void){
	unsigned int pre, now;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	if(atbm_direct_read_reg_32(hw_priv, 0x1640006c, &pre) < 0){
		return -1;
	}
	atbm_SleepMs(1000);
	if(atbm_direct_read_reg_32(hw_priv, 0x1640006c, &now) < 0){
		return -2;
	}
	if((now - pre < 950000) || (now - pre > 1050000)){
		return -3;
	}
	wifi_printk(WIFI_ALWAYS,"atbm_timesync_test ok");
	return 0;
}


extern int wsm_txrx_data_test(struct atbmwifi_common *hw_priv,int len,int if_id);

int atbm_txrx_test(void){
	int time = 10000;
	struct atbmwifi_common	*hw_priv = &g_hw_prv;
	unsigned int band_width = 0;
	unsigned int start = atbm_GetOsTime();
	unsigned int now = start;
	wifi_printk(WIFI_ALWAYS,"now:%d\n",now);
	while((atbm_GetOsTime() - start) < time){
		if(wsm_txrx_data_test(hw_priv, 1500, 0))
		{
			wifi_printk(WIFI_ALWAYS,"atbm_txrx_test -1");
			return -1;
		}
		band_width += 1500;
		if((atbm_GetOsTime() - now) >= HZ){
			band_width = band_width << 3;
			wifi_printk(WIFI_ALWAYS, "band width %uM%uK\n", band_width>>20, (band_width>>10)&0x3ff);
			now = atbm_GetOsTime();
			band_width = 0;
		}
	}
	return 0;
}

struct atbm_test_item items[] = {
	{"atbm_packed", atbm_packed_test},
	{"atbm_GetOsTime", atbm_GetOsTimeTest},
	{"atbm_SleepMs", atbm_SleepMsTest},
	{"atbm_thread", atbm_thread_test},
	{"atbm_mutex", atbm_mutex_test},
	{"atbm_waitEvent", atbm_waitEvent_test},
	{"atbm_timer", atbm_timer_test},
	{"atbm_MsgQ", atbm_MsgQ_test},
	/*following test items can only be executed after the setup of SDIO/USB interface*/
	{"atbm_timesync", atbm_timesync_test},
	{"atbm_txrx", atbm_txrx_test},
	{NULL, NULL},
};

int atbm_func_test(void){
	int i, ret;
	for(i = 0; items[i].test_func != NULL; i++){
		ret = items[i].test_func();
		if(ret){
			wifi_printk(WIFI_ALWAYS, "%d.Test item[%s] failed[%d]!!\n", i+1, items[i].name, ret);
		}else{
			wifi_printk(WIFI_ALWAYS, "%d.Test item[%s] passed!!\n", i+1, items[i].name);
		}
	}
	return 0;
}

int atbm_func_test_item(int item){
	int ret;

	ret = items[item-1].test_func();
	if(ret){
		wifi_printk(WIFI_ALWAYS, "%d.Test item[%s] failed[%d]!!\n", item, items[item-1].name, ret);
	}else{
		wifi_printk(WIFI_ALWAYS, "%d.Test item[%s] passed!!\n", item, items[item-1].name);
	}
	return 0;
}






//wifi_ap_list_t ap_list;
extern int atbm_wifi_scan_network(char* scan_buf, atbm_uint32 buf_size);
extern unsigned int atbm6032_wifi_APList_ScanChannel(void);
//char result_buf[2732];
int wifi_scan(void)//(wifi_ap_list_t *ap_list)
{
#if 0
	int i = 0;
	//char result_buf[2732];
	memset(result_buf, 0, sizeof(result_buf));
	WLAN_SCAN_RESULT *result = (WLAN_SCAN_RESULT *)result_buf;
	WLAN_BSS_INFO *info = result->bss_info;
	atbm_wifi_scan_network(result_buf,2732);
	
	ap_list->ap_count = result->count;
	printf("\n\n result->count=%d \n",result->count);
	for(i =0;i < result->count; i++)
	{
		info = info +i;
		ap_list->ap_info[i].channel = info->chanspec;
		ap_list->ap_info[i].security = 0;
		ap_list->ap_info[i].rssi = (char)info->RSSI;

		atbm_memcpy(ap_list->ap_info[i].ssid, info->SSID,  info->SSID_len);
		ap_list->ap_info[i].ssid[info->SSID_len] ='\0';
		
		atbm_memcpy(ap_list->ap_info[i].bssid, info->BSSID, 6);
		printf("\n\n ap_info[%d].channel=%d, SSID=%c-%c-%c-%c\n",i,info->chanspec,info->SSID[0],info->SSID[1],info->SSID[2],info->SSID[3]);

		
	}
	#endif
	return 0;
}



void wifi_scan_Test(void)
{

#if 0
	printf("\n\n wifi_scan_Test \n");
	wifi_printk(WIFI_ALWAYS,"111111111111111111111111\n");

	atbm_wifi_on(0);
	//wifi_scan(&ap_list);
	atbm_wifi_sta_join_ap("f_test", NULL, 0, 0, "12345678");
/////////
	/*get mac addr from efuse*/
	unsigned char	MacAddr[6];

	atbm_wifi_get_mac_address(MacAddr);
	atbm_uint8 a;
	wifi_printk(WIFI_ALWAYS,"atbm_get_mac_address1\n");
	for(a = 0;a < 6; a++)
	{
		wifi_printk(WIFI_ALWAYS,",%x",MacAddr[a]);
	}
#endif

	
	
	
	//atbm_wifi_on(0);
	
	//wifi_scan(&ap_list);
	//atbm_wifi_sta_join_ap("f_test", NULL, 0, 0, "12345678");
	
	
	
}
extern int atbm6032_close(void *ndev);

void wifi_test(void)
{

	printf("\n\n atbm_wifi_isconnected(1) %d \n",atbm_wifi_isconnected(0));

}

void wifi_tes1(void)
{

	
}

void wifi_tes5(void)
{
	
	
	
}


void wifi_tes3(void)
{
	//printf("\n\n ====================================================== \n");

	//atbm_SleepMs(100000);
	//printf("\n\n +++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n");
	//atbm_thread_test();
	//atbm_SleepMsTest();
	//atbm_mutex_test();
	atbm_func_test();
}




extern struct atbm_usb_interface *usb_res_intf;
extern int atbm6032_close(void *ndev);

int cnt_dd = 0;
void wifi_tes4(void)
{

}


#endif
