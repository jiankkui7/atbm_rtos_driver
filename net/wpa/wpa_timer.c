/**************************************************************************************************************
 * altobeam RTOS WSM host interface (HI) implementation
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "atbm_hal.h"
static int wpa_bh_term = 0;
extern FLASH_FUNC int hostapd_eapol_init(struct atbmwifi_vif *priv,struct atbmwifi_wpa_state_machine *sm);
extern atbm_void hostapd_4_way_handshake_start(atbm_void *data1,atbm_void *data2);
extern atbm_void atbmwifi_wpa_event_mode_init(struct atbmwifi_vif *start_priv,enum atbm_nl80211_iftype start_type);
extern atbm_void atbmwifi_wpa_event_mode_deinit(struct atbmwifi_vif *stop_priv,enum atbm_nl80211_iftype stop_type);
extern int atbmwifi_wpa_event_associte_ap(struct atbmwifi_vif *priv,struct atbmwifi_cfg* config);
extern atbm_void atbmwifi_wpa_event_authen(struct atbmwifi_vif *priv);
extern void atbmwifi_wpa_event_assciate(struct atbmwifi_vif *priv);
atbm_void atbmwifi_wpa_event_assocated(struct atbmwifi_vif *priv,atbm_uint16 linkid);
extern FLASH_FUNC atbm_void atbmwifi_wpa_event_deauthen(struct atbmwifi_vif *priv);
extern FLASH_FUNC void atbmwifi_wpa_event_connect_fail(struct atbmwifi_vif *priv);
extern FLASH_FUNC int atbmwifi_ieee80211_rx(struct atbmwifi_vif *priv,struct atbm_buff *skb);
extern atbm_void ieee802_1x_receive(struct atbmwifi_vif *priv,
							 const atbm_uint8 *sa, const atbm_uint8 *buf,
							 atbm_size_t len);
extern atbm_void wpa_supplicant_rx_eapol(atbm_void *ctx, const atbm_uint8 *src_addr,
			     atbm_uint8 *buf, atbm_size_t len);
extern FLASH_FUNC atbm_void atbmwifi_wpa_event_process_scan_end(struct atbmwifi_common *hw_priv,
				atbm_uint32 scan_status);
extern atbm_void wpa_supplicant_rx_eap_status(struct atbmwifi_vif *priv);
FLASH_FUNC atbm_void atbmwifi_wpa_event_start_ap(struct atbmwifi_vif *priv,struct atbmwifi_cfg *config);
#define  ELOOP_TIMER_OUT			(HZ)		
#define  ELOOP_TIMER_TABLE_SIZE		(15)
#define ATBM_WPA_EVENT_QUEUE_MAX	(10)
static void atbmwifi_wpa_event_bh(atbm_void *arg);
int os_get_random(unsigned char *buf, atbm_size_t len)
{
	int i,j=0;
	atbm_uint32 random_num;
	int seed = 0x12334545;
	const atbm_uint8 *addr = (const atbm_uint8 *)&random_num;
	random_num = atbm_os_random() ^ seed;	
	//seed = seed;
	for(i = 0;i < len;i++)
	{		
		buf[i] = addr[j++];
		if((j%4)==0) {
			j=0;
			random_num = atbm_os_random()*random_num;
		}		
	}
	return 0;
}

int os_random(atbm_void)
{
	int tmp =0;	
	os_get_random((unsigned char *)&tmp,4);
	return tmp;
}

struct atbm_wpa_event {
	struct atbm_list_head list;
	enum atbm_wpa_event_id event;
	atbm_void* data1;
	atbm_void* data2;
	atbm_void* data3;
	#ifdef ATBM_WPA_EVENT_NEEDED_ACK
	atbm_uint8 waited_ack;
	atbm_os_wait_queue_head_t wait_lock;
	#endif
};
static pAtbm_thread_t atbm_wpa_event_bh;
static struct atbm_list_head atbm_wpa_event_pending_list;
static atbm_spinlock_t atbm_wpa_event_mutex;
static atbm_os_wait_queue_head_t atbm_wpa_event_wake;
static atbm_uint32 atbm_wpa_event_runing = 0;

#define ATBM_EVENT_RUNNING					(1)
#define ATBM_EVENT_NOT_RUNNING				(2)

#define atbm_wpa_event_set_running(__running)	(*((volatile atbm_uint32*)(&atbm_wpa_event_runing)) = (atbm_uint32)(__running))
#define atbm_wpa_event_get_running()			*((volatile atbm_uint32*)(&atbm_wpa_event_runing))

#define atbm_wpa_event_in_running()			atbm_wpa_event_set_running(ATBM_EVENT_RUNNING)
#define atbm_wpa_event_out_running()		atbm_wpa_event_set_running(ATBM_EVENT_NOT_RUNNING)
#define atbm_wpa_event_is_running()			(atbm_wpa_event_get_running()==ATBM_EVENT_RUNNING)

#define atbm_wpa_event_lock(_flag)			atbm_spin_lock_irqsave(&atbm_wpa_event_mutex,_flag)
#define atbm_wpa_event_unlock(_flag)		atbm_spin_unlock_irqrestore(&atbm_wpa_event_mutex,_flag)
#define atbm_wpa_event_bh_wakeup()			if(!atbm_wpa_event_is_running())	atbm_os_wakeup_event(&atbm_wpa_event_wake)
#define atbm_wpa_event_clear(_event)
#define atbm_wpa_event_set_params(__pevent,__data1,__data2,__data3,__ev,__ack)			\
		(__pevent)->data1=__data1;(__pevent)->data2=__data2;(__pevent)->data3=__data3;	\
		(__pevent)->event = __ev;atbm_wpa_wait_ack_en(__pevent,__ack)

#define atbm_wpa_queue_ev_get(__pevent)		__pevent = atbm_list_first_entry(&atbm_wpa_event_pending_list, struct atbm_wpa_event, list)
#define atbm_wpa_queue_init_event_lock()	atbm_spin_lock_init(&atbm_wpa_event_mutex);	atbm_os_init_waitevent(&atbm_wpa_event_wake); 
#define atbm_wpa_wait_ack(_event)
#define atbm_wpa_wait_ack_init(_event)
#define atbm_wpa_wait_acked(_event)
#define atbm_wpa_wait_ack_en(_event,_en)
#define atbm_wpa_event_queue_ev_to_pendding(__pevent) 														\
		atbm_list_add_tail(&((__pevent)->list), &atbm_wpa_event_pending_list)

#define ATBM_WPA_EVENT_ADD_EVENT_TO_QUEUE(_pevent,_data1,_data2,_data3,_ev,_ack,_ret)						\
		do{																									\
			atbm_uint32 __irq_flag = 0;																		\
			_pevent = atbm_kmalloc(sizeof(struct atbm_wpa_event),GFP_KERNEL);								\
			ATBM_BUG_ON(_pevent==ATBM_NULL)																	\
			atbm_memset(_pevent,0,sizeof(struct atbm_wpa_event));											\
			atbm_wpa_event_set_params(_pevent,_data1,_data2,_data3,_ev,_ack);								\
			atbm_wpa_event_lock(__irq_flag);																	\
			atbm_wpa_event_queue_ev_to_pendding(_pevent);													\
			atbm_wpa_event_unlock(__irq_flag);																\
			_ret = 0;																						\
		}while(0)
#define ATBM_WPA_EVENT_PROCESS_QUEUED_EV(_pevent,_irq_flag)															\
		do{																									\
			atbm_wpa_queue_ev_get(_pevent);																	\
			atbm_list_del(&_pevent->list);																			\
			atbm_wpa_event_unlock(_irq_flag);																\
			atbm_wpa_event_process(_pevent);																\
			atbm_wpa_wait_acked(_pevent);																	\
			atbm_kfree(_pevent);																			\
			atbm_wpa_event_lock(_irq_flag);																	\
		}while(0)
#define ATBM_WPA_EVENT_QUEUE_INIT()																			\
		do{																									\
			ATBM_INIT_LIST_HEAD(&atbm_wpa_event_pending_list);												\
			atbm_wpa_queue_init_event_lock();																\
		}while(0)

struct wpa_timer
{
	struct atbm_list_head list;
	atbm_void (*fun) (atbm_void *data1,atbm_void *data2);
	atbm_void *data1;
	atbm_void *data2;
	atbm_uint32 cancled;
//	struct atbm_timer_list *timer;
	OS_TIMER  timer;
};
static struct wpa_timer timer_table[ELOOP_TIMER_TABLE_SIZE];
static struct atbm_list_head atbm_timeout_free_list;
static struct atbm_list_head atbm_timeout_pennding_list;
static struct atbm_list_head atbm_timeout_ready_list;
static atbm_spinlock_t atbm_timer_mutex;

#define atbm_timer_lock(_flag) 			atbm_spin_lock_irqsave(&atbm_timer_mutex,_flag)
#define atbm_timer_unlock(_flag)		atbm_spin_unlock_irqrestore(&atbm_timer_mutex,_flag)
#define ATBM_CANCLE_TIMER_FROM_LIST(_list,_func,_data1,_data2,_found)										\
	do{																										\
		struct wpa_timer *timer_cancle,*temp;																\
		atbm_list_for_each_entry_safe(timer_cancle,temp,(_list),list,struct wpa_timer){						\
			if(timer_cancle->fun != _func)																	\
				continue;																					\
			if(timer_cancle->data1 != _data1)																\
				continue;																					\
			if(timer_cancle->data2 != _data2)																\
				continue;																					\
			_found = 1;																						\
			atbm_list_move_tail(&timer_cancle->list,&atbm_timeout_free_list);								\
			timer_cancle->cancled = 1;																		\
		}																									\
	}while(0)

#define ATBM_FREE_TIMER_FORM_LIST(_list)																	\
	do{																										\
		struct wpa_timer *free_timer = ATBM_NULL;															\
		while(!atbm_list_empty((_list))){																	\
			free_timer = atbm_list_first_entry((_list),struct wpa_timer, list);								\
			free_timer->cancled = 1;																		\
			atbm_list_move_tail(&free_timer->list,&atbm_timeout_free_list);									\
		}																									\
	}while(0)
static NORELOC  atbm_void eloop_timeout_func(TIMER_1ST_PARAM atbm_void * arg)
{
	struct wpa_timer *ready_timer = (struct wpa_timer *)arg;
	atbm_uint32 irq_flag = 0;
	if(ready_timer == ATBM_NULL)
		return;

	if(ready_timer->fun == ATBM_NULL)
		return;

	atbm_timer_lock(irq_flag);
	if(ready_timer->cancled == 0)
		atbm_list_move_tail(&ready_timer->list,&atbm_timeout_ready_list);
	else
		ready_timer->cancled = 0;
	atbm_timer_unlock(irq_flag);
	
	atbm_wpa_event_bh_wakeup();
	
}
static NORELOC atbm_void eloop_timeout_func_poll(void)
{
	atbm_uint32 irq_flag = 0;
	atbm_timer_lock(irq_flag);
	while(!atbm_list_empty(&atbm_timeout_ready_list)){
		struct wpa_timer *ready_timer = atbm_list_first_entry(
			&atbm_timeout_ready_list, struct wpa_timer, list);

		if(ready_timer->fun == ATBM_NULL)
			continue;
		if(ready_timer->cancled){
			ready_timer->cancled = 0;
			continue;
		}
		atbm_timer_unlock(irq_flag);
		ready_timer->fun(ready_timer->data1,ready_timer->data2);
		atbm_timer_lock(irq_flag);	
		atbm_list_move_tail(&ready_timer->list,&atbm_timeout_free_list);
	}
	
	atbm_timer_unlock(irq_flag);
}
static int atbmwifi_wpa_timer_int(void)
{
	atbm_uint8 index = 0;
	atbm_memset(timer_table,0,sizeof(timer_table));
	atbm_spin_lock_init(&atbm_timer_mutex);
	
	ATBM_INIT_LIST_HEAD(&atbm_timeout_free_list);
	ATBM_INIT_LIST_HEAD(&atbm_timeout_pennding_list);
	ATBM_INIT_LIST_HEAD(&atbm_timeout_ready_list);
	
	for(index = 0;index<ELOOP_TIMER_TABLE_SIZE;index++)
	{
		atbm_InitTimer(&timer_table[index].timer,eloop_timeout_func,(atbm_void*)(&timer_table[index]));		
		atbm_list_add_tail(&(timer_table[index].list), &atbm_timeout_free_list);
	}

	return 0;
}
int eloop_cancel_timeout(atbm_void (*handler)(atbm_void *eloop_ctx, atbm_void *sock_ctx),
			 atbm_void *eloop_data, atbm_void *user_data)
{
//	struct wpa_timer *timer_cancle,temp;
	atbm_uint8 found = 0;
	atbm_uint32 irq_flag = 0;
	atbm_timer_lock(irq_flag);
	ATBM_CANCLE_TIMER_FROM_LIST(&atbm_timeout_pennding_list,handler,eloop_data,user_data,found);
	if(found == 0)	
		ATBM_CANCLE_TIMER_FROM_LIST(&atbm_timeout_ready_list,handler,eloop_data,user_data,found);
	atbm_timer_unlock(irq_flag);

	if(found == 0)
		wifi_printk(WIFI_DBG_MSG,"eloop_cancel_timeout: not found\n");
	return 0;
}
atbm_void wpa_timer_free(atbm_void)
{
	atbm_uint32 index;
	ATBM_FREE_TIMER_FORM_LIST(&atbm_timeout_pennding_list);
	ATBM_FREE_TIMER_FORM_LIST(&atbm_timeout_ready_list);
	for(index = 0;index<ELOOP_TIMER_TABLE_SIZE;index++){
		atbm_FreeTimer(&timer_table[index].timer); 
	}
}
int eloop_register_timeout(unsigned int secs, unsigned int msecs,
			   atbm_void (*handler)(atbm_void *eloop_ctx, atbm_void *timeout_ctx),
			   atbm_void *eloop_data, atbm_void *user_data)
{
	struct wpa_timer *timer_free = ATBM_NULL;
	atbm_uint8 start_timer = 1;
	atbm_int32 ret = 0;
	atbm_uint32 irq_flag = 0;
	if(ATBM_NULL == handler)
	{
		return 0;
	}
	
	atbm_timer_lock(irq_flag);
	if (!(atbm_list_empty(&atbm_timeout_free_list))){
		timer_free = atbm_list_first_entry(
			&atbm_timeout_free_list, struct wpa_timer, list);
		
		timer_free->data1 = eloop_data;
		timer_free->data2 = user_data;
		timer_free->fun = handler;
		timer_free->cancled = 0;
		if((secs==0)&&(msecs == 0)){
			atbm_list_move_tail(&timer_free->list,&atbm_timeout_ready_list);
			start_timer = 0;
		} 
		else {
			atbm_list_move_tail(&timer_free->list,&atbm_timeout_pennding_list);	
			start_timer = 1;
		}
	}else{
		ret = -1;
	}
	atbm_timer_unlock(irq_flag);
	
	wifi_printk(WIFI_WPA,"eloop_register_timeout:ret(%d),start_timer(%d)\n",ret,start_timer);
	if(ret == 0){
		if(start_timer == 0){			
			//ATBM_BUG_ON(atbm_wpa_event_wake != atbm_wpa_event_wake_bak);
			atbm_wpa_event_bh_wakeup();
		}
		else		
			atbm_StartTimer(&timer_free->timer,(/*ELOOP_TIMER_OUT*/1000*secs+msecs));
	}else{
		wifi_printk(WIFI_WPA,"eloop_register_timeout:err\n");
	}

	return ret;
}

static int atbmwifi_wpa_event_init(void)
{
//	atbm_uint8 index = 0;
//	atbm_uint32 irq_flag = 0;
	
	ATBM_WPA_EVENT_QUEUE_INIT();
	
	atbm_wpa_event_bh=atbm_createThread(atbmwifi_wpa_event_bh,(atbm_void*)ATBM_NULL,HIF_TASK_PRIO);
	if (!atbm_wpa_event_bh){
		wifi_printk(WIFI_IF,"eloop_thread Failed\n");
		return -1;
	}

	return 0;
}
atbm_uint32 atbmwifi_wpa_event_destory(atbm_void)
{
	/*Destory wpa_event list*/
	//ATBM_WAP_EVENT_QUEUE_DEINT();
	
	wpa_bh_term=1;
	atbm_os_wakeup_event(&atbm_wpa_event_wake);
	/*Destory wpa_wvent_bh*/
	atbm_stopThread(atbm_wpa_event_bh);
	/*Clear Timer*/
	wpa_timer_free();
	atbm_os_delete_waitevent(&atbm_wpa_event_wake);
	return 0;
}
static char *atbm_wpa_event_to_string(enum atbm_wpa_event_id event)
{
	switch(event){
		case WPA_EVENT__INIT:
			return "[INIT]";
		case WPA_EVENT__DEINIT:
			return "[DEINIT]";
		case WPA_EVENT__SUPPLICANT_SCAN_END:
			return "[SCAN_END]";
		case WPA_EVENT__SUPPLICANT_START_CONNECT:
			return "[SUPPLICANT_START_CONNECT]";
		case WPA_EVENT__SUPPLICANT_AUTHEN:
			return "[SUPPLICANT_AUTHEN]";
		case WPA_EVENT__SUPPLICANT_ASSOCIAT:
			return "[SUPPLICANT_ASSOCIAT]";
		case WPA_EVENT__SUPPLICANT_ASSOCIATED:
			return "[SUPPLICANT_ASSOCIATED]";
		case WPA_EVENT__SUPPLICANT_CONNECTED:
			return "[SUPPLICANT_CONNECTED]";
		case WPA_EVENT__SUPPLICANT_DEAUTHEN:
			return "[SUPPLICANT_DEAUTHEN]";
		case WPA_EVENT__SUPPLICANT_CONNECT_FAIL:
			return "[SUPPLICANT_CONNECT_FAIL]";
		case WPA_EVENT__HOSTAPD_START:
			return "[HOSTAPD_START]";
		case WPA_EVENT__HOSTAPD_STA_ASSOCIATED:
			return "[HOSTAPD_STA_ASSOCIATED]";
		case WPA_EVENT__HOSTAPD_STA_HANDSHAKE_START:
			return "[HOSTAPD_STA_HANDSHAKE_START]";
		case WPA_EVENT__HOSTAPD_STA_HANDSHAKE:
			return "[HOSTAPD_STA_HANDSHAKE]";
		case WPA_EVENT__HOSTAPD_STA_DEAUTHENED:
			return "[HOSTAPD_STA_DEAUTHENED]";
		case WPA_EVENT__RX_PKG:
			return "[RX_PKG]";
		case WPA_EVENT__EAP_TX_RESP:
			return "[EAP_TX_RESP]";
		case WPA_EVENT__EAP_RX:
			return "[EAP_RX]";
		case WPA_EVENT__EAP_TX_STATUS:
			return "[EAP_TX_STATUS]";
		case WPA_EVENT__SMARTCONFIG_SUCCESS:
			return "[SMARTCONFIG_SUCCESS]";
		default:
			return "[NULL]";
	}
}
static void atbm_wpa_event_process(struct atbm_wpa_event *event)
{
	char *event_string;
	event_string = atbm_wpa_event_to_string(event->event);
	//wifi_printk(WIFI_WPA,"event_process%s\n",event_string);
	switch(event->event){
		
		case WPA_EVENT__INIT:
		{
			struct atbmwifi_vif *start_priv = (struct atbmwifi_vif *)event->data1;
			enum atbm_nl80211_iftype start_type = (enum atbm_nl80211_iftype)event->data2;
			if(start_priv == NULL){
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			atbmwifi_wpa_event_mode_init(start_priv,start_type);
			break;
		}
		
		case WPA_EVENT__DEINIT:
		{
			struct atbmwifi_vif *stop_priv = (struct atbmwifi_vif *)event->data1;
			enum atbm_nl80211_iftype stop_type = (enum atbm_nl80211_iftype)event->data2;
			if(stop_priv == NULL){
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			atbmwifi_wpa_event_mode_deinit(stop_priv,stop_type);
			break;
		}
		/*
		*process supplicant event
		*/
		case WPA_EVENT__SUPPLICANT_SCAN_END:
		{
			struct atbmwifi_common *hw_priv = (struct atbmwifi_common *)event->data1;
			atbm_uint32 scan_status = (atbm_uint32)event->data2;
			
			if(hw_priv == ATBM_NULL){
				wifi_printk(WIFI_WPA,"event_process%s hw_priv err\n",event_string);
				break;
			}
			atbmwifi_wpa_event_process_scan_end(hw_priv,scan_status);
			break;
		}
		case WPA_EVENT__SUPPLICANT_START_CONNECT:
		{
			
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;
			struct atbmwifi_cfg* config = (struct atbmwifi_cfg*)event->data2;

			if((priv==ATBM_NULL) || (config==ATBM_NULL)){
				
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			if(!atbmwifi_is_sta_mode(priv->iftype))
			{				
				wifi_printk(WIFI_WPA,"event_process%s not sta mode\n",event_string);
				break;
			}
			atbmwifi_wpa_event_associte_ap(priv,config);
			break;
		}
		case WPA_EVENT__SUPPLICANT_AUTHEN:
		{			
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;

			if(priv==ATBM_NULL){
				
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			
			if(!atbmwifi_is_sta_mode(priv->iftype))
			{				
				wifi_printk(WIFI_WPA,"event_process%s not sta mode\n",event_string);
				break;
			}
			atbmwifi_wpa_event_authen(priv);
			break;
		}
		case WPA_EVENT__SUPPLICANT_ASSOCIAT:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;

			if(priv==ATBM_NULL){
				
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			
			if(!atbmwifi_is_sta_mode(priv->iftype))
			{				
				wifi_printk(WIFI_WPA,"event_process%s not sta mode\n",event_string);
				break;
			}
			atbmwifi_wpa_event_assciate(priv);
			break;
		}
		case WPA_EVENT__SUPPLICANT_ASSOCIATED:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;
			atbm_uint16 linkid = *(atbm_uint16*)event->data2;
			if(priv==ATBM_NULL){
				
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			
			if(!atbmwifi_is_sta_mode(priv->iftype))
			{				
				wifi_printk(WIFI_WPA,"event_process%s not sta mode\n",event_string);
				break;
			}
			atbmwifi_wpa_event_assocated(priv,linkid);
			break;
		}
		case WPA_EVENT__SUPPLICANT_CONNECTED:
			break;
		case WPA_EVENT__SUPPLICANT_DEAUTHEN:
		{
			break;
		}
		case WPA_EVENT__SUPPLICANT_CONNECT_FAIL:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;

			if(priv==ATBM_NULL){
				
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			
			if(!atbmwifi_is_sta_mode(priv->iftype))
			{				
				wifi_printk(WIFI_WPA,"event_process%s not sta mode\n",event_string);
				break;
			}
			atbmwifi_wpa_event_connect_fail(priv);
			break;
		}
		/*
		*process hostapd event
		*/
		case WPA_EVENT__HOSTAPD_START:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;
			struct atbmwifi_cfg* config = (struct atbmwifi_cfg*)event->data2;

			if((priv==ATBM_NULL) || (config==ATBM_NULL)){
				
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			if(!atbmwifi_is_ap_mode(priv->iftype))
			{				
				wifi_printk(WIFI_WPA,"event_process%s not ap mode\n",event_string);
				break;
			}
			atbmwifi_wpa_event_start_ap(priv,config);
			break;
		}
		case WPA_EVENT__HOSTAPD_STA_ASSOCIATED:
			break;
		case WPA_EVENT__HOSTAPD_STA_HANDSHAKE:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;
			struct hostapd_sta_info *sta = (struct hostapd_sta_info*)event->data2;

			if((priv == ATBM_NULL)||(sta==ATBM_NULL)){				
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			if(!atbmwifi_is_ap_mode(priv->iftype))
			{				
				wifi_printk(WIFI_WPA,"event_process%s not ap mode\n",event_string);
				break;
			}
			hostapd_run(priv,sta);
			break;
		}
		case WPA_EVENT__HOSTAPD_STA_HANDSHAKE_START:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;
			struct hostapd_sta_info *sta = (struct hostapd_sta_info *)event->data2;
			struct atbmwifi_wpa_state_machine *sm;

			if((priv == ATBM_NULL)||(sta==ATBM_NULL)){				
				wifi_printk(WIFI_WPA,"event_process%s err\n",event_string);
				break;
			}
			if(!atbmwifi_is_ap_mode(priv->iftype))
			{				
				wifi_printk(WIFI_WPA,"event_process%s not ap mode\n",event_string);
				break;
			}
			sm = sta->atbmwifi_wpa_sm;
			
			hostapd_eapol_init(priv,sm);
			sm->wpa_ptk_state = ATBM_WPA_PTK_PTKSTART;
			
			eloop_register_timeout(0,1,hostapd_4_way_handshake_start,(atbm_void *)priv,sta);

			break;
		}
		case WPA_EVENT__HOSTAPD_STA_DEAUTHENED:
			break;
		/*
		*process mgmt and eap pkg
		*/
		case WPA_EVENT__RX_PKG:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;
			struct atbm_buff *skb = (struct atbm_buff *)event->data2;
			atbm_int32 needfree = 1;
			
			if(priv == NULL){
				wifi_printk(WIFI_WPA,"event_process%s priv err\n",event_string);
				break;
			}
			if(skb == NULL){
				wifi_printk(WIFI_WPA,"event_process%s skb err\n",event_string);
				break;
			}

			needfree = atbmwifi_ieee80211_rx(priv,skb);
			if(needfree){
				atbm_dev_kfree_skb(skb);	
			}
			break;
		}
		/*
		*process eap messege
		*/
		case WPA_EVENT__EAP_TX_RESP:
			break;
		case WPA_EVENT__EAP_RX:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;
			struct atbm_buff *skb = (struct atbm_buff *)event->data2;
			struct atbmwifi_ieee8023_hdr *hdr;
			if(priv == NULL){
				wifi_printk(WIFI_WPA,"event_process%s priv err\n",event_string);
				break;
			}

			if(skb == NULL){
				wifi_printk(WIFI_WPA,"event_process%s skb err\n",event_string);
				break;
			}

			hdr = (struct atbmwifi_ieee8023_hdr *)ATBM_OS_SKB_DATA(skb);
			
			if(atbmwifi_is_ap_mode(priv->iftype))
			{
				ieee802_1x_receive(priv,
									(const atbm_uint8*)&(hdr->h_source),
									((const atbm_uint8*)ATBM_OS_SKB_DATA(skb)) + 14,
									ATBM_OS_SKB_LEN(skb) - 14);
			
			}
			else
			{	
				wpa_supplicant_rx_eapol(priv, 
				(const atbm_uint8*)&(hdr->h_source) ,
				((atbm_uint8*)ATBM_OS_SKB_DATA(skb)) + 14, 
				ATBM_OS_SKB_LEN(skb) - 14);		
			}
			//eapol need free
			atbm_dev_kfree_skb(skb);
			break;
		}
		case WPA_EVENT__EAP_TX_STATUS:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;

			if(priv == NULL){
				wifi_printk(WIFI_WPA,"event_process%s priv err\n",event_string);
				break;
			}

			if(atbmwifi_is_sta_mode(priv->iftype)){
				wpa_supplicant_rx_eap_status(priv);
			}
#ifdef CONFIG_WPS
			else{
				struct hostapd_data *hostapd = (struct hostapd_data *)(priv->appdata);
				atbmwifi_ieee80211_tx_mgmt_deauth(priv,hostapd->wpsdata->mac_addr_e,priv->bssid,ATBM_WLAN_REASON_DEAUTH_LEAVING);
				eap_wsc_dinit(priv);
#ifdef CONFIG_P2P
				if(priv->p2p_ap){
					atbm_p2p_wps_sucess(priv, 1);
				}
#endif
			}
#endif
			break;
		}
		case WPA_EVENT__SMARTCONFIG_SUCCESS:
		{
			struct atbmwifi_vif *priv = (struct atbmwifi_vif *)event->data1;
			struct atbmwifi_cfg *hmac_cfg_p = (struct atbmwifi_cfg *)event->data2;
			smartconfig_success_notify(priv, hmac_cfg_p);
		}
		default:
			return;
	}
}
static void atbmwifi_wpa_event_poll(void)
{		
	atbm_uint32 irq_flag = 0;
	atbm_wpa_event_lock(irq_flag);
	while(!atbm_list_empty(&atbm_wpa_event_pending_list)){
		struct atbm_wpa_event *event_pendig = ATBM_NULL;
		atbm_wpa_event_in_running();
		ATBM_WPA_EVENT_PROCESS_QUEUED_EV(event_pendig,irq_flag);
	}
	atbm_wpa_event_out_running();
	atbm_wpa_event_unlock(irq_flag);
}

static void atbmwifi_wpa_event_bh(atbm_void *arg)
{		
	wpa_bh_term = 0;

	while(1){
		atbm_os_wait_event_timeout(&atbm_wpa_event_wake,100*HZ);

		atbmwifi_wpa_event_poll();
		eloop_timeout_func_poll();
	}
	atbm_ThreadStopEvent(atbm_wpa_event_bh);
}

atbm_int32 atbmwifi_wpa_event_queue(atbm_void *user_data1,atbm_void *user_data2,atbm_void *user_data3,
	enum atbm_wpa_event_id event_id,atbm_uint8 wait_ack)
{
	atbm_int32 ret = 0;
//	atbm_uint32 irq_flag = 0;
	struct atbm_wpa_event *event_free = ATBM_NULL;
	if(event_id>=WPA_EVENT__MAX){
		wifi_printk(WIFI_DBG_ANY,"event err\n");
		return -1;
	}
	ATBM_WPA_EVENT_ADD_EVENT_TO_QUEUE(event_free,user_data1,user_data2,user_data3,event_id,wait_ack,ret);
	if(ret == -1){
		iot_printf("atbm_wpa_event_free_list table is empty\n");
	}
	else {
		atbm_wpa_event_bh_wakeup();
		atbm_wpa_wait_ack(event_free);
	}
	return ret;
}
int eloop_register_task(atbm_void *user_data1,atbm_void *user_data2)
{		
	return atbmwifi_wpa_event_queue(user_data1,user_data2,ATBM_NULL,WPA_EVENT__HOSTAPD_STA_HANDSHAKE,0);
}
static int __wpa_timer_init(atbm_void)
{
	atbm_int32 ret = 0;
	
	wifi_printk(WIFI_ALWAYS,"__wpa_timer_init\n");
	
	ret=atbmwifi_wpa_timer_int();
	if(ret != 0){
		wifi_printk(WIFI_DBG_ANY,"atbmwifi_wpa_timer_int err\n");
		return ret;
	}
	ret = atbmwifi_wpa_event_init();

	if(ret != 0){
		wifi_printk(WIFI_DBG_ANY,"atbmwifi_wpa_event_init err\n");

		return ret;
	}

	return 0;
}
int wpa_timer_init(atbm_void)
{
	return __wpa_timer_init();
}
