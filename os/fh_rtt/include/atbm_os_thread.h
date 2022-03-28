#ifndef ATBM_OS_THREAD_H
#define ATBM_OS_THREAD_H

#define WIFI_TASK_TICK 5
#define WIFI_TASK_NUM  10
#define WIFI_TASK_NAME_LEN 16
#define WIFI_THREAD_PRIO_START 8
#define BH_TASK_PRIO (WIFI_THREAD_PRIO_START)	 /** High **/
#define ELOOP_TASK_PRIO (WIFI_THREAD_PRIO_START + 3)
#define WORK_TASK_PRIO (WIFI_THREAD_PRIO_START + 4)
#define HIF_TASK_PRIO (WIFI_THREAD_PRIO_START + 5)
#define TXURB_TASK_PRIO (WIFI_THREAD_PRIO_START + 1)
#define RXURB_TASK_PRIO (WIFI_THREAD_PRIO_START + 2)
#define TX_BH_TASK_PRIO (WIFI_THREAD_PRIO_START + 1)
#define RX_BH_TASK_PRIO (WIFI_THREAD_PRIO_START + 2)

#if ATBM_SUPPORT_SMARTCONFIG
#define SMARTCONFIG_MONNITOR_TASK_PRIO (WIFI_THREAD_PRIO_START + 4)
#endif
#define MAIL_BOX_BH_PRIO     (WIFI_THREAD_PRIO_START -1)

typedef struct rt_thread *pAtbm_thread_t;

//typedef atbm_void * pAtbm_thread_t ;

/*priotry */
enum  ATBM_THREAD_PRIO
{
	//WORK_TASK_PRIO,
	//BH_TASK_PRIO,
	//ELOOP_TASK_PRIO,
	HIF_TASK_PRIO1,
};

pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio);
int atbm_stopThread(pAtbm_thread_t thread_id);
int atbm_ThreadStopEvent(pAtbm_thread_t thread_id);


#endif /* ATBM_OS_THREAD_H */
