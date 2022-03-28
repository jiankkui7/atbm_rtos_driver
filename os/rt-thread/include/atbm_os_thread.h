#ifndef ATBM_OS_THREAD_H
#define ATBM_OS_THREAD_H
#include <rtdef.h>
#include <rtthread.h>
#include "atbm_type.h"

#define WIFI_TASK_TICK 5
#define WIFI_TASK_NUM  8
#define WIFI_TASK_NAME_LEN 16
#define WIFI_THREAD_PRIO_START  11
#define BH_TASK_PRIO     	WIFI_THREAD_PRIO_START	 /** High **/
#define ELOOP_TASK_PRIO     (WIFI_THREAD_PRIO_START + 1)
#define WORK_TASK_PRIO     (WIFI_THREAD_PRIO_START + 2)
#define HIF_TASK_PRIO     (WIFI_THREAD_PRIO_START + 3)
#define MAIL_BOX_BH_PRIO     (WIFI_THREAD_PRIO_START -1)

typedef void *os_thread_arg_t;
typedef void (*os_pthread) (os_thread_arg_t argument); 
typedef struct rt_thread *pAtbm_thread_t;
typedef struct os_thread_def  {
	const char name[WIFI_TASK_NAME_LEN];
	os_pthread entry;
	atbm_uint32 stack_size;
	atbm_uint8 priority;
	atbm_uint32 tick;
} AtbmThreadDef_t;

pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio);
int atbm_stopThread(pAtbm_thread_t thread_id);
int atbm_ThreadStopEvent(pAtbm_thread_t thread_id);
#endif /* ATBM_OS_THREAD_H */
