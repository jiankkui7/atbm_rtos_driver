#ifndef ATBM_OS_THREAD_H
#define ATBM_OS_THREAD_H
#if 0
#include "atbm_type.h"
atbm_uint32 atbm_os_CreateTask(atbm_void (*taskproc)(atbm_void *param), atbm_thread_t *task_cfg, atbm_void *param);
ATBM_BOOL atbm_os_setTaskName(atbm_uint8 ubNewPriority, atbm_uint8 *pTaskName);
atbm_void atbm_os_startTask(atbm_void);
atbm_uint8 atbm_os_changeTaskPri(atbm_uint8 ubold_pri, atbm_uint8 ubnew_pri);
atbm_uint8 atbm_os_delTask(atbm_uint8 taskid);
atbm_uint8 atbm_os_suspendTask(atbm_uint8 taskid);
atbm_uint8 atbm_os_resumeTask(atbm_uint8 taskid);
atbm_void atbm_os_StartTask(atbm_void);
#endif

#define WIFI_TASK_TICK 5
#define WIFI_TASK_NUM  10
#define WIFI_TASK_NAME_LEN 16
#define WIFI_THREAD_PRIO_START 8
#define BH_TASK_PRIO (WIFI_THREAD_PRIO_START + 1)	 /** High **/
#define ELOOP_TASK_PRIO     (WIFI_THREAD_PRIO_START + 2)
#define WORK_TASK_PRIO     (WIFI_THREAD_PRIO_START + 3)
#define HIF_TASK_PRIO     (WIFI_THREAD_PRIO_START + 4)
#define TXURB_TASK_PRIO     	(WIFI_THREAD_PRIO_START)
#define RXURB_TASK_PRIO     	(WIFI_THREAD_PRIO_START + 5)
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
atbm_uint32 atbm_getThreadStackFreesize();


#endif /* ATBM_OS_THREAD_H */
