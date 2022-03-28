#include "atbm_hal.h"
#include "atbm_os_thread.h"
AtbmThreadDef_t ATBMTHREAD[WIFI_TASK_NUM]={0};
static atbm_uint32 TaskNum=0;
pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{	
	pAtbm_thread_t thread;	
	do{
		if(prio==BH_TASK_PRIO){
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_BH",WIFI_TASK_NAME_LEN);
		}else if (prio==ELOOP_TASK_PRIO){
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_LOOP",WIFI_TASK_NAME_LEN);
		}else if (prio==WORK_TASK_PRIO){
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_WORK",WIFI_TASK_NAME_LEN);
		}else if(prio==HIF_TASK_PRIO){ 
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_HIF",WIFI_TASK_NAME_LEN);
		}else{
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_MAIL",WIFI_TASK_NAME_LEN);
		}
		ATBMTHREAD[TaskNum].stack_size=4096;
		ATBMTHREAD[TaskNum].priority=prio;
		ATBMTHREAD[TaskNum].tick=WIFI_TASK_TICK;
		ATBMTHREAD[TaskNum].entry=task;
	}while(0);
	wifi_printk(WIFI_ALWAYS,"NAME=%s\n",ATBMTHREAD[TaskNum].name);
	wifi_printk(WIFI_ALWAYS,"stack_size=%d\n",ATBMTHREAD[TaskNum].stack_size);
	wifi_printk(WIFI_ALWAYS,"priority=%d\n",ATBMTHREAD[TaskNum].priority);
	wifi_printk(WIFI_ALWAYS,"tick=%d\n",ATBMTHREAD[TaskNum].tick);
	
	thread = rt_thread_create(ATBMTHREAD[TaskNum].name, ATBMTHREAD[TaskNum].entry, p_arg, ATBMTHREAD[TaskNum].stack_size, ATBMTHREAD[TaskNum].priority, ATBMTHREAD[TaskNum].tick);
	 if (thread != RT_NULL)
		 rt_thread_startup(thread);
	 
	 TaskNum++;
	 return thread;
}
int atbm_stopThread(pAtbm_thread_t thread_id)
{	
    atbm_uint32 result;
    result = rt_thread_delete(thread_id);
    if (result == RT_EOK)
        return OS_SUCCESS;
    else
        return OS_FAIL;
}

int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	//Not used
	return 0;
}

