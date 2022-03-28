
#include "atbm_hal.h"

#include "atbm_os_thread.h"
#include "os_api.h"


atbm_void * atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{
	unsigned int task_prio =7;
	if(prio == HIF_TASK_PRIO)
		task_prio = 1;
	if(prio == WORK_TASK_PRIO)
		task_prio = 7;
	return thread_create(task, p_arg, task_prio, ATBM_NULL, 4096,"rtosthread");
}
int atbm_wakeThread()
{

}
int atbm_stopThread(atbm_void * thread_id)
{	
	thread_exit(thread_id);
}
int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	//Not used
	return 0;
}


