#include "atbm_os_thread.h"
#include "atbm_hal.h" 
#include "usr_cfg.h"
atbm_uint8	task_cnt = 0;
extern  int thread_create(void(*task)(void *p_arg), void *p_arg, unsigned int prio, unsigned int *pbos, unsigned int stk_size, char *name);
extern 	int thread_exit(int thread_id);
pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{
	atbm_uint32 task_prio =prio;
	pAtbm_thread_t threadID;
  threadID=thread_create((atbm_void(*)(atbm_void*))task,p_arg,task_prio,ATBM_NULL,4096,"atbm_sdio_bh");
	return threadID;
}

pAtbm_thread_t atbm_wakeThread()
{
	wifi_printk(WIFI_DBG_MSG, "atbm_wakeThread() not support.\n");
	return 0;
}

pAtbm_thread_t atbm_stopThread(pAtbm_thread_t thread_id)
{	
	thread_exit(thread_id);
	wifi_printk(WIFI_DBG_MSG, "stopThread (%d) success!\n",thread_id);

	return 0;
}

int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	//Not used
	return 0;
}

