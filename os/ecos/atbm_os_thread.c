
#include "atbm_hal.h"

#include "atbm_os_thread.h"
//#include "os_api.h"
#include <cyg/kernel/kapi.h>

TASK_THREAD thread_arry[MAX_TASK_NUM]={0};
atbm_uint8	task_cnt = 0;


void atbm_thead_init()
{
	task_cnt = 0;
	memset(thread_arry,0,sizeof(TASK_THREAD)*MAX_TASK_NUM);
}
/*
OS: eCos
Syntax: void
		cyg_thread_create(
			cyg_addrword_t sched_info,
			cyg_thread_entry_t *entry,
			cyg_addrword_t entry_data,
			char *name,
			void *stack_base,
			cyg_ucount32 stack_size,
			cyg_handle_t *handle,
			cyg_thread *thread
		);
		
Parameters/Context:
		sched_info！scheduler-specific information. For most schedulers, this is the priority value for the thread.
		entry！routine that begins execution of the thread.
		entry_data！data value passed to the thread entry routine.
		name！string name of the thread.
		stack_base！base address of the stack for the thread.
		stack_size！size, in bytes, of the stack for the thread.
		handle！returned handle to the thread.
		thread！thread information is stored in the thread memory object pointed to by this parameter.
		
Description: 
		Creates a thread in a suspended state. 
		It is very important to note that a thread will not run until
		the cyg_thread_resume call is made for the thread and the scheduler is started.
*/
pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{
	atbm_uint32 task_prio =7;
	atbm_uint32 t_id;
	
	//Find an un-used ID
	for ( t_id=0; t_id < MAX_TASK_NUM; t_id++ )
	{
		if ( !thread_arry[t_id].used )
		{
			thread_arry[t_id].used = 1;
			break;
		}
	}

	//Clear task name buffer
	atbm_memset(&thread_arry[t_id].task_name[0], 0, TASK_NAME_LEN);

	//Task count num start from 1
	task_cnt++;

	//Build task name according to task count
	sprintf(&thread_arry[t_id].task_name[0], "ecos_wifi_thread_%d", task_cnt);

	//Convert task priority
	if(prio == HIF_TASK_PRIO)
		task_prio = 1;
	if(prio == WORK_TASK_PRIO)
		task_prio = 7;

	//cyg_handle_t	threadID = 0;
	//cyg_thread		thread_obj = {0};

    cyg_thread_create( (cyg_addrword_t)task_prio,							// priority
						task,                     							// task func 
						(cyg_addrword_t) p_arg,   							// parameter addr
		    			(atbm_void *) &thread_arry[t_id].task_name[0],           // task name
		    			(atbm_void *) &thread_arry[t_id].task_stack[0],			// stack
		    			TASK_STACK_SIZE,									// stack size
		    			&thread_arry[t_id].threadID, 
		    			&thread_arry[t_id].thread_obj);

	if(thread_arry[t_id].threadID != ATBM_NULL)
	{
	
#ifndef KTHREAD_SUPPORT
		cyg_semaphore_init(&thread_arry[t_id].taskComplete.wait, 0);
		thread_arry[t_id].taskComplete.done = 0;
#endif

		//Let the thread run when the scheduler starts.
		cyg_thread_resume(thread_arry[t_id].threadID);
		wifi_printk(WIFI_DBG_MSG, "careae task(%s) success!\n", &thread_arry[t_id].task_name[0]);
    }
	else
	{
		wifi_printk(WIFI_DBG_ERROR, "create task(%s) failed!\n", &thread_arry[t_id].task_name[0]);
	}
	iot_printf("createThread %d task %p\n",t_id,task);

	return t_id;
}

int atbm_wakeThread()
{
	wifi_printk(WIFI_DBG_MSG, "atbm_wakeThread() not support.\n");
}

int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	atbm_uint32 t_id=(atbm_uint32)thread_id;
	
	iot_printf("ThreadStopEvent %d\n",t_id);
	

	thread_arry[t_id].taskComplete.done = 1;
	cyg_semaphore_post(&thread_arry[t_id].taskComplete.wait);

//	cyg_semaphore_post((cyg_sem_t *)x)

}
/*
OS: eCos
Syntax: cyg_bool_t
	cyg_thread_delete(cyg_handle_t thread);
	
Parameters: Thread
Context: thread！handle to the thread.
	Description: Kills a thread, using the cyg_thread_kill function, and removes it from the scheduler.
	A value of false is returned if the thread cannot be killed. After this call, memory (the
	thread handle, stack and thread object) created for the thread can be reused. Resources
	allocated by the thread are not freed by calling this function. In addition, synchronization
	objects owned by the thread are not unlocked; this is the responsibility of the programmer.
*/
int atbm_stopThread(pAtbm_thread_t thread_id)
{	
	//thread_exit(thread_id);
	atbm_uint32 t_id=(atbm_uint32)thread_id;
	
	//Find correct thread id in the pool
	
	iot_printf("stopThread %d\n",t_id);
	thread_arry[t_id].used = 0;


#ifndef KTHREAD_SUPPORT

	while (1) 
	{
		cyg_semaphore_wait(&thread_arry[t_id].taskComplete.wait);
		if (thread_arry[t_id].taskComplete.done == 1)
		{
			break;
		}
		else
		{
			wifi_printk(WIFI_DBG_ERROR, "Killed task(%s) \n",&thread_arry[t_id].task_name[0]); 
		}
	}

	cyg_semaphore_destroy(&thread_arry[t_id].taskComplete.wait);
#endif

	cyg_thread_delete(thread_arry[t_id].threadID);
	wifi_printk(WIFI_DBG_MSG, "careae task(%s) success!\n", &thread_arry[t_id].task_name[0]);

	return 0;
}


