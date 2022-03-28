#include "atbm_hal.h"
#include "atbm_os_thread.h"
//#include "drv_api.h"
//#include "akos_api.h"
#include "task.h"
//#include "xr_sys_types.h"

#include "api.h"
typedef TaskHandle_t		T_hTask;


#define MAX_WIFI_TASK 6
#define ATBM_BH_PRO_BASE       (90)
#define WIFI_GENERAL_STACK_SIZE 1024*6
struct Wifi_Thead_Arg{
	int valid;
	int taskid;
	atbm_void *pstack_addr;  	
	T_hTask pTask;
};
struct Wifi_Thead_Arg  Wifi_Thead[MAX_WIFI_TASK]={0};
/*
enum  ATBM_THREAD_PRIO{
	BH_TASK_PRIO,
	ELOOP_TASK_PRIO,
	WORK_TASK_PRIO,
	HIF_TASK_PRIO,
};
*/
char *atbm_bh_name[MAX_WIFI_TASK] = 
{
	"work",
	"bhtask",
	"eloop",
	"hif",
	"ATBM_NULL",
	"ATBM_NULL",
};
#if (PLATFORM==JIANRONG_RTOS_3268)
#define RTOS	"rtosthread"
#define RTOS1	"rtosthread1"
#define RTOS2	"rtosthread2"
#define RTOS3	"rtosthread3"
#define RTOS4	"rtosthread4"
//static int b_first_init =0;
atbm_void * atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{
	unsigned int task_prio =7;
	if(prio == HIF_TASK_PRIO)
		task_prio = 1;
	if(prio == WORK_TASK_PRIO)
		task_prio = 7;

	if(prio==WORK_TASK_PRIO)
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS1);
	}
	else if(prio==BH_TASK_PRIO)
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS2);
	}
	else if(prio==ELOOP_TASK_PRIO)
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS3);
	}
	else if(prio==HIF_TASK_PRIO)
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS4);
	}
	else
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS);
	}
	
}
#else

#define RTOS	"rtosthread"
#define RTOS1	"rtosthread1"
#define RTOS2	"rtosthread2"
#define RTOS3	"rtosthread3"
#define RTOS4	"rtosthread4"



atbm_void * atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{
	unsigned int task_prio =prio;
	if(prio==WORK_TASK_PRIO)
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS1);
	}
	else if(prio==BH_TASK_PRIO)
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS2);
	}
	else if(prio==ELOOP_TASK_PRIO)
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS3);
	}
	else if(prio==HIF_TASK_PRIO)
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS4);
	}
	else
	{
		return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS);
	}



	return thread_create(task,p_arg,task_prio,ATBM_NULL,8192,RTOS);

#if 0

unsigned int ID = prio;
struct Wifi_Thead_Arg *pTheadArg;
T_hTask handle;
//if(b_first_init==0){
	//osl_ext_task_init();
	//b_first_init=1;
//}

if(ID >= MAX_WIFI_TASK){
	wifi_printk(WIFI_ALWAYS,"atbm_createThread ID=%d error!!\n",ID);
	return ATBM_NULL;
}

pTheadArg = &Wifi_Thead[ID];

if(pTheadArg->valid == 1){
	wifi_printk(WIFI_ALWAYS,"atbm_createThread valid =%d error!!\n",ID);
	return ATBM_NULL;
}

pTheadArg->pstack_addr = (void*)atbm_kzalloc(WIFI_GENERAL_STACK_SIZE,GFP_KERNEL);

if(pTheadArg->pstack_addr == ATBM_NULL){
	wifi_printk(WIFI_ALWAYS,"atbm_createThread pstack_addr =%d error!!\n",ID);
	return ATBM_NULL;
}

wifi_printk(WIFI_ALWAYS,"atbm_createThread name(%s),stack(%p)\n",atbm_bh_name[ID],pTheadArg->pstack_addr);
handle = AK_Create_Task(task,atbm_bh_name[ID],(unsigned long)p_arg,p_arg,
	pTheadArg->pstack_addr,WIFI_GENERAL_STACK_SIZE,ATBM_BH_PRO_BASE+prio,0,AK_PREEMPT,AK_START);

if (AK_IS_INVALIDHANDLE(handle)){
	wifi_printk(WIFI_ALWAYS,"atbm_createThread handle =%d error!!\n",ID);
	atbm_kfree(pTheadArg->pstack_addr);
	return ATBM_NULL;
}

pTheadArg->valid = 1;
pTheadArg->taskid = prio;

pTheadArg->pTask = handle;

return (atbm_void *)(ID+1);



#endif
	
}

#endif

int atbm_stopThread(atbm_void * thread_id)
{	
	thread_exit(thread_id);
	return 0;
}
int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	//Not used
	return 0;
}

