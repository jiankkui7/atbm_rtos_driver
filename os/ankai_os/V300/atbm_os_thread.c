#include "atbm_hal.h"
#include "atbm_os_thread.h"
#include "drv_api.h"
#include "akos_api.h"
#include "os_malloc.h"

#include "akos_api.h"


#define MAX_WIFI_TASK 6
#define ATBM_BH_PRO_BASE       (100)
#define WIFI_GENERAL_STACK_SIZE 1024*6
struct Wifi_Thead_Arg{
	int valid;
	int taskid;
	atbm_void *pstack_addr;  	
	T_hTask pTask;
	int prio;
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
#ifdef CONFIG_P2P
	"p2p_task",
#else
	"ATBM_NULL",
#endif
#if ATBM_SUPPORT_SMARTCONFIG
	"st",
#else
	"ATBM_NULL",
#endif
};
//static int b_first_init =0;
atbm_void * atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{
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
	pTheadArg->prio = ATBM_BH_PRO_BASE+prio;
	return (atbm_void *)(ID+1);
}


int atbm_stopThread(atbm_void * thread_id)
{	
	unsigned int ID = (unsigned int)thread_id;
	struct Wifi_Thead_Arg *pTheadArg;
	
	if((ID == 0)||(ID>MAX_WIFI_TASK)){
		wifi_printk(WIFI_ALWAYS,"atbm_stopThread ID=%d error!!\n",ID);
		return -1;
	}

	ID--;

	pTheadArg = &Wifi_Thead[ID];

	if(pTheadArg->valid == 0){
		wifi_printk(WIFI_ALWAYS,"atbm_stopThread valid =%d error!!\n",ID);
		return -1;
	}

	AK_Terminate_Task(pTheadArg->pTask);
	AK_Delete_Task(pTheadArg->pTask);

	pTheadArg->valid = 0;
	pTheadArg->taskid = 0;
	pTheadArg->pTask = -1;

	atbm_kfree(pTheadArg->pstack_addr);

	return 0;
}

int atbm_changeThreadPriority(int prio){
	int id;
	struct Wifi_Thead_Arg *pTheadArg;
	for(id = 0; id < MAX_WIFI_TASK; id++){
		pTheadArg = &Wifi_Thead[id];
		if((id + prio) == pTheadArg->prio)
			return 0;
		if(pTheadArg->valid == 1){
			pTheadArg->prio = prio + id;
			AK_Change_Priority(pTheadArg->pTask, pTheadArg->prio);
		}
	}
}

int atbm_IncThreadPriority(int prio){
	int prio_to_set;
	struct Wifi_Thead_Arg *pTheadArg = &Wifi_Thead[0];

	prio_to_set = pTheadArg->prio + prio;
	if(prio_to_set < HMAC_MIN_THREAD_PRIO || prio_to_set > HMAC_MAX_THREAD_PRIO)
		return 0;
	return atbm_changeThreadPriority(pTheadArg->prio + prio);
}

atbm_uint32 atbm_getThreadStackFreesize(){
	/*not the real free stack size, only check whether stack overflow*/
	return (atbm_uint32)AK_Check_Task_Stack();
}

int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	//Not used
	return 0;
}

