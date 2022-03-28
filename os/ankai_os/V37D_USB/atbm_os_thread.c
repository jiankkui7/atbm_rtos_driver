#include "atbm_hal.h"
#include "atbm_os_thread.h"
#include "drv_module.h"
#include "akos_api.h"
#include "rtdef.h"

typedef void *os_thread_arg_t;
typedef void (*os_pthread) (os_thread_arg_t argument); 
#define WIFI_TASK_TICK 5
#define WIFI_TASK_NAME_LEN 16
#define WIFI_TASK_NUM  8
typedef struct os_thread_def  {
	const char name[WIFI_TASK_NAME_LEN];
	os_pthread entry;
	atbm_uint32 stack_size;
	atbm_uint8 priority;
	atbm_uint32 tick;
} AtbmThreadDef_t;

AtbmThreadDef_t ATBMTHREAD[WIFI_TASK_NUM]={0};
static atbm_uint32 TaskNum=0;


#define MAX_WIFI_TASK 6
#define ATBM_BH_PRO_BASE       (10)
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
#if ATBM_SUPPORT_SMARTCONFIG
	"smartconfig",
#endif
	"ATBM_NULL",
	"ATBM_NULL",
};
//static int b_first_init =0;
pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{
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
	
	handle = rt_thread_create(atbm_bh_name[ID], task, p_arg, WIFI_GENERAL_STACK_SIZE, ATBM_BH_PRO_BASE+prio, ATBMTHREAD[TaskNum].tick);
	if (AK_IS_INVALIDHANDLE(handle)){
		wifi_printk(WIFI_ALWAYS,"atbm_createThread handle =%d error!!\n",ID);
		atbm_kfree(pTheadArg->pstack_addr);
		return ATBM_NULL;
	}

	pTheadArg->valid = 1;
	pTheadArg->taskid = prio;

	pTheadArg->pTask = handle;

	return (atbm_void *)(ID+1);
#else
	pAtbm_thread_t thread;	
	do{
		if(prio==BH_TASK_PRIO){
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_BH",WIFI_TASK_NAME_LEN);
		}else if (prio==TXURB_TASK_PRIO){
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_TX_URB",WIFI_TASK_NAME_LEN);
		}else if (prio==RXURB_TASK_PRIO){
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_RX_URB",WIFI_TASK_NAME_LEN);
		}else if (prio==ELOOP_TASK_PRIO){
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_LOOP",WIFI_TASK_NAME_LEN);
		}else if (prio==WORK_TASK_PRIO){
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_WORK",WIFI_TASK_NAME_LEN);
		}else if(prio==HIF_TASK_PRIO){ 
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_HIF",WIFI_TASK_NAME_LEN);
#if ATBM_SUPPORT_SMARTCONFIG
		}else if(prio==SMARTCONFIG_MONNITOR_TASK_PRIO){ 
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_ST",WIFI_TASK_NAME_LEN);
#endif
		}else{
			atbm_memcpy(&ATBMTHREAD[TaskNum].name,"Atbm_MAIL",WIFI_TASK_NAME_LEN);
		}
		ATBMTHREAD[TaskNum].stack_size=8192;
		ATBMTHREAD[TaskNum].priority= (prio == RXURB_TASK_PRIO) ? TXURB_TASK_PRIO : prio;
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
#endif
}


int atbm_stopThread(pAtbm_thread_t thread_id)
{	
#if 0
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
#else
	atbm_uint32 result;
	result = rt_thread_delete(thread_id);
	if (result == RT_EOK)
		return OS_SUCCESS;
	else
		return OS_FAIL;

#endif
}

atbm_uint32 atbm_getThreadStackFreesize(){
	pAtbm_thread_t thread = rt_thread_self();
	return (thread->stack_addr + thread->stack_size - thread->sp);
}

int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	//Not used
	return 0;
}

