#include "atbm_hal.h"
#include "atbm_os_thread.h"
#include "rtkos_osl_ext.h"



static atbm_void emptyInit(atbm_void *userdata) {}
static atbm_void emptyParser(vm_msg_t *pMessage) {}
#define MAX_WIFI_TASK 6
static MsTaskId_e WifiTaskId[MAX_WIFI_TASK];
//static Msg_t *msg[MAX_WIFI_TASK] = NULL;

static MsTaskCreateArgs_t WifiTaskArgs[MAX_WIFI_TASK] =
{
    {CUS37_PRIO  , 0, ATBM_NULL, emptyInit, emptyParser, ATBM_NULL, &WifiTaskId[0] , ATBM_NULL, ATBM_FALSE},
    {CUS37_PRIO+1, 0, ATBM_NULL, emptyInit, emptyParser, ATBM_NULL, &WifiTaskId[1] , ATBM_NULL, ATBM_FALSE},
    {CUS37_PRIO+2, 0, ATBM_NULL, emptyInit, emptyParser, ATBM_NULL, &WifiTaskId[2] , ATBM_NULL, ATBM_FALSE},
    {CUS37_PRIO+3, 0, ATBM_NULL, emptyInit, emptyParser, ATBM_NULL, &WifiTaskId[3] , ATBM_NULL, ATBM_FALSE},
    {CUS38_PRIO+4, 0, ATBM_NULL, emptyInit, emptyParser, ATBM_NULL, &WifiTaskId[4] , ATBM_NULL, ATBM_FALSE},
    {CUS38_PRIO+5, 0, ATBM_NULL, emptyInit, emptyParser, ATBM_NULL, &WifiTaskId[5] , ATBM_NULL, ATBM_FALSE}
};
struct osl_ext_task_t WifiTaskArgs_ext[MAX_WIFI_TASK] = {0};



#define WIFI_GENERAL_STACK_SIZE 4096
struct Wifi_Thead_Arg{
	int valid;
	int taskid;
	atbm_void * pTask;
};
struct Wifi_Thead_Arg  Wifi_Thead[MAX_WIFI_TASK]={0};

//static int b_first_init =0;
atbm_void * atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{
	unsigned int ID = prio;
	//if(b_first_init==0){
		//osl_ext_task_init();
		//b_first_init=1;
	//}
	
	if(ID >= MAX_WIFI_TASK){
		wifi_printk(WIFI_ALWAYS,"atbm_createThread ID=%d error!!\n",ID);
		return ATBM_NULL;
	}

#if 0

	
	if(WifiTaskArgs[ID].AppliInit == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS,"atbm_createThread duplicant error!!\n");
		return ATBM_NULL;
	}
	if(Wifi_Thead[ID].valid){
		wifi_printk(WIFI_ALWAYS,"<WARNING>atbm_createThread duplicant !!\n");
	}
	WifiTaskArgs[ID].AppliInit = ATBM_NULL;
	WifiTaskArgs[ID].AppliParser = task;
	WifiTaskArgs[ID].StackSize = WIFI_GENERAL_STACK_SIZE;
	WifiTaskArgs[ID].pStackTop = (atbm_uint32*)MsAllocateMem(WifiTaskArgs[ID].StackSize);
	strcpy(WifiTaskArgs[ID].TaskName, "wifi");
	MsCreateTask(&WifiTaskArgs[ID]);
	
	//MsStartTask(WifiTaskId[ID]);
	msg = (Msg_t*)MsAllocateMem(sizeof(Msg_t));
	msg->Header.TypMsg = 1;
	msg->Header.MbxSrc = RTK_FIRST_CUSTOMER_MAILBOXID;
	msg->Header.MbxDst = WifiTaskId[ID];
	msg->Header.Length = sizeof(msg->Body.userdata);
	msg->Body.userdata = (atbm_uint32)p_arg;

	MsSend(WifiTaskId[ID], (atbm_void*)msg);

	Wifi_Thead[ID].pTask = &WifiTaskArgs[ID];
	Wifi_Thead[ID].taskid = ID;
	Wifi_Thead[ID].valid = 1;
	return &Wifi_Thead[ID];
#else
	osl_ext_task_create_ex("wifi",
							WIFI_GENERAL_STACK_SIZE,
							prio,
							0,
							task,
							p_arg,
							&WifiTaskArgs_ext[ID]);
	return &WifiTaskArgs_ext[ID];
#endif 
}


int atbm_stopThread(atbm_void * thread_id)
{	
#if 0
	struct Wifi_Thead_Arg * pWifi_Thead = thread_id;

	MsDeleteTask(WifiTaskId[pWifi_Thead->taskid]);
	MsReleaseMemory(pWifi_Thead->pTask);
	return 0;
#else
	osl_ext_task_delete(thread_id);
#endif 
}
int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	//Not used
	return 0;
}


