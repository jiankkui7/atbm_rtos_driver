#ifndef ATBM_OS_THREAD_H
#define ATBM_OS_THREAD_H

typedef cyg_handle_t * pAtbm_thread_t ;
/*priotry */
enum  ATBM_THREAD_PRIO{
	WORK_TASK_PRIO,
	BH_TASK_PRIO,
	ELOOP_TASK_PRIO,
	HIF_TASK_PRIO,
};
struct complete_s{
		int done;
		cyg_sem_t wait;
};

#define MAX_TASK_NUM		5 // max task number
#define TASK_NAME_LEN		32 // task name max length
#define TASK_STACK_SIZE		128*1024 //stack size is 128K
typedef struct __task_thread__
{
    atbm_uint8	task_name[TASK_NAME_LEN];
	atbm_int8	task_stack[TASK_STACK_SIZE];
	cyg_handle_t	threadID;
	cyg_thread		thread_obj;
#ifndef KTHREAD_SUPPORT
	struct complete_s taskComplete;
#endif
	ATBM_BOOL	used;
} TASK_THREAD;

pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio);
int atbm_stopThread(pAtbm_thread_t thread_id);
int atbm_ThreadStopEvent(pAtbm_thread_t thread_id);

#endif /* ATBM_OS_THREAD_H */
