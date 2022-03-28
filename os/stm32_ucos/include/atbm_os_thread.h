#ifndef ATBM_OS_THREAD_H
#define ATBM_OS_THREAD_H
#include "atbm_type.h"
typedef atbm_uint32 pAtbm_thread_t;
/*priotry */
enum  ATBM_THREAD_PRIO{
	WORK_TASK_PRIO,
	BH_TASK_PRIO,
	ELOOP_TASK_PRIO,
	HIF_TASK_PRIO,
};
#define TASK_STACK_SIZE		4*1024 //stack size is 128K
pAtbm_thread_t atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio);
pAtbm_thread_t atbm_stopThread(pAtbm_thread_t thread_id);
int atbm_ThreadStopEvent(pAtbm_thread_t thread_id);

#endif /* ATBM_OS_THREAD_H */
