#ifndef ATBM_OS_MUTEX_H
#define ATBM_OS_MUTEX_H
#include "atbm_type.h"

#include "usr_cfg.h"
#define atbm_mutex  mutex_t
#define atbm_os_wait_queue_head_t wait_queue_head_t

#define atbm_os_init_waitevent(x) init_waitqueue_head(x) 
#define atbm_os_delete_waitevent(x) //Need Fixed
#define atbm_os_wait_event_timeout(x,y) wait_event_interruptible_timeout(*(wait_queue_head_t*)x,0,y)
#define atbm_os_wakeup_event(x) wake_up_interruptible(*(wait_queue_head_t*)x)
/*mutex*/
#define atbm_os_mutexLockInit(x) *(x)=mutex_init(__FUNCTION__)
#define atbm_os_DeleteMutex(x) mutex_destory(*(mutex_t*)x)
#define atbm_os_mutexLock(x,a) mutex_lock(*(mutex_t*)x)
#define atbm_os_mutexUnLock(x) mutex_unlock(*(mutex_t*)x)
#endif /* ATBM_OS_MUTEX_H */

