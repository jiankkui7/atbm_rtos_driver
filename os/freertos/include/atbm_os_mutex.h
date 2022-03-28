#ifndef ATBM_OS_MUTEX_H
#include "mutex.h"
#include "atbm_os_atomic.h"

typedef  atbm_void * atbm_mutex  ;
typedef  atbm_void * atbm_os_wait_queue_head_t  ;

/*mutex*/
#define atbm_os_mutexLockInit(x) mutex_init((atbm_mutex *)x)
#define atbm_os_mutexLock(x,a) mutex_lock((atbm_mutex *)x)
#define atbm_os_mutexUnLock(x) mutex_unlock((atbm_mutex *)x)
#define atbm_os_DeleteMutex(x) mutex_destroy((atbm_mutex *)x)

#define atbm_os_wait_event_timeout(x,t) wait_event_timeout((atbm_mutex *)x,t)
#define atbm_os_wakeup_event(x) mutex_unlock((atbm_mutex *)x)
#define atbm_os_wakeup_event_isr(x) mutex_unlock_isr((atbm_mutex *)x)
#define atbm_os_mutextryLock(x)	(0)

extern atbm_void atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSemId);
extern atbm_uint8 atbm_os_delete_waitevent(atbm_os_wait_queue_head_t* pulSemId);




#endif /* ATBM_OS_MUTEX_H */

