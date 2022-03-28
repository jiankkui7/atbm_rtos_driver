#ifndef ATBM_OS_MUTEX_H
//#include "mutex.h"
#include "atbm_os_atomic.h"
#define OS_WAIT_FOREVER 0xffffffff
typedef  cyg_mutex_t atbm_mutex  ;
typedef  cyg_sem_t atbm_os_wait_queue_head_t  ;

/*mutex*/
#define atbm_os_mutexLockInit(x) cyg_mutex_init((cyg_mutex_t *)x)
#define atbm_os_DeleteMutex(x) cyg_mutex_destroy((cyg_mutex_t *)x)

#define atbm_os_mutexLock(x,a) cyg_mutex_lock((cyg_mutex_t *)x)
#define atbm_os_mutexUnLock(x) cyg_mutex_unlock((cyg_mutex_t *)x)


/*semaphore*/
#define atbm_os_init_waitevent(x) cyg_semaphore_init((cyg_sem_t *)x,0)
#define atbm_os_delete_waitevent(x) cyg_semaphore_destroy((cyg_sem_t *)x)

#define atbm_os_wait_event(x) cyg_semaphore_wait((cyg_sem_t *)x)//always suspend
#define atbm_os_wait_event_timeout(x,t) cyg_semaphore_timed_wait((cyg_sem_t *)x, (t/*tick*/+cyg_current_time()))

#define atbm_os_wakeup_event(x) cyg_semaphore_post((cyg_sem_t *)x)

#ifdef ATBM_USB_RX_ISR
#error eCos: please attention, ISR event wakeup is not support
#define atbm_os_wakeup_event_isr(x) cyg_semaphore_post((cyg_sem_t *)x)
#endif

#define atbm_os_mutextryLock(x)	(0)
#endif /* ATBM_OS_MUTEX_H */

