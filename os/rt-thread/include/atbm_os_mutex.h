#ifndef ATBM_OS_MUTEX_H
#define ATBM_OS_MUTEX_H
#include <rtdef.h>
#include <rtthread.h>
#include "atbm_type.h"
#define OS_WAIT_FOREVER    0xffffffff // block forever until get the source
#define OS_NO_WAIT         0  //no block
//mutex
#define OS_MUTEX_INHERIT     1
#define OS_MUTEX_NO_INHERIT  0

typedef rt_mutex_t atbm_mutex;
atbm_uint32 atbm_os_mutexLockInit(atbm_mutex * pmutex);
atbm_uint8 atbm_os_DeleteMutex(atbm_mutex * pmutex_id);
atbm_uint8 atbm_os_mutexLock(atbm_mutex * pmutex_id,atbm_uint32 ulTimeout);
atbm_uint8 atbm_os_mutexUnLock(atbm_mutex * pmutex_id);

//semaphore 
typedef  rt_sem_t atbm_os_wait_queue_head_t ;

atbm_uint32 atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSem);
atbm_uint8 atbm_os_wait_event_timeout(atbm_os_wait_queue_head_t * pSem, atbm_int64 ulTimeout);
atbm_uint8 atbm_os_wakeup_event(atbm_os_wait_queue_head_t * pSem);

#endif /* ATBM_OS_MUTEX_H */

