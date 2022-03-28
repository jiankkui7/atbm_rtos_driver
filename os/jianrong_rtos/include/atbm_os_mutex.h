#ifndef ATBM_OS_MUTEX_H
#define ATBM_OS_MUTEX_H
#include "atbm_type.h"
#include "api.h"



typedef   SemaphoreHandle_t atbm_mutex  ;
typedef   SemaphoreHandle_t atbm_os_wait_queue_head_t  ;

/*sem*/
//atbm_uint32  atbm_os_CreateSem(atbm_uint8 ubSemValue);
//atbm_uint8 atbm_os_DeleteSem(atbm_uint32  ulSemId);
//atbm_uint8 atbm_os_QuerySem(atbm_uint32  ulSemId, atbm_uint16 *usCount);
atbm_uint8 atbm_os_wait_event_timeout(atbm_os_wait_queue_head_t* pulSemId, atbm_uint32 ulTimeout);
atbm_uint8 atbm_os_wakeup_event(atbm_os_wait_queue_head_t* pulSemId);
int atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSemId);
atbm_uint8 atbm_os_delete_waitevent(atbm_os_wait_queue_head_t* pulSemId);

/*mutex*/
atbm_uint32 atbm_os_mutexLockInit(atbm_mutex * pmutex_id);
atbm_uint8 atbm_os_DeleteMutex(atbm_mutex * pmutex_id);
atbm_uint8 atbm_os_mutexLock(atbm_mutex * pmutex_id,atbm_uint32 ulTimeout);
atbm_uint8 atbm_os_mutexUnLock(atbm_mutex * pmutex_id);
#endif /* ATBM_OS_MUTEX_H */

