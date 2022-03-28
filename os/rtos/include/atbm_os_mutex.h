#ifndef ATBM_OS_MUTEX_H
#define ATBM_OS_MUTEX_H
#include "atbm_type.h"


typedef  atbm_void * atbm_mutex  ;
typedef  atbm_void * atbm_os_wait_queue_head_t  ;
/*sem*/
atbm_uint32 atbm_os_CreateSem(atbm_uint8 ubSemValue);
atbm_uint8 atbm_os_DeleteSem(atbm_uint32 ulSemId);
atbm_uint8 atbm_os_wait_event_timeout(atbm_uint32* pulSemId, atbm_uint32 ulTimeout);
atbm_uint8 atbm_os_wakeup_event(atbm_uint32 * pulSemId);
atbm_uint8 atbm_os_QuerySem(atbm_uint32 ulSemId, atbm_uint16 *usCount);
atbm_int32 atbm_os_init_waitevent(atbm_uint32* pulSemId);
atbm_uint8 atbm_os_DeleteSem(atbm_uint32 ulSemId);
#define atbm_os_delete_waitevent(x) atbm_os_DeleteSem((atbm_uint32)*x)

/*mutex*/

atbm_uint32 atbm_os_mutexLockInit(atbm_uint32 * pmutex_id);
atbm_uint8 atbm_os_DeleteMutex(atbm_uint32 ulMutexId);
atbm_uint8 atbm_os_mutexLock(atbm_uint32 ulMutexId, atbm_uint32 ulTimeout);
atbm_uint8 atbm_os_mutexUnLock(atbm_uint32 ulMutexId);
#endif /* ATBM_OS_MUTEX_H */

