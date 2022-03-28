#ifndef ATBM_OS_MUTEX_H
#define ATBM_OS_MUTEX_H

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/event_groups.h>
#include <io.h>

#include "atbm_type.h"

typedef   QueueHandle_t atbm_mutex  ;
typedef   EventGroupHandle_t atbm_os_wait_queue_head_t  ;

atbm_uint8 atbm_os_wait_event_timeout(atbm_os_wait_queue_head_t * pulSemId, atbm_uint32 ulTimeout);
atbm_uint8 atbm_os_wakeup_event(atbm_os_wait_queue_head_t * pulSemId);
int atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSemId);

/*mutex*/
atbm_uint32 atbm_os_mutexLockInit(atbm_mutex * pmutex_id);
atbm_uint8 atbm_os_DeleteMutex(atbm_mutex * pmutex_id);
atbm_uint8 atbm_os_mutexLock(atbm_mutex * pmutex_id,atbm_uint32 ulTimeout);
atbm_uint8 atbm_os_mutexUnLock(atbm_mutex * pmutex_id);
#endif /* ATBM_OS_MUTEX_H */

