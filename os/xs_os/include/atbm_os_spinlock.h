#ifndef ATBM_OS_SPINLOCK_H
#define ATBM_OS_SPINLOCK_H
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "atbm_type.h"
//#include "akos_api.h"

typedef   QueueHandle_t atbm_spinlock_t;
/*spin lock*/
#define atbm_spin_lock_init(x) ((*x) = xSemaphoreCreateMutex())
#define atbm_spin_lock(x)
#define atbm_spin_unlock(x)
#define atbm_spin_lock_irqsave(x,f) xSemaphoreTake(*x, 10 / portTICK_PERIOD_MS)
#define atbm_spin_unlock_irqrestore(x,f)  xSemaphoreGive(*x)
#define atbm_spin_lock_bh(x)
#define atbm_spin_unlock_bh(x)


#endif /* ATBM_OS_SPINLOCK_H */

