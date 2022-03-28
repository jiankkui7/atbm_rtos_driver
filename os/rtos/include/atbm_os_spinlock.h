#ifndef ATBM_OS_SPINLOCK_H
#define ATBM_OS_SPINLOCK_H
//#include <drvOSAPI.h>
typedef int spinlock_t;
/*spin lock*/
#define atbm_spin_lock_init(x) osapi_spin_lock_init(x)
#define atbm_spin_lock(x) osapi_spin_lock(x)
#define atbm_spin_unlock(x) osapi_spin_unlock(x)
#define atbm_spin_lock_irqsave(x) osapi_spin_lock_irqsave(x)
#define atbm_spin_unlock_irqrestore(x)  osapi_spin_unlock_irqrestore(x)
#define atbm_spin_lock_bh(x) osapi_spin_lock(x)
#define atbm_spin_unlock_bh(x) osapi_spin_unlock(x)


#endif /* ATBM_OS_SPINLOCK_H */

