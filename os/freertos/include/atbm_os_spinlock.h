#ifndef ATBM_OS_SPINLOCK_H
#define ATBM_OS_SPINLOCK_H
//#include <drvOSAPI.h>
typedef int atbm_spinlock_t;
/*spin lock*/
#define atbm_spin_lock_init  spin_lock_init 
#define atbm_spin_lock  spin_lock 
#define atbm_spin_unlock  spin_unlock 
#define atbm_spin_lock_irqsave  spin_lock_irqsave
#define atbm_spin_unlock_irqrestore  spin_unlock_irqrestore

#define atbm_spin_lock_bh spin_lock
#define atbm_spin_unlock_bh spin_unlock

#endif /* ATBM_OS_SPINLOCK_H */

