#ifndef ATBM_OS_SPINLOCK_H
#define ATBM_OS_SPINLOCK_H
/*include os platform*/
#include "usr_cfg.h"

#include "atbm_type.h"

#define  atbm_spinlock_t spinlock_t
/*spin lock*/
#define atbm_spin_lock_init(lock)  spin_lock_init(lock)
#define atbm_spin_lock_destroy(lock)  

#define atbm_spin_lock(lock)  
#define atbm_spin_unlock(lock)

#define atbm_spin_lock_irqsave(lock, flag)  spin_lock_irqsave(lock,flag)
//comments that: the 2nd param is a <unsinged int> value, but not pointer.
#define atbm_spin_unlock_irqrestore(lock, flag) spin_unlock_irqrestore(lock,flag)

#define atbm_spin_lock_bh(lock)
#define atbm_spin_unlock_bh(lock) 
#endif /* ATBM_OS_SPINLOCK_H */

