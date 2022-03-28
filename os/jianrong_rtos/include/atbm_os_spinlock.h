#ifndef ATBM_OS_SPINLOCK_H
#define ATBM_OS_SPINLOCK_H
#include "atbm_type.h"
#include "api.h"

#include "linux_spinlock.h"

typedef   spinlock_t atbm_spinlock_t;
/*spin lock*/
#define atbm_spin_lock_init(x)
#define atbm_spin_lock(x) 
#define atbm_spin_unlock(x) 
#define atbm_spin_lock_irqsave(x,f) spin_lock_irqsave(x,f)
#define atbm_spin_unlock_irqrestore(x,f)  spin_unlock_irqrestore(x,f)
#define atbm_spin_lock_bh(x) 
#define atbm_spin_unlock_bh(x)


#endif /* ATBM_OS_SPINLOCK_H */

