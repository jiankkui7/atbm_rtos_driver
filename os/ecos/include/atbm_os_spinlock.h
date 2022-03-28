#ifndef ATBM_OS_SPINLOCK_H
#define ATBM_OS_SPINLOCK_H

//#include <drvOSAPI.h>
typedef cyg_spinlock_t atbm_spinlock_t;

/*spin lock*/
#define atbm_spin_lock_init(lock)  cyg_spinlock_init((cyg_spinlock_t*)(lock), 0) 
#define atbm_spin_lock_destroy(lock)  cyg_spinlock_destroy((cyg_spinlock_t *)(lock))

#define atbm_spin_lock(lock)  cyg_spinlock_spin((cyg_spinlock_t*)(lock))
#define atbm_spin_unlock(lock)  cyg_spinlock_clear((cyg_spinlock_t*)(lock))

#define atbm_spin_lock_irqsave(lock, flag)  cyg_spinlock_spin_intsave((cyg_spinlock_t*)(lock), &flag)
//comments that: the 2nd param is a <unsinged int> value, but not pointer.
#define atbm_spin_unlock_irqrestore(lock, flag)  cyg_spinlock_clear_intsave((cyg_spinlock_t*)(lock),flag/*&flag*/)

#define atbm_spin_lock_bh(lock) cyg_spinlock_spin((cyg_spinlock_t*)(lock))
#define atbm_spin_unlock_bh(lock) cyg_spinlock_clear((cyg_spinlock_t*)(lock))

#endif /* ATBM_OS_SPINLOCK_H */

