#ifndef ATBM_OS_SPINLOCK_H
#define ATBM_OS_SPINLOCK_H
#include "atbm_type.h"

typedef   atbm_uint8 atbm_spinlock_t;
/*spin lock*/
#define atbm_spin_lock_init(x)
#define atbm_spin_lock(x) rt_enter_critical()
#define atbm_spin_unlock(x) rt_exit_critical()
#define atbm_spin_lock_irqsave(x,f) do {*(f) = rt_hw_interrupt_disable();}while(0)//rt_enter_critical()
#define atbm_spin_unlock_irqrestore(x,f) rt_hw_interrupt_enable(f)//rt_exit_critical()
#define atbm_spin_lock_bh(x) rt_enter_critical()
#define atbm_spin_unlock_bh(x) rt_exit_critical()


#endif /* ATBM_OS_SPINLOCK_H */

