#ifndef ATBM_OS_SPINLOCK_H
#define ATBM_OS_SPINLOCK_H
#include "atbm_type.h"
#include "akos_api.h"

extern void store_all_int(void);
extern void restore_all_int(void);

typedef   atbm_uint8 atbm_spinlock_t;
/*spin lock*/
#define atbm_spin_lock_init(x)
#define atbm_spin_lock(x) 
#define atbm_spin_unlock(x) 
#define atbm_spin_lock_irqsave(x,f) do{ \
					(void)x; (void)f; store_all_int(); }while(0);
#define atbm_spin_unlock_irqrestore(x,f) do{ \
					(void)x; (void)f; restore_all_int(); }while(0);
#define atbm_spin_lock_bh(x) 
#define atbm_spin_unlock_bh(x)


#endif /* ATBM_OS_SPINLOCK_H */

