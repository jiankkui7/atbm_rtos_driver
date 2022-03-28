#ifndef ATBM_OS_SPINLOCK_H
#define ATBM_OS_SPINLOCK_H
#include <rtdef.h>
typedef rt_base_t atbm_spinlock_t;
/*spin lock*/
#define atbm_spin_lock(x) //rt_enter_critical()
#define atbm_spin_unlock(x)  //rt_exit_critical()
#define atbm_spin_lock_bh(x)// rt_enter_critical()
#define atbm_spin_unlock_bh(x)// rt_exit_critical()

#define  OS_ENTER_CRITICAL_EX(__irqflag)  {__irqflag = rt_hw_interrupt_disable();}
#define  OS_EXIT_CRITICAL_EX(__irqflag)   {rt_hw_interrupt_enable(__irqflag);}

#define atbm_spin_lock_init(x)	*(x) = 0

#define atbm_spin_lock_irqsave(__lock, __irqflag)	\
do{												\
	OS_ENTER_CRITICAL_EX(__irqflag);			\
	if(*(__lock) == 1){						\
		wifi_printk(WIFI_ALWAYS,"SPIN UNLOCKED \n");							\
	}      \
	*(__lock) = 1;								\
}while(0)	

#define atbm_spin_unlock_irqrestore(__lock , __irqflag)		\
do{												\
	*(__lock) = 0;								\
	OS_EXIT_CRITICAL_EX(__irqflag);					\
}while(0)

#endif /* ATBM_OS_SPINLOCK_H */

