/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#include "atbm_hal.h"


/*
OS: eCos
Syntax: void
	cyg_scheduler_lock(void);
Context: Thread/DSR
Parameters: None
Description: Locks the scheduler, preventing any other threads from executing. This function increments
	the scheduler lock counter.
*/
/*
OS: eCos
Syntax: void
	cyg_interrupt_disable(void);
Context: Any
Parameters: None
Description: Disable all interrupts, using the HAL_INTERRUPT_DISABLE macro.
*/
unsigned int atbm_local_irq_save(atbm_void)
{
	ATBM_OS_CPU_SR cpu_sr = 0u;
	//enter_critical();
	//cyg_scheduler_lock();//software interrup
	//cyg_interrupt_disable();
	HAL_DISABLE_INTERRUPTS(cpu_sr);
	return (unsigned int)cpu_sr;
}


/*
OS: eCos
Syntax: void
	cyg_scheduler_unlock(void);
Context: Thread/DSR
Parameters: None
Description: This function decrements the scheduler lock counter. Threads are allowed to execute when
	the scheduler lock counter reaches 0.
*/
/*
OS: eCos
Syntax: void
	cyg_interrupt_enable(void);
Context: Any
Parameters: None
Description: Enable all interrupts, using the HAL_INTERRUPT_ENABLE macro.
*/
atbm_void atbm_local_irq_restore(unsigned int cpu_sr)
{
	//exit_critical();
	//cyg_scheduler_unlock();//software interrup
	//cyg_interrupt_enable();
	HAL_RESTORE_INTERRUPTS(cpu_sr);
}
 

atbm_void atbm_atomic_set(atbm_atomic_t *at, int val)
{
	ATBM_OS_CPU_SR cpu_sr = atbm_local_irq_save();
	at->val = val;
	atbm_local_irq_restore(cpu_sr);
}

int atbm_atomic_read(atbm_atomic_t *at)
{
	int val = 0;
	ATBM_OS_CPU_SR cpu_sr = atbm_local_irq_save();
	
	val = at->val;
	atbm_local_irq_restore(cpu_sr);

	return val;
}

int atbm_atomic_add_return(int val,atbm_atomic_t *at)
{

	ATBM_OS_CPU_SR cpu_sr = atbm_local_irq_save();
	at->val += val;
	atbm_local_irq_restore(cpu_sr);
	
	return  at->val;	
}

int atbm_atomic_xchg(atbm_atomic_t * v, int val)
{
	int tmp = 0;
	ATBM_OS_CPU_SR cpu_sr = atbm_local_irq_save();
	tmp = v->val;
	v->val = val;
	atbm_local_irq_restore(cpu_sr);
	return tmp;
}


int atbm_set_bit(int nr,atbm_uint32* addr)
{
	int mask,retval;

	ATBM_OS_CPU_SR cpu_sr = atbm_local_irq_save();
	addr += nr >>5;
	mask = 1<<(nr & 0x1f);

	retval = (mask & *addr) != 0;
	*addr |= mask;
	atbm_local_irq_restore(cpu_sr);

	return  retval;

}

int atbm_clear_bit(int nr,atbm_uint32 * addr)
{
	int mask,retval;
	ATBM_OS_CPU_SR cpu_sr = atbm_local_irq_save();

	addr += nr >>5;
	mask = 1<<(nr & 0x1f);

	retval = (mask & *addr) != 0;
	*addr &= ~mask;
	atbm_local_irq_restore(cpu_sr);

	return  retval;

}


int atbm_test_bit(int nr,atbm_uint32 * addr)
{

	int mask;

	addr += nr >>5;
	mask = 1<<(nr & 0x1f);

	return  ((mask & *addr) != 0);

}
int atbm_find_first_zero_bit(atbm_uint32 * addr,int size)
{
	int i =0;
	for (i = 0; i <size; i++) {
		if(atbm_test_bit(i,addr) ==0)
			return i;
	}
	return -1;
}


