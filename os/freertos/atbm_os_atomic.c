/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#include "atbm_hal.h"


unsigned int atbm_local_irq_save(atbm_void)
{
	ATBM_OS_CPU_SR cpu_sr = 0u;
	enter_critical();
	
	return (unsigned int)cpu_sr;
}

 atbm_void atbm_local_irq_restore(unsigned int cpu_sr)
{
	exit_critical();
}
 
 
 int atbm_set_bit(int nr,atbm_uint32* addr)
 {
	 int mask,retval;
	 
	 addr += nr >>5;
	 mask = 1<<(nr & 0x1f);
	 
	 enter_critical();
	 retval = (mask & *addr) != 0;
	 *addr |= mask;
	 exit_critical();
	 
	 return  retval;
	 
 }
 
 int atbm_clear_bit(int nr,atbm_uint32 * addr)
 {
	 int mask,retval;
	 
	 addr += nr >>5;
	 mask = 1<<(nr & 0x1f);
	 
	 enter_critical();
	 retval = (mask & *addr) != 0;
	 *addr &= ~mask;
	 exit_critical();
	 
	 return  retval;
	 
 }
 
 
 int atbm_test_bit(int nr,atbm_uint32 * addr)
 {
 
	 int mask;
	 
	 addr += nr >>5;
	 mask = 1<<(nr & 0x1f);
	 
	 return  ((mask & *addr) != 0);
	 
 }

