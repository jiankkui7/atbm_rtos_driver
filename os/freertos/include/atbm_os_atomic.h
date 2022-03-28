/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#ifndef ATBM_OS_ATOMIC_H
#define ATBM_OS_ATOMIC_H

typedef struct _atbm_atomic_t
{
	  int val;
} atbm_atomic_t;
#include "atomic.h"

int atbm_test_bit(int nr,atbm_uint32 * addr);
int atbm_clear_bit(int nr,atbm_uint32 * addr);
int atbm_set_bit(int nr,atbm_uint32* addr);

#define atbm_atomic_read(a) atomic_read(a)
#define atbm_atomic_set(a,b) atomic_set(a,b)



#define atbm_atomic_xchg  atomic_xchg
#define atbm_atomic_add_return  atomic_add_return

#define atbm_atomic_sub_return(i, v)	(atbm_atomic_add_return(-(int)(i), (v)))
#define atbm_find_first_zero_bit find_first_zero_bit
#define atbm_atomic_add					atbm_atomic_add_return

unsigned int atbm_local_irq_save();
atbm_void atbm_local_irq_restore(unsigned int cpu_sr);

#define atbm_TimeAfter OS_Time_After
#define atbm_GetOsTimeMs() os_time_get()

#endif /* ATBM_OS_ATOMIC_H */

