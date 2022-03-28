/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#ifndef ATBM_OS_API_H
#define ATBM_OS_API_H

#include "atbm_hal.h"

#define __INLINE 
#define HZ  100
#define __ATBM_FUNCTION__ __func__
#define atbm_packed __attribute__ ((packed))
#define atbm_mdelay atbm_SleepMs

#define rcu_read_lock()
#define rcu_read_unlock()

#define atbm_random() rand()
struct __una_u16 { atbm_uint16 x; } atbm_packed ;
struct __una_u32  { atbm_uint32 x; } atbm_packed ;

static __INLINE atbm_uint16 __get_unaligned_cpu16(const atbm_void *p)
{
 	const struct __una_u16 *ptr = (const struct __una_u16 *)p;
 	return ptr->x;
}
 
static __INLINE  atbm_uint32 __get_unaligned_cpu32 (const atbm_void *p)
{
	 const struct __una_u32  *ptr = (const struct __una_u32  *)p;
	 return ptr->x;
}

//static __INLINE uint16 get_unaligned_le16(const void *p)
//{
// 	return __get_unaligned_cpu16((const atbm_uint8 *)p);
//}
 
static __INLINE atbm_uint32 get_unaligned_le32(const atbm_void *p)
{
	return __get_unaligned_cpu32 ((const atbm_uint8 *)p);
}

#endif //ATBM_OS_API_H
