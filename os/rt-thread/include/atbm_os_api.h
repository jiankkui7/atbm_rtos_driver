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
/*include os platform */
#include "atbm_type.h"
#define __INLINE 
#define HZ  100
#define OS_SUCCESS  0
#define OS_FAIL     -1
#define ZEROSIZE 1
#define atbm_packed __attribute__ ((packed))
#define atbm_mdelay(a) rt_thread_delay(a)
typedef unsigned int size_t;
#define NULL 0
#define rcu_read_lock()
#define rcu_read_unlock()
static __INLINE atbm_uint32 atbm_random()
{
	static unsigned int m_w = 0xDEADBEEF;	 /* must not be zero */
	static unsigned int m_z = 0xCAFEBABE;	 /* must not be zero */

	m_z = 36969 * (m_z & 65535) + (m_z >> 16);
	m_w = 18000 * (m_w & 65535) + (m_w >> 16);
	return (m_z << 16) + m_w;  /* 32-bit result */

}
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

static __INLINE atbm_uint32 atbm_os_random()
{
	atbm_uint32 data = atbm_random()/3;
	return (data>>1);
}
int atbmwifi_event_OsCallback(atbm_void *prv,int eventid,atbm_void *param);
atbm_uint32 atbm_usb_register_init();
atbm_uint32 atbm_usb_register_deinit();
#endif //ATBM_OS_API_H
