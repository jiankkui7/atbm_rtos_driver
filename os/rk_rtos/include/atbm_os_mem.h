/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#ifndef ATBM_OS_MEM_H
#define ATBM_OS_MEM_H
//#include "sys_MsWrapper_cus_os_mem.h"

#define atbm_kmalloc(x,y) MsAllocateMem(x)  
#define atbm_kzalloc(x,y) MsCallocateMem(x)            
#define atbm_kfree(x)   if(x) MsReleaseMemory(x);           
#define atbm_memcpy         memcpy 
#define atbm_memset         memset 
#define atbm_memmove  		memmove
#define atbm_memcmp 		memcmp 

#endif /* ATBM_OS_MEM_H */
