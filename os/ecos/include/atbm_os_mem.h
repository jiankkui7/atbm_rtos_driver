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
#include <stdlib.h>

#define GFP_KERNEL 0

#define atbm_kmalloc(x,y)     malloc(x) 
#define atbm_kfree(x)        free(x)              
#define atbm_memcpy          memcpy 
#define atbm_memset         memset 
#define atbm_memmove  memcpy
#define atbm_memcmp memcmp 


static void * atbm_kzalloc(int size,int flag)     {  
	void * buf=	atbm_kmalloc(size,GFP_KERNEL);
	memset(buf,0,size);
	return  buf;
}
#endif /* ATBM_OS_MEM_H */
