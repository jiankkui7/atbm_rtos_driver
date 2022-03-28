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

typedef atbm_uint32 _t mem_size_t;
void *mem_malloc(mem_size_t size);
void *mem_calloc(mem_size_t count, mem_size_t size);
void  mem_free(void *mem);

#define atbm_kmalloc(x,y)     mem_malloc(x) 
#define atbm_kfree(x)        mem_free(x)              
#define atbm_memcpy          memcpy 
#define atbm_memset         memset 
#define atbm_memmove  memcpy
#define atbm_memcmp memcmp 


static char * atbm_kzalloc(int size,int flags)     {  
	char * buf=	atbm_kmalloc(size,GFP_KERNEL);
	memset(buf,0,size);
	return  buf;
}
#endif /* ATBM_OS_MEM_H */
