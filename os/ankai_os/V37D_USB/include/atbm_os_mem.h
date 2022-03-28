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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "command.h"
//#include "os_malloc.h"
extern void *atbm_ak_wifi_zalloc(unsigned int size);
#define atbm_kmalloc(x,y) malloc(x)  
#define atbm_kzalloc(x,y) atbm_ak_wifi_zalloc(x)            
#define atbm_kfree(x)   free(x)           
#define atbm_memcpy         memcpy 
#define atbm_memset         memset 
#define atbm_memmove  		memmove
#define atbm_memcmp 		memcmp 
extern char *strdup(const char *s);

#endif /* ATBM_OS_MEM_H */
