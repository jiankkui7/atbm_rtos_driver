#ifndef ATBM_OS_MEM_H
#define ATBM_OS_MEM_H
//#include "sys_MsWrapper_cus_os_mem.h"

#define atbm_kmalloc(x,y) x//MsAllocateMem(x) 
#define atbm_kzalloc(x,y) x//MsAllocateMem(x)            
#define atbm_kfree(x)    x // MsReleaseMemory(x)           
#define atbm_memcpy(d,s,c)           
#define atbm_memset(a,v,n)             
#define atbm_memmove(d,s,c)  
#define atbm_memcmp(d,s,c)  (d,s,c)
#endif /* ATBM_OS_MEM_H */
