#ifndef ATBM_OS_MEM_H
#define ATBM_OS_MEM_H
/*include os platform*/
#include "api.h"
#define atbm_kmalloc(x,y) mem_malloc(x)
#define atbm_kzalloc(x,y) mem_malloc(x)         
#define atbm_kfree(x)  mem_free(x)      
#define atbm_memcpy(d,s,c)           
#define atbm_memset(a,v,n)             
#define atbm_memmove(d,s,c)  
#define atbm_memcmp(d,s,c)  (d,s,c)
#endif /* ATBM_OS_MEM_H */
