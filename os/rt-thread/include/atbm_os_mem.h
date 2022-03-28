#ifndef ATBM_OS_MEM_H
#define ATBM_OS_MEM_H
#include <rtdef.h>
#include <rtthread.h>
#define atbm_memcpy(d,s,c) rt_memcpy(d,s,c)        
#define atbm_memset(a,v,n) rt_memset(a,v,n)         
#define atbm_memmove(d,s,c) rt_memmove(d,s,c) 
#define atbm_memcmp(d,s,c) rt_memcmp(d,s,c)
#define strlen  rt_strlen
#define sprintf rt_sprintf

static inline atbm_void *atbm_kmalloc(size_t size,int flag)
{
		atbm_void *ptr = rt_malloc(size);
		return ptr;
}
static inline atbm_void *atbm_kzalloc(size_t size,int flag)
{
		atbm_void *ptr = rt_malloc(size);
		if (ptr)
			atbm_memset(ptr, 0x00, size);

		return ptr;
}
static inline atbm_void *atbm_realloc(atbm_void *ptr,size_t size)
{
		atbm_void *newptr=rt_realloc(ptr,size);
		return newptr;

}
static inline atbm_void atbm_kfree(atbm_void *ptr)
{	
		rt_free(ptr);
		ptr=ATBM_NULL;
}

#endif /* ATBM_OS_MEM_H */
