#include "atbm_os_mutex.h"
#include "atbm_hal.h"
//semaphore
atbm_uint32 atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSem)
{	
	*pulSem = rt_sem_create("waitQueue", 0, RT_IPC_FLAG_PRIO);
	if (*pulSem){
			wifi_printk(WIFI_ALWAYS,"OS: Semaphore Init: handle %p\r\n", *pulSem);
			return OS_SUCCESS;
		}else{
			ATBM_BUG_ON(1);
			return OS_FAIL;
		}
}
atbm_uint8 atbm_os_wait_event_timeout(atbm_os_wait_queue_head_t * pSem, atbm_int64 ulTimeout)
{ 
	atbm_uint8 ret;
	if(*pSem==ATBM_NULL)
		ATBM_BUG_ON(1);
	//wifi_printk(WIFI_ALWAYS,"OS: Semaphore take: handle %p\r\n", *pSem);
	if(0 == ulTimeout){
	    ret = rt_sem_trytake(*pSem);
	}else if(OS_WAIT_FOREVER == ulTimeout){
	    ret = rt_sem_take(*pSem, RT_WAITING_FOREVER);
	}else{
	    ret = rt_sem_take(*pSem, ulTimeout);
	}
	if(ret == RT_EOK){
		return OS_SUCCESS;
	}else{
		return OS_FAIL;
	}
}

atbm_uint8 atbm_os_wakeup_event(atbm_os_wait_queue_head_t * pSem)
{
	atbm_uint8 ret;
	if(*pSem==ATBM_NULL)
		ATBM_BUG_ON(1);
	
	//wifi_printk(WIFI_ALWAYS,"OS: Semaphore release: handle %p\r\n", *pSem);
	ret = rt_sem_release(*pSem);
	if(ret == RT_EOK){
		return OS_SUCCESS;
	}else{
		return OS_FAIL;
	}
}
atbm_uint32 atbm_os_delete_waitevent(atbm_os_wait_queue_head_t* pulSem)
{	
	rt_sem_delete(*pulSem);
	return OS_SUCCESS;
}
//mutex
atbm_uint32 atbm_os_mutexLockInit(atbm_mutex * pmutex)
{
	*pmutex= rt_mutex_create("AtbMutex", RT_IPC_FLAG_PRIO);
	if(*pmutex){
		return OS_SUCCESS;
	}else{
		return OS_FAIL;
	}
}
atbm_uint8 atbm_os_DeleteMutex(atbm_mutex * pmutex)
{
	rt_mutex_delete(*pmutex);
	return OS_SUCCESS;
}

atbm_uint8 atbm_os_mutexLock(atbm_mutex * pmutex,atbm_uint32 ulTimeout)
{
	atbm_uint8 ret;
	ulTimeout=OS_WAIT_FOREVER;
	if(0 == ulTimeout)
	    ret = rt_mutex_take(*pmutex, 0);
	else if(OS_WAIT_FOREVER == ulTimeout)
	    ret = rt_mutex_take(*pmutex, RT_WAITING_FOREVER);
	else
	    ret = rt_mutex_take(*pmutex, ulTimeout);
	
	return ret == RT_EOK ? OS_SUCCESS : OS_FAIL;
}

atbm_uint8 atbm_os_mutexUnLock(atbm_mutex * pmutex)
{
	atbm_uint8 ret;
	ret = rt_mutex_release(*pmutex);
	return ret == RT_EOK ? OS_SUCCESS : OS_FAIL;
}


