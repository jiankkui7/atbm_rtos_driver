/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "rtdef.h"
#include "atbm_hal.h"
#include "akos_error.h"
#include "akos_api.h"
#define AK_MUTEX_DEBUG_LEVEL	WIFI_DBG_MSG
#define AK_MUTEX_ERR_LEVEL		WIFI_DBG_ERROR
//------------------------------------------------------------------------------
//  Function    : atbm_os_CreateSem
//  Description :
//------------------------------------------------------------------------------
/** @brief This function creates a semaphore.

@param[in] ubSemValue : is the initial value for the semaphore.  If the value is 0, no resource is
                        available.  You initialize the semaphore to a non-zero value to specify how many resources are available.
@retval 0xFF for create semaphore internal error from OS
		0xFE the system maximum semaphore counts exceed.
		others, the ID to access the semaphore
*/
atbm_uint32 atbm_os_CreateSem(atbm_uint8 ubSemValue)
{
#if 0
	atbm_uint32 rsem = AK_INVALID_SUSPEND;
	rsem = AK_Create_Semaphore(1,AK_PRIORITY);
	
	if(rsem == AK_INVALID_SUSPEND){
	wifi_printk(AK_MUTEX_ERR_LEVEL,"atbm_os_CreateSem err\n");
	return -1;
	}
	return rsem;
#else
	//rsem = mutex_init("");
	const char *name = NULL;
	rt_sem_t ret = rt_sem_create( name, ubSemValue, RT_IPC_FLAG_FIFO);
 
	wifi_printk(AK_MUTEX_DEBUG_LEVEL,"-- %x--\n", ret);
    return (rt_sem_t)ret;
#endif

}
atbm_int32 atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSem)
{	 
#if 0
	atbm_int32 status = 0;

	status = AK_Create_Semaphore(0,AK_PRIORITY);
	if(status == AK_INVALID_SUSPEND){
		*pulSem = -1;		
		wifi_printk(AK_MUTEX_ERR_LEVEL,"atbm_os_init_waitevent err\n");
		return -1;
	}
	
	wifi_printk(AK_MUTEX_DEBUG_LEVEL,"atbm_os_init_waitevent ok\n");
	*pulSem = status;
	return 0;
#else
	*pulSem = rt_sem_create("waitQueue", 0, RT_IPC_FLAG_PRIO);
	if (*pulSem){
		wifi_printk(WIFI_ALWAYS,"OS: Semaphore Init: handle %p\r\n", *pulSem);
		return OS_SUCCESS;
	}else{
		ATBM_BUG_ON(1);
		return OS_FAIL;
	}
#endif
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_DeleteSem
//  Description :
//------------------------------------------------------------------------------
/** @brief This function deletes a semaphore and readies all tasks pending on the semaphore.

@param[in] ulSemId : The semaphore ID that return by @ref atbm_os_CreateSem 
@retval 0xFF for delete semaphore internal error from OS
		0, return delete success.
*/

atbm_uint8 atbm_os_DeleteSem(atbm_os_wait_queue_head_t* pulSem)
{
	//iot_printf("%s %d\n",__func__,__LINE__);
	int status = AK_SUCCESS;
	
	//status = AK_Delete_Semaphore(*pulSem);
	status = rt_mutex_delete(*pulSem);
	
	if(AK_SUCCESS != status)
		return -1;
    return 0;
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_wait_event_timeout
//  Description :
//------------------------------------------------------------------------------
/** @brief This function waits for a semaphore.

@param[in] ulSemId : The semaphore ID that return by @ref atbm_os_CreateSem 
@param[in] ulTimeout : is an optional timeout period (in clock ticks).  If non-zero, your task will
                            wait for the resource up to the amount of time specified by this argument.
                            If you specify 0, however, your task will wait forever at the specified
                            semaphore or, until the resource becomes available.
@retval 0xFE for bad input semaphore id,
		0xFF for acquire semaphore internal error from OS
		0 for getting the resource.
		1 for time out happens
*/

atbm_uint8 atbm_os_wait_event_timeout(atbm_os_wait_queue_head_t * pSem, atbm_uint32 ulTimeout)
{
#if 0
	int ret;
	atbm_uint32 wait_ms;

	if ( ulTimeout == AK_SUSPEND )
	{
		//ret = AK_Obtain_Semaphore(*semaphore , AK_SUSPEND);
		ret = rt_sem_take(*pSem, RT_WAITING_FOREVER);
		wait_ms = AK_SUSPEND;
	}
	else if ( ulTimeout == 0 )
	{
		//ret = AK_Obtain_Semaphore(*semaphore , AK_NO_SUSPEND);
		ret = rt_sem_trytake(*pSem);
		wait_ms = AK_NO_SUSPEND;
	}
	else
	{
		if (ulTimeout < 10)
			ulTimeout = 10;
		ulTimeout = (ulTimeout * 200) / 1000;
		wait_ms = ulTimeout;
	}

	//ret = AK_Obtain_Semaphore(*pSem , wait_ms);
	wifi_printk(WIFI_ALWAYS,"OS: waitting timeout xxxx : handle%p,ulTimeout=%d\r\n", *pSem,ulTimeout);
	ret = rt_sem_take(*pSem, 40);
	wifi_printk(WIFI_ALWAYS,"OS: vvvvvvvvvvvvxxxx :ret%d\r\n", ret);
	if (AK_SUCCESS == ret)
		return 1;
	else if (AK_TIMEOUT == ret)
		return 0;
	else
		return -1;
#else
	rt_err_t ret;
	if(*pSem==ATBM_NULL)
		ATBM_BUG_ON(1);
	if(0 == ulTimeout){
	    ret = rt_sem_trytake(*pSem);
	}else if(OS_WAIT_FOREVER == ulTimeout){
	    ret = rt_sem_take(*pSem, RT_WAITING_FOREVER);
	}else{
	    ret = rt_sem_take(*pSem, ulTimeout/5);
	}
	//wifi_printk(WIFI_ALWAYS,"OS: Semaphore take:handle %p ulTimeout/5 is %dms\r\n",*pSem, ulTimeout/5);
	if(ret == RT_EOK)//OS_SUCCESS;
		return 1;
	else if (-RT_ETIMEOUT == ret)//RT_ETIMEOUT;
		return 0;
	else //fail
		return OS_FAIL;
#endif

}

//------------------------------------------------------------------------------
//  Function    : atbm_os_wakeup_event
//  Description :
//------------------------------------------------------------------------------
/** @brief This function signals a semaphore

@param[in] ulSemId : The semaphore ID that return by @ref atbm_os_CreateSem 
@retval 0xFE for bad input semaphore id,
		0xFF for release semaphore internal error from OS
		0 for getting the resource.
		1 If the semaphore count exceeded its limit.
*/
atbm_uint8 atbm_os_wakeup_event(atbm_os_wait_queue_head_t * pSem)
{
	int ret =AK_SUCCESS; 
	
	//ret = AK_Release_Semaphore(*pSem);
	ret = rt_sem_release(*pSem);

	if(AK_SUCCESS != ret){		
		wifi_printk(AK_MUTEX_ERR_LEVEL,"atbm_os_wakeup_event err\n");
		return -1;
	}

	return 0;
}




//------------------------------------------------------------------------------
//  Function    : atbm_os_mutexLockInit
//  Description :
//------------------------------------------------------------------------------

atbm_uint32 atbm_os_mutexLockInit(atbm_mutex * pmutex)
{
#if 0
	//return ak_thread_mutex_init(pmutex);
	atbm_uint32 rsem = AK_INVALID_SUSPEND;
	rsem = AK_Create_Semaphore(1,AK_PRIORITY);
	
	if(rsem == AK_INVALID_SUSPEND){		
		wifi_printk(WIFI_DBG_ERROR, "atbm_os_mutexLockInit err\n");
		return -1;
	}
	*pmutex = rsem;
	
	wifi_printk(AK_MUTEX_DEBUG_LEVEL,"atbm_os_mutexLockInit ok\n");
	return 0;
#else
	*pmutex= rt_mutex_create("AtbMutex", RT_IPC_FLAG_PRIO);

	if(*pmutex){
		return OS_SUCCESS;
	}else{
		return OS_FAIL;
	}

#endif

}

//------------------------------------------------------------------------------
//  Function    : atbm_os_DeleteMutex
//  Description :
//------------------------------------------------------------------------------
/** @brief This function deletes a mutual exclusion semaphore and readies all tasks pending on the it.

@param[in] ulMutexId : The mutex ID that return by @ref atbm_os_mutexLockInit 
@retval 0xFF for delete mutex internal error from OS
		0, return delete success.
*/

atbm_uint8 atbm_os_DeleteMutex(atbm_mutex * pmutex)
{
   // return ak_thread_mutex_destroy(pmutex_id);
   int status = AK_SUCCESS;
	
	//status = AK_Delete_Semaphore(*pmutex_id);
	rt_mutex_delete(*pmutex);
	
	if(AK_SUCCESS != status)
		return -1;
    return 0;
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_mutexLock
//  Description :
//------------------------------------------------------------------------------
/** @brief This function waits for a mutual exclusion semaphore

@param[in] ulMutexId : The mutex ID that return by @ref atbm_os_mutexLockInit 
@param[in] ulTimeout : is an optional timeout period (in clock ticks).  If non-zero, your task will
                            wait for the resource up to the amount of time specified by this argument.
                            If you specify 0, however, your task will wait forever at the specified
                            semaphore or, until the resource becomes available.
@retval 0xFE for bad input mutex id,
		0xFF for acquire mutex internal error from OS
		0 for getting the resource.
		1 for time out happens
*/

atbm_uint8 atbm_os_mutexLock(atbm_mutex * pmutex,atbm_uint32 ulTimeout)
{
#if 0
	//if(ulTimeout==0)
	//	ulTimeout = OSL_EXT_TIME_FOREVER;
	ulTimeout = ulTimeout;
    //return ak_thread_mutex_lock(pmutex_id);

    AK_Obtain_Semaphore(*pmutex_id, AK_SUSPEND);
	return 0;

#else
	atbm_uint8 ret = -1;
	ulTimeout=RT_WAITING_FOREVER;

	if(0 == ulTimeout)
		ret = rt_mutex_take(*pmutex, 0);
	else if(RT_WAITING_FOREVER == ulTimeout)
		ret = rt_mutex_take(*pmutex, RT_WAITING_FOREVER);
	else
		ret = rt_mutex_take(*pmutex, ulTimeout);

	return ret == RT_EOK ? OS_SUCCESS : OS_FAIL;
#endif
	
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_mutexUnLock
//  Description :
//------------------------------------------------------------------------------
/** @brief This function signals a mutual exclusion semaphore

@param[in] ulMutexId : The mutex ID that return by @ref atbm_os_CreateSem 
@retval 0xFE for bad input mutex id,
		0xFF for release mutex internal error from OS
		0 for getting the resource.
*/
atbm_uint8 atbm_os_mutexUnLock(atbm_mutex * pmutex_id)
{
#if 0
	//return ak_thread_mutex_unlock(pmutex_id);
    AK_Release_Semaphore(*pmutex_id);
	return 0;
#else
	atbm_uint8 ret;

	ret = rt_mutex_release(*pmutex_id);
	return ret == RT_EOK ? OS_SUCCESS : OS_FAIL;
#endif
}


atbm_uint8 atbm_os_mutextryLock(atbm_mutex * pmutex_id)
{
	long status = AK_SUCCESS;
	atbm_uint8 ret = 0;

	//status = AK_Obtain_Semaphore(*pmutex_id, AK_NO_SUSPEND);
	status = rt_sem_take(*pmutex_id, AK_NO_SUSPEND);

	if(status == AK_SUCCESS)
		return OS_SUCCESS;

	return OS_FAIL;
}

