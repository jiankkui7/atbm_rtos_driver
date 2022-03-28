/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


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
	atbm_uint32 rsem = AK_INVALID_SUSPEND;
	
	rsem = AK_Create_Semaphore(1,AK_PRIORITY);

	if(rsem == AK_INVALID_SUSPEND){
		wifi_printk(AK_MUTEX_ERR_LEVEL,"atbm_os_CreateSem err\n");
		return -1;
	}
	return rsem;
}
atbm_int32 atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSem)
{	 
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
	
	status = AK_Delete_Semaphore(*pulSem);
	
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
	int ret;
	atbm_uint32 wait_ms;

	if ( ulTimeout == AK_SUSPEND )
	{
		//ret = AK_Obtain_Semaphore(*semaphore , AK_SUSPEND);
		wait_ms = AK_SUSPEND;
	}
	else if ( ulTimeout == 0 )
	{
		//ret = AK_Obtain_Semaphore(*semaphore , AK_NO_SUSPEND);
		wait_ms = AK_NO_SUSPEND;
	}
	else
	{
		if (ulTimeout < 10)
			ulTimeout = 10;
		ulTimeout = (ulTimeout * 200) / 1000;
		wait_ms = ulTimeout;
	}

	ret = AK_Obtain_Semaphore(*pSem , wait_ms);
	if (AK_SUCCESS == ret)
		return 1;
	else if (AK_TIMEOUT == ret)
		return 0;
	else
		return -1;



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
	
	ret = AK_Release_Semaphore(*pSem);

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

atbm_uint8 atbm_os_DeleteMutex(atbm_mutex * pmutex_id)
{
   // return ak_thread_mutex_destroy(pmutex_id);
   int status = AK_SUCCESS;
	
	status = AK_Delete_Semaphore(*pmutex_id);
	
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

atbm_uint8 atbm_os_mutexLock(atbm_mutex * pmutex_id,atbm_uint32 ulTimeout)
{
	//if(ulTimeout==0)
	//	ulTimeout = OSL_EXT_TIME_FOREVER;
	ulTimeout = ulTimeout;
    //return ak_thread_mutex_lock(pmutex_id);
    AK_Obtain_Semaphore(*pmutex_id, AK_SUSPEND);

	return 0;
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
    //return ak_thread_mutex_unlock(pmutex_id);
    AK_Release_Semaphore(*pmutex_id);

	return 0;
}


atbm_uint8 atbm_os_mutextryLock(atbm_mutex * pmutex_id)
{
	long status = AK_SUCCESS;
	atbm_uint8 ret = 0;

	status = AK_Obtain_Semaphore(*pmutex_id, AK_NO_SUSPEND);

	if(status == AK_SUCCESS)
		return 0;

	return 1;
}

#ifdef CONFIG_P2P
void *start_address = ATBM_NULL;

atbm_queue atbm_os_queueCreate(int length, int itemsize){
	start_address = atbm_kmalloc(length * itemsize, GFP_KERNEL);

	return AK_Create_Queue(start_address, length * itemsize,
                      AK_FIXED_SIZE, itemsize, AK_FIFO);
}
int atbm_os_queueReceive(atbm_queue queue, int *size, void *message, unsigned long timeout){
	return (int)AK_Receive_From_Queue(queue, message, *size,
                                size, AK_SUSPEND);
}

int atbm_os_queueSend(atbm_queue queue, int size, void *message, unsigned long timeout){
	return (int)AK_Send_To_Queue(queue, message, size, timeout);
}

int atbm_os_queueDelete(atbm_queue queue){
	if(start_address){
		atbm_kfree(start_address);
		start_address = ATBM_NULL;
	}
	return (int)AK_Delete_Queue(queue);
}

#endif

