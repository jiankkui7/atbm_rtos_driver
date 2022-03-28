/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#include "atbm_hal.h"
#include "err.h"
#if (PLATFORM==JIANRONG_RTOS_3268)
#include "api.h"
#else
#include "mutex.h"
#endif
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
    QueueHandle_t x_sema_hdl;

	//x_sema_hdl = xSemaphoreCreateBinary();
    x_sema_hdl = xSemaphoreCreateCounting(-1, ubSemValue);
	
	if (x_sema_hdl == NULL )
	{
	    p_err("osal_sema_create err");
	}
	return (atbm_uint32)x_sema_hdl;

}
int atbm_os_init_waitevent(atbm_os_wait_queue_head_t * pulSem)
{	 
	int status = 0;
	status = xSemaphoreCreateCounting( -1, 0 );
	if (!status)
		p_err("init_waitqueue_head err");

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
	vSemaphoreDelete(*pulSem);
	return RET_SUCCESS;

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
	INT8U perr;
		uint32_t ticks;
		
		if (pSem == 0)
		{
			p_err("wait_event_timeout wq err");
			return	- 1;
		}
		ticks = (ulTimeout * configTICK_RATE_HZ) / 500;
		if (xSemaphoreTake(*pSem, ticks) == pdTRUE)
			{
				return 1;
			}
		//printf("xSemaphore_time out:%d\n",__LINE__);
		return 0;	//timeout

}

#if (PLATFORM==JIANRONG_RTOS_3268)
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
atbm_uint8 atbm_os_wakeup_event(atbm_os_wait_queue_head_t  * pSem)
{
	if (xSemaphoreGiveFromISR(*pSem, NULL) != pdTRUE)
		p_err("wake_up err");


	return 0;
}




//------------------------------------------------------------------------------
//  Function    : atbm_os_mutexLockInit
//  Description :
//------------------------------------------------------------------------------

atbm_uint32 atbm_os_mutexLockInit(atbm_mutex  *	pmutex)
{
	//return ak_thread_mutex_init(pmutex);
	mutex_t rsem;
	rsem = mutex_init_legacy("test");
	printf("mutex lock init ok~:%x %x\n",pmutex,rsem);
	*pmutex = rsem;
	printf("mutex lock init ok:%x\n",pmutex);
	
	return 0;
}
#else
extern uint32_t os_int_nesting;


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


atbm_uint8 atbm_os_wakeup_event(atbm_os_wait_queue_head_t  * pSem)
{
	if(os_int_nesting)
	{
		if (xSemaphoreGiveFromISR(*pSem, NULL) != pdTRUE)//os_int_nesting
			p_err("wake_up err");
	}
	else
	{
	if (xSemaphoreGive(*pSem) != pdTRUE)//os_int_nesting
			p_err("wake_up no int err");
	}


	return 0;
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_mutexLockInit
//  Description :
//------------------------------------------------------------------------------

atbm_uint32 atbm_os_mutexLockInit(atbm_mutex  *	pmutex)
{
	//return ak_thread_mutex_init(pmutex);
	mutex_t rsem;
	rsem = mutex_init_legacy_atbm("test");
	printf("mutex lock init ok~:%x %x\n",pmutex,rsem);
	*pmutex = rsem;
	printf("mutex lock init ok:%x\n",pmutex);
	wifi_printk(AK_MUTEX_DEBUG_LEVEL,"atbm_os_mutexLockInit ok\n");
	return 0;
}


#endif
//------------------------------------------------------------------------------
//  Function    : atbm_os_DeleteMutex
//  Description :
//------------------------------------------------------------------------------
/** @brief This function deletes a mutual exclusion semaphore and readies all tasks pending on the it.

@param[in] ulMutexId : The mutex ID that return by @ref atbm_os_mutexLockInit 
@retval 0xFF for delete mutex internal error from OS
		0, return delete success.
*/
atbm_uint8 atbm_os_delete_waitevent(atbm_os_wait_queue_head_t* pulSemId)
{
	//Need Fixed
	return 0;
}

atbm_uint8 atbm_os_DeleteMutex(atbm_mutex * pmutex_id)
{
   // return ak_thread_mutex_destroy(pmutex_id);
    vSemaphoreDelete (*pmutex_id);
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
	INT8U perr;
    //printf("pmutex_id:%x\n",*pmutex_id);
	perr = xSemaphoreTake( *pmutex_id, ulTimeout);
	if (perr == pdPASS)
		return 0;

	p_err("mutex_lock err %d", perr);
	return  - 1;

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
	INT8U perr;

	perr = xSemaphoreGive (*pmutex_id);
	if (perr == pdTRUE)
		return 0;

	p_err("mutex_unlock err %d", perr);
	return  - 1;

}


atbm_uint8 atbm_os_mutextryLock(atbm_mutex  * pmutex_id)
{
	INT8U perr;

	perr = xSemaphoreTake( *pmutex_id, portMAX_DELAY );
	if (perr == pdPASS)
		return 0;

	p_err("mutex_lock err %d", perr);
	return  - 1;

}

