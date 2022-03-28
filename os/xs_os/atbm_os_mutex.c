/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "atbm_os_mutex.h"
#include "atbm_hal.h"

#define AK_MUTEX_DEBUG_LEVEL	WIFI_DBG_MSG
#define AK_MUTEX_ERR_LEVEL		WIFI_DBG_ERROR

#define p_err printf


int atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSem)
{
	int status = 0;
	status = xSemaphoreCreateCounting( 1, 0 );
	if (!status)
		p_err("init_waitqueue_head err");

	*pulSem = status;

	return 0;

}

/*
@retval 0xFE for bad input semaphore id,
	0xFF for acquire semaphore internal error from OS
	0 for getting the resource.
	1 for time out happens
*/

atbm_uint8 atbm_os_wait_event_timeout(atbm_os_wait_queue_head_t * pSem, atbm_uint32 ulTimeout)
{
	uint32_t ticks;

	if (pSem == 0)
	{
		p_err("wait_event_timeout wq err");
		return	- 1;
	}
	ticks = (ulTimeout * configTICK_RATE_HZ) / 500;
	if (xSemaphoreTake(*pSem, ticks) == pdTRUE)
		return 1;

	//printf("xSemaphore_time out:%d\n",__LINE__);
	return 0;	//timeout
}

static void atbm_os_wakeup_event_from_hsr(uint32_t data)
{
	atbm_os_wait_queue_head_t * pSem = (atbm_os_wait_queue_head_t *)data;

	if (xSemaphoreGive(*pSem) != pdTRUE)
		;//p_err("wake_up err");

}

/*
@retval 0xFE for bad input semaphore id,
	0xFF for release semaphore internal error from OS
	0 for getting the resource.
	1 If the semaphore count exceeded its limit.
*/
atbm_uint8 atbm_os_wakeup_event(atbm_os_wait_queue_head_t * pSem)
{

	vPortInstallHSR(atbm_os_wakeup_event_from_hsr, (uint32_t)pSem);

	return 0;
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_mutexLockInit
//  Description :
//------------------------------------------------------------------------------

atbm_uint32 atbm_os_mutexLockInit(atbm_mutex * pmutex)
{
	QueueHandle_t mutex = NULL;

	mutex = xSemaphoreCreateMutex();

	if (mutex == NULL) {
		return -1;
	} else {
		*pmutex = mutex;
		return 0;
	}	
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
	vSemaphoreDelete(*pmutex_id);

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
	BaseType_t ret;

	if (ulTimeout == 0)
		ret = xSemaphoreTake(*pmutex_id, portMAX_DELAY);
	else
		ret = xSemaphoreTake(*pmutex_id, ulTimeout / portTICK_PERIOD_MS);

	if (ret == pdTRUE)
		return 0;
	else
		return 1;
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
	uint8_t perr;
	perr = xSemaphoreGive (*pmutex_id);
	if (perr == pdTRUE)
	return 0;
	p_err("mutex_unlock err %d", perr);
	return  - 1;
}


atbm_uint8 atbm_os_mutextryLock(atbm_mutex * pmutex_id)
{
	uint8_t perr;

	perr = xSemaphoreTake( *pmutex_id, portMAX_DELAY );
	if (perr == pdPASS)
		return 0;

	p_err("mutex_lock err %d", perr);
		return -1;
}

