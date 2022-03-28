/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#include "atbm_hal.h"
#include "osl_ext.h"
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
	osl_ext_sem_t sem;
	osl_ext_sem_create("atbm1", ubSemValue, &sem);
	return sem;
}
int atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSem)
{	 
#if SEM_USE
	 osl_ext_status_t status;
	 
	status =  osl_ext_sem_create("atbm1", 0, pulSem);
	
	//iot_printf("%s %d \n",__func__,__LINE__);	
	if(status != OSL_EXT_SUCCESS)
		return -1;
	else
		return 0;
#else	
	*pulSem = MMPF_OS_CreateEventFlagGrp(0);

	return 0;
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
    return osl_ext_sem_delete(pulSem);
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
#if SEM_USE
	atbm_uint16 count=0;
	//osl_ext_sem_query(pSem,&count);
	//iot_printf("%s pSem=%d count %d\n",__func__,*(atbm_uint32 *)pSem,count);
    return osl_ext_sem_take(pSem, ulTimeout);
#else
	MMPF_OS_FLAGS flags;
    MMPF_OS_FLAGS waitFlags=BIT(0);
	
	MMPF_OS_WaitFlags(*pSem, waitFlags, MMPF_OS_FLAG_WAIT_SET_ANY | MMPF_OS_FLAG_CONSUME, ulTimeout, &flags);
	return 0;
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
#if SEM_USE
	osl_ext_status_t stauts =OSL_EXT_SUCCESS ;
	atbm_int16 count=0;
	if(osl_ext_sem_query(pSem,&count)==OSL_EXT_SUCCESS){
 		if(count<=0){
			stauts = osl_ext_sem_give(pSem);
			osl_ext_sem_query(pSem,&count);
		   // iot_printf("%s-- pSem=%d count %d\n",__func__,*(atbm_uint32 *)pSem,count);
		}			
	}
	return stauts;
#else	
	MMPF_OS_SetFlags(*pSem, BIT(0), MMPF_OS_FLAG_SET);
	return 0;
#endif
}




//------------------------------------------------------------------------------
//  Function    : atbm_os_mutexLockInit
//  Description :
//------------------------------------------------------------------------------
/** @brief This function creates a mutual exclusion semaphore.

@param[in] ubPriority : is the priority to use when accessing the mutual exclusion semaphore.  In
                            other words, when the semaphore is acquired and a higher priority task
                            attempts to obtain the semaphore then the priority of the task owning the
                            semaphore is raised to this priority.  It is assumed that you will specify
                            a priority that is LOWER in value than ANY of the tasks competing for the
                            mutex.
@retval 0xFF for create semaphore internal error from OS
		0xFE the system maximum semaphore counts exceed.
		others, the ID to access the semaphore
*/
atbm_uint32 atbm_os_mutexLockInit(atbm_mutex * pmutex)
{
	atbm_uint8	ubPriority = 0;
	//atbm_uint32	*pmutex_id = pmutex; 
	//osl_ext_mutex_t mutex;
	osl_ext_status_t stauts ;
	
	//*pmutex_id = MMPF_OS_CreateMutex(ubPriority);
	
	stauts = osl_ext_mutex_create("atbm",(osl_ext_mutex_t *) pmutex);	
    if(stauts == OSL_EXT_SUCCESS)
		return 0;
	else
		return -1;
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
    return osl_ext_mutex_delete(pmutex_id);
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
    return osl_ext_mutex_acquire(pmutex_id,OSL_EXT_TIME_FOREVER);
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
    return osl_ext_mutex_release(pmutex_id);
}

