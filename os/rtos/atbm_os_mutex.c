#include "os_wrap.h"
#include "atbm_type.h"
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
    return MMPF_OS_CreateSem(ubSemValue);
}
int atbm_os_init_waitevent(atbm_uint32* pulSemId)
{
	*pulSemId =atbm_os_CreateSem(0)£»

	if((*pulSemId  == 0xFF) ||(*pulSemId  == 0xFE))
		return -1;
	else
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

atbm_uint8 atbm_os_DeleteSem(atbm_uint32 ulSemId)
{
    return MMPF_OS_DeleteSem(ulSemId);
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

atbm_uint8 atbm_os_wait_event_timeout(atbm_uint32* pulSemId, atbm_uint32 ulTimeout)
{
    return MMPF_OS_AcquireSem(*pulSemId, ulTimeout);
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
atbm_uint8 atbm_os_wakeup_event(atbm_uint32 * pulSemId)
{
    return MMPF_OS_ReleaseSem(*pulSemId);
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_QuerySem
//  Description :
//------------------------------------------------------------------------------
/** @brief This function obtains count about a semaphore

@param[in] ulSemId : The semaphore ID that return by @ref atbm_os_CreateSem 
@param[out] usCount : The count of the ulSemId
@retval 0xFE for bad input semaphore id,
		0xFF for query semaphore internal error from OS
		0 for no error
*/
atbm_uint8 atbm_os_QuerySem(atbm_uint32 ulSemId, atbm_uint16 *usCount)
{
    return MMPF_OS_QuerySem(ulSemId, (atbm_uint16*)usCount);
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
atbm_uint32 atbm_os_mutexLockInit(atbm_uint32 * pmutex_id)
{
	atbm_uint8	ubPriority = 0;
	//atbm_uint32 	mutex_id = 0;
	*pmutex_id = MMPF_OS_CreateMutex(ubPriority);
    if(( *pmutex_id!= 0xff)
		&&( *pmutex_id != 0xfe))
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

atbm_uint8 atbm_os_DeleteMutex(atbm_uint32 ulMutexId)
{
    return MMPF_OS_DeleteMutex(ulMutexId);
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

atbm_uint8 atbm_os_mutexLock(atbm_uint32 ulMutexId, atbm_uint32 ulTimeout)
{
    return MMPF_OS_AcquireMutex(ulMutexId, ulTimeout);
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
atbm_uint8 atbm_os_mutexUnLock(atbm_uint32 ulMutexId)
{
    return MMPF_OS_ReleaseMutex(ulMutexId);
}

