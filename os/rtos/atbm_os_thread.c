#include "atbm_os_thread.h"
#include "atbm_type.h"

/*
------------------------------------------------------------------------------
  Function    : atbm_os_OS_CreateTask
  Description :
------------------------------------------------------------------------------
@brief This function is used to have OS manage the execution of a task.  Tasks can either
              be created prior to the start of multitasking or by a running task.  A task cannot be
              created by an ISR.

@param[in] taskproc : the task function entry pointer
@param[in] task_cfg : pointert to @ref atbm_os_TASK_CFG structure, that deal with stack top/bottom address and task priority.
@param[in] param : input paramter to the taskproc
@retval 0xFE for bad input priority
		0xFF for createtask internal error from OS
		others, return the priority of the task.
*/
atbm_uint32 atbm_os_createTask(atbm_void (*taskproc)(atbm_void *param), atbm_os_thread_t *thread, atbm_void *param);
{
	int ret;
    ret=MMPF_OS_CreateTask(taskproc, (MMPF_TASK_CFG*)thread, (atbm_void *)param);
	return ret;
}
//------------------------------------------------------------------------------
//  Function    : atbm_os_OS_SetTaskName
//  Description :
//------------------------------------------------------------------------------
ATBM_BOOL atbm_os_setTaskName(atbm_uint8 ubNewPriority, atbm_uint8 *pTaskName)
{
    MMP_UBYTE ubRetVal = 0;
    ubRetVal = MMPF_OS_SetTaskName((MMP_UBYTE)ubNewPriority, (MMP_UBYTE *)pTaskName);
    if (ubRetVal != 0) {
        wifi_printk(WIFI_OS,"%s,%d error!\r\n", __FUNCTION__, __LINE__);
        return atbm_os_FALSE;
    }
    return atbm_os_TRUE;
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_OS_StartTask
//  Description :
//------------------------------------------------------------------------------
/** @brief To start the OS multi-task working.

@return None.
*/
atbm_void atbm_os_startTask(atbm_void)
{
    MMPF_OS_StartTask();
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_OS_ChangeTaskPriority
//  Description :
//------------------------------------------------------------------------------
atbm_uint8 atbm_os_changeTaskPri(atbm_uint8 ubold_pri, atbm_uint8 ubnew_pri)
{
    return MMPF_OS_ChangeTaskPriority((MMPF_OS_TASKID) ubold_pri, (MMP_UBYTE) ubnew_pri);
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_OS_DeleteTask
//  Description :
//------------------------------------------------------------------------------
/** @brief This function allows you to delete a task.  The calling task can delete itself by its own priority number.  
           The deleted task is returned to the dormant state and can be re-activated by creating the deleted task again.

@param[in] taskid : is the task ID to delete.  Note that you can explicitely delete the current task without knowing its 
					priority level by setting taskid to 0xFF.
@retval 0xFE for bad input task id,
		0xFF for deltask internal error from OS
		0, return delete success.
*/
atbm_uint8 atbm_os_delTask(atbm_uint8 taskid)
{
    return MMPF_OS_DeleteTask(taskid);
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_OS_SuspendTask
//  Description :
//------------------------------------------------------------------------------
/** @brief This function allows you to suspend a task dynamically.

@param[in] taskid : the task ID that return by @ref atbm_os_OS_CreateTask 
@retval 0xFE for bad input task id,
		0xFF for suspend task internal error from OS
		0, return suspend success.
*/
atbm_uint8 atbm_os_suspendTask(atbm_uint8 taskid)
{
    return MMPF_OS_SuspendTask(taskid);
}

//------------------------------------------------------------------------------
//  Function    : atbm_os_OS_ResumeTask
//  Description :
//------------------------------------------------------------------------------
/** @brief This function allows you to resume a suspended task.

@param[in] taskid : the task ID that return by @ref atbm_os_OS_CreateTask 
@retval 0xFE for bad input task id,
		0xFF for resume task internal error from OS
		0, return resume success.
*/
atbm_uint8 atbm_os_resumeTask(atbm_uint8 taskid)
{
    return MMPF_OS_ResumeTask(taskid);
}
atbm_void atbm_os_StartTask(atbm_void)
{
    MMPF_OS_StartTask();
}

int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	//Not used
	return 0;
}


