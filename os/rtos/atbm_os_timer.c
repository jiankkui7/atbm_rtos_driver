#include "atbm_os_timer.h"

/**************************************************************************
**
** NAME         atbm_os_InitTimer
**
** PARAMETERS:  OS_TIMER *  pTimer          A timer object
**
**              TIMER_CALLBACK pCallback       The callback to call at the
**                                          specified time.
**
** RETURNS:     None.
**
** DESCRIPTION  Initialise a timer object.
**
**************************************************************************/
PUBLIC int   atbm_InitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef)
{
    pTimer->Callback = pCallback;
    pTimer->CallRef = CallRef;
	return 0;
}


/**************************************************************************
**
** NAME         atbm_os_StartTimer
**
** PARAMETERS:  OS_TIMER *  pTimer          A timer object
**
**              uint32  Interval            The time at which to callback.
**                                          The value is expressed in us.
**
** RETURNS:     if error return -1, else if ok return 0;.
**
** DESCRIPTION  Schedules a callback at a specified time. The time
**              granularity is us.
**
**************************************************************************/
PUBLIC int  atbm_StartTimer(OS_TIMER *pTimer, int Interval)
{
	pTimer->TimerHander = MMPF_OS_StartTimer(Interval,MMPF_OS_TMR_OPT_PERIODIC,(MMPF_OS_TMR_CALLBACK)pTimer->Callback, pTimer->CallRef);
	if (pTimer->TimerHander >= MMPF_OS_TMRID_MAX) 
	{
		return -1;
	}
	return 0;
}




/**************************************************************************
**
** NAME         atbm_CancelTimer
**
** PARAMETERS:  OS_TIMER *  pTimer          A timer object.
**
** RETURNS:     if OK return 0; else return others;
**
** DESCRIPTION  Cancels a previously scheduled callback.
**
**************************************************************************/
PUBLIC int atbm_CancelTimer(OS_TIMER *pTimer)
{
	return MMPF_OS_StopTimer(pTimer->TimerHander, MMPF_OS_TMR_OPT_NONE);
}


PUBLIC atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond)
{
    UINT16 usDelay;

    while (uiMiliSecond > 0)
    {
        usDelay = (uiMiliSecond < 5000) ? uiMiliSecond : 5000;
        MMPF_OS_SleepMS(usDelay);
        uiMiliSecond -= usDelay;
    }
}


