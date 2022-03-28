#include "atbm_hal.h"
#include "atbm_os_timer.h"
#include "rtkos_osl.h"
#if defined(__RTK_OS__)
#include "cam_os_wrapper.h"
#include "halex_timer.h"
#endif

#define ATBM_RK_OS_MAX_MS (0xFFFFFFFF/24000)
#define ATBM_RK_OS_MAX_DELTA_MS (ATBM_RK_OS_MAX_MS/2 + 1)
#define ATBM_RK_OS_TICKS_MS     (65536) 
#define ATBM_RK_OS_TICKS_MS_DELTA_MAX (0x10000000)
static OS_TIMER  atbm_wifi_tick;
static atbm_uint32	atbm_wifi_tick_start_tick;
static atbm_uint32 atbm_wifi_ticks;

#define ATBM_WIFI_SET(_addr,_val)   (*((volatile atbm_uint32*)(_addr)) = (atbm_uint32)(_val))
#define ATBM_WIFI_GET(_addr)           (*((volatile atbm_uint32*)(_addr)))

#define ATBM_WIFI_SET_TICKS(_ticks)	ATBM_WIFI_SET(&atbm_wifi_ticks,_ticks)
#define ATBM_WIFI_SET_START_TICKS(_start_ticks)	ATBM_WIFI_SET(&atbm_wifi_tick_start_tick,_start_ticks)

#define ATBM_WIFI_GET_TICKS()	        ATBM_WIFI_GET(&atbm_wifi_ticks)
#define ATBM_WIFI_GET_START_TICKS()  	ATBM_WIFI_GET(&atbm_wifi_tick_start_tick)

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
    pTimer->pCallback = pCallback;
    pTimer->pCallRef = CallRef;
	pTimer->TimerHander = MMPF_OS_CREATE_TMR_INT_ERR;
	pTimer->bTimerStart  = 0;
	return 0;
}
PUBLIC int  atbm_TimerOutFunc(MsTimerId_e eTimerID, atbm_uint32 UserData)
{	
	OS_TIMER *pTimer = (OS_TIMER *)UserData;
	//iot_printf("atbm_TimerOutFunc  pTimer %x\n",pTimer);
	pTimer->pCallback(pTimer->pCallRef);
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
	atbm_uint32 init_ticks = OSL_MSEC_TO_TICKS(Interval);
	atbm_CancelTimer(pTimer);
	pTimer->TimerHander = MMPF_OS_StartTimer(init_ticks,MMPF_OS_TMR_OPT_ONE_SHOT,(MMPF_OS_TMR_CALLBACK)atbm_TimerOutFunc,pTimer);
	if (pTimer->TimerHander == MMPF_OS_CREATE_TMR_INT_ERR) 
	{
		wifi_printk(WIFI_ALWAYS,"atbm_StartTimer %d ERROR\n",pTimer->TimerHander );
		return -1;
	}
	//iot_printf("atbm_StartTimer %d\n",pTimer->TimerHander );
	pTimer->bTimerStart  = 1;
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
	if (pTimer->TimerHander == MMPF_OS_CREATE_TMR_INT_ERR) 
	{
		return -1;
	}
	if (pTimer->bTimerStart ==0) 
	{
		return -1;
	}
	pTimer->bTimerStart  = 0;
	//iot_printf("atbm_CancelTimer %d\n",pTimer->TimerHander );
	return MMPF_OS_StopTimer(pTimer->TimerHander, MMPF_OS_TMR_OPT_NONE);
}
PUBLIC atbm_void atbm_FreeTimer(OS_TIMER *pTimer)
{
	if(pTimer->TimerHander != MMPF_OS_CREATE_TMR_INT_ERR){
		atbm_CancelTimer(pTimer);
		pTimer->TimerHander = MMPF_OS_CREATE_TMR_INT_ERR;
	}
}


PUBLIC atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond)
{
    UINT16 usDelay;

    while (uiMiliSecond > 0)
    {
        usDelay = (uiMiliSecond < 5000) ? uiMiliSecond : 5000;
        //MMPF_OS_SleepMS(usDelay);
		AHC_OS_SleepMs(usDelay);
        uiMiliSecond -= usDelay;
    }
}

ATBM_BOOL atbm_TimeAtSameRange(atbm_uint32 TimeFi,atbm_uint32 TimeSe)
{
	atbm_uint32 delta_time;

	delta_time = TimeFi>TimeSe ? (TimeFi - TimeSe):(TimeSe-TimeFi);

	return (delta_time<ATBM_RK_OS_MAX_DELTA_MS);
}
static atbm_void atbm_get_wifi_tick(atbm_uint32 *start_tick,atbm_uint32 *ticks)
{
	ATBM_OS_CPU_SR cpu_sr = atbm_local_irq_save();
	*start_tick = ATBM_WIFI_GET_START_TICKS();
	*ticks = ATBM_WIFI_GET_TICKS();
	atbm_local_irq_restore(cpu_sr);
}

static atbm_void atbm_update_wifi_ticks(atbm_uint32 start_tick)
{
	atbm_uint32 ticks;
	atbm_uint32 prev_start_tick;
	atbm_uint32 duration;
	ATBM_OS_CPU_SR cpu_sr = atbm_local_irq_save();
	prev_start_tick = ATBM_WIFI_GET_START_TICKS();
	duration = start_tick>prev_start_tick ? (start_tick-prev_start_tick):
											(start_tick+ATBM_RK_OS_MAX_MS-prev_start_tick);
	ATBM_WIFI_SET_START_TICKS(start_tick);
	ticks = ATBM_WIFI_GET_TICKS();
	ticks += duration; 
	ATBM_WIFI_SET_TICKS(ticks);
	atbm_local_irq_restore(cpu_sr);
}
unsigned int atbm_GetOsTimeMs()
{
	MMP_ULONG	ms_ago;
	MMP_ULONG	ms_cur;
	MMP_ULONG   start_tick;
	MMP_ULONG	ticks;
	
	atbm_get_wifi_tick(&start_tick,&ticks);
	ms_cur = atbm_GetOsTime();
	if(!atbm_TimeAtSameRange(ms_cur,start_tick)){
		ATBM_WARN_ON_FUNC(!(ms_cur<=start_tick));
		ms_cur += ATBM_RK_OS_MAX_MS;
		ATBM_WARN_ON_FUNC(!(ms_cur>=ATBM_RK_OS_MAX_MS));
	}
	ms_ago = ms_cur-start_tick;
	return ticks + ms_ago;
}
unsigned int atbm_GetOsTime(void)
{
	MMP_ULONG		time;
	MMPF_OS_GetTime(&time);
//	time = _GetTime();
	return time;
}

ATBM_BOOL atbm_TimeAfter(atbm_uint32 tickMs)
{
	atbm_uint32 current_time = atbm_GetOsTimeMs();
	
	return ((signed int)current_time - (signed int)tickMs < 0);
		
}

static atbm_void atbm_wifi_ticks_timer(unsigned long arg)
{
	atbm_update_wifi_ticks(atbm_GetOsTime());
	wifi_printk(WIFI_DBG_ERROR,"atbm_wifi_ticks_timer:ticks(%d),tick_start(%d)\n",atbm_wifi_ticks,atbm_wifi_tick_start_tick);
	atbm_StartTimer(&atbm_wifi_tick,ATBM_RK_OS_TICKS_MS);
}

atbm_void atbm_wifi_ticks_timer_init(atbm_void)
{
	atbm_InitTimer(&atbm_wifi_tick,atbm_wifi_ticks_timer,&atbm_wifi_ticks);
	atbm_wifi_ticks = 0;
	atbm_wifi_tick_start_tick = atbm_GetOsTime();
	atbm_StartTimer(&atbm_wifi_tick,ATBM_RK_OS_TICKS_MS);
}
atbm_void atbm_wifi_ticks_timer_cancle(atbm_void)
{
	atbm_CancelTimer(&atbm_wifi_tick);
}
