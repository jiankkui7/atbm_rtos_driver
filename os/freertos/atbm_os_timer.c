#include "atbm_hal.h"
#include "os_api.h"


PUBLIC int   atbm_InitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef)
{
	pTimer->pCallback = pCallback;
	pTimer->pCallRef = CallRef;
	pTimer->TimerHander = 0;
	pTimer->bTimerStart =0;

}
PUBLIC int  atbm_TimerOutFunc(atbm_void *arg)
{	
	OS_TIMER *pTimer = pvTimerGetTimerID(arg);
	pTimer->pCallback(pTimer->pCallRef);
}
PUBLIC int  atbm_StartTimer(OS_TIMER *pTimer, int Interval/*ms*/)
{
	if(pTimer->TimerHander){
		atbm_CancelTimer(pTimer);
	}
	pTimer->TimerHander = (atbm_uint32)timer_setup(Interval,0,atbm_TimerOutFunc,pTimer);	
	mod_timer(pTimer->TimerHander, Interval+jiffies);
	pTimer->bTimerStart =1;
	return 1;
}
PUBLIC int atbm_CancelTimer(OS_TIMER *pTimer)
{
	pTimer->bTimerStart =0;
	del_timer(pTimer->TimerHander);
}
PUBLIC atbm_void atbm_FreeTimer(OS_TIMER *pTimer)
{
	if(pTimer->bTimerStart !=0){
		pTimer->bTimerStart = 0;
		del_timer(pTimer->TimerHander);
	}
	timer_free(pTimer->TimerHander);
	pTimer->TimerHander = ATBM_NULL;
}
PUBLIC atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond)
{
	atbm_mdelay(uiMiliSecond);
}

unsigned int atbm_GetOsTime(void)
{
//
//	MMP_ULONG		time;
//	MMPF_OS_GetTime(&time);
//	time = _GetTime();
	//return os_time_get();
	return OS_TickTime();//system tick
}
/*
ATBM_BOOL atbm_TimeAfter(atbm_uint32 tickMs)
{
	atbm_uint32 current_time = atbm_GetOsTimeMs();
	
	return ((signed int)current_time - (signed int)tickMs < 0);
		
}*/

//#define ATBM_RK_OS_MAX_MS (0xFFFFFFFF/24000)
//#define ATBM_RK_OS_MAX_DELTA_MS (ATBM_RK_OS_MAX_MS/2 + 1)
//#define ATBM_RK_OS_TICKS_MS     (65536) 
//#define ATBM_RK_OS_TICKS_MS_DELTA_MAX (0x10000000)
///static OS_TIMER  atbm_wifi_tick;
//static atbm_uint32	atbm_wifi_tick_start_tick;
//static atbm_uint32 atbm_wifi_ticks;

static atbm_void atbm_wifi_ticks_timer(unsigned long arg)
{
	//atbm_update_wifi_ticks(atbm_GetOsTime());
	//wifi_printk(WIFI_DBG_ERROR,"atbm_wifi_ticks_timer:ticks(%d),tick_start(%d)\n",atbm_wifi_ticks,atbm_wifi_tick_start_tick);
	//atbm_StartTimer(&atbm_wifi_tick,ATBM_RK_OS_TICKS_MS);
}

atbm_void atbm_wifi_ticks_timer_init(atbm_void)
{
//	atbm_InitTimer(&atbm_wifi_tick,atbm_wifi_ticks_timer,&atbm_wifi_ticks);
//	atbm_wifi_ticks = 0;
//	atbm_wifi_tick_start_tick = atbm_GetOsTime();
//	atbm_StartTimer(&atbm_wifi_tick,ATBM_RK_OS_TICKS_MS);
}
atbm_void atbm_wifi_ticks_timer_cancle(atbm_void)
{
//	atbm_CancelTimer(&atbm_wifi_tick);
}

