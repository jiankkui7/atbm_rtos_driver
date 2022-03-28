#include "atbm_os_timer.h"
#include "atbm_hal.h"
#include "fh_os.h"
static inline unsigned long os_msec_to_ticks(unsigned long msecs)
{
	return ((msecs) * (RT_TICK_PER_SECOND)) / 1000;
}
static inline unsigned long os_ticks_to_msec(unsigned long ticks)
{
	return ((ticks) * 1000) / (RT_TICK_PER_SECOND);
}

atbm_uint32  atbm_InitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef)
{
	atbm_uint8 flag;
	flag=RT_TIMER_FLAG_DEACTIVATED;
	flag |= RT_TIMER_FLAG_ONE_SHOT;
	flag|=RT_TIMER_FLAG_SOFT_TIMER;
	//os_msec_to_ticks(10) timer is right???
    *pTimer = rt_timer_create("AtbmTimer", pCallback, CallRef, os_msec_to_ticks(10), flag);
    if(*pTimer == (OS_TIMER)NULL){
	    return OS_FAIL;
    }else{
	    return OS_SUCCESS;
    }
}
/**************************************************************************/
atbm_uint32  atbm_StartTimer(OS_TIMER *pTimer, atbm_uint32 Interval)
{
	atbm_uint32 result;
	atbm_uint32 ticks;
    ticks = os_msec_to_ticks(Interval);
	//change time
    result=rt_timer_control(*pTimer, RT_TIMER_CTRL_SET_TIME, &ticks);
    if (result == RT_EOK){
    }else{
        return OS_FAIL;
    }
	//start time
    result = rt_timer_start(*pTimer);
    if (result == RT_EOK){
        return OS_SUCCESS;
    }else{
        return OS_FAIL;
    }
}
atbm_uint32 atbm_CancelTimer(OS_TIMER *pTimer)
{
	atbm_uint32 result;
	
    result = rt_timer_stop(*pTimer);
	
    if (result == RT_EOK){
        return OS_SUCCESS;
    }else{
        return OS_FAIL;
    }
}
atbm_uint32 atbm_FreeTimer(OS_TIMER *pTimer)
{
	atbm_uint32 result;
	result = rt_timer_delete(*pTimer);
    if (result == RT_EOK){
        return OS_SUCCESS;
    }else{
        return OS_FAIL;
    }
}
atbm_uint64 atbm_GetOsTimeMs()
{
	unsigned int tick,time;
	tick= rt_tick_get();
	time=os_ticks_to_msec(tick);
	return time;
}
atbm_uint32 atbm_GetOsTime(void)
{
	unsigned int time = rt_tick_get();
	return time;
}

ATBM_BOOL atbm_TimeAfter(atbm_uint32 tickMs)
{
	atbm_uint32 current_time = atbm_GetOsTimeMs();
	
	return ((signed int)((signed int)current_time - (signed int)tickMs < 0));
		
}
atbm_void atbm_wifi_ticks_timer_init(atbm_void)
{
}
atbm_void atbm_delay(atbm_uint32 ms){
	otgudelay(ms);
}
