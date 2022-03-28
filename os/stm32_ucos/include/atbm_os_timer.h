#ifndef ATBM_OS_TIMER_H
#define ATBM_OS_TIMER_H
/*include os platform*/
#include "timer.h"

#include "atbm_os_api.h"
#define TIMER_1ST_PARAM

typedef atbm_void (*TIMER_CALLBACK)(atbm_void*CallRef);
struct OS_TIMER_S
{
    timer_t          *TimerId;
    TIMER_CALLBACK  Callback;
    atbm_void *          CallRef;
	atbm_uint32			Timer_is_cancled;
	atbm_uint32			Timer_is_peridoc;
	atbm_uint32        Timer_period;
};

typedef atbm_void (*TIMER_CALLBACK)(atbm_void * CallRef);
typedef struct OS_TIMER_S OS_TIMER;

static inline void atbm_InitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef)
{
	pTimer->TimerId=timer_setup(100,0,pCallback,CallRef);
	pTimer->Callback=pCallback;
	pTimer->CallRef=CallRef;
	pTimer->Timer_period=0;
	pTimer->Timer_is_cancled=ATBM_TRUE;
	pTimer->Timer_is_peridoc=ATBM_FALSE;

}
static inline void atbm_StartTimer(OS_TIMER *pTimer, int Interval/*ms*/)
{
	pTimer->Timer_period=Interval;
	mod_timer(pTimer->TimerId,pTimer->Timer_period);
	pTimer->Timer_is_cancled=ATBM_FALSE;
	pTimer->Timer_is_peridoc=ATBM_TRUE;
}
static inline void atbm_CancelTimer(OS_TIMER *pTimer)
{
	del_timer(pTimer->TimerId);
	pTimer->Timer_is_cancled=ATBM_TRUE;
	pTimer->Timer_period=0;

}
static inline atbm_void atbm_FreeTimer(OS_TIMER *pTimer)
{

}
static inline atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond)
{

}
static inline unsigned int atbm_GetOsTime(void)
{
	return 0;
}
static inline atbm_void atbm_wifi_ticks_timer_init(atbm_void)
{
}
#define atbm_TimeAfter(a) ((a) - (10*os_time_get()) >= 0)
#define atbm_GetOsTimeMs() os_time_get() 
#define msecs_to_jiffies(Ms) jiffies
#define msleep sleep
#endif /* ATBM_OS_TIMER_H */
