#ifndef ATBM_OS_TIMER_H
#define ATBM_OS_TIMER_H

#define TIMER_1ST_PARAM

struct OS_TIMER_S
{
    atbm_uint32          TimerId;
    TIMER_CALLBACK  Callback;
    atbm_void *          CallRef;
	atbm_uint32			TimerHander;
};

typedef atbm_void (*TIMER_CALLBACK)(atbm_void * CallRef);
typedef struct OS_TIMER_S OS_TIMER;

PUBLIC int   atbm_InitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef);
PUBLIC int  atbm_StartTimer(OS_TIMER *pTimer, int Interval/*ms*/);
PUBLIC int atbm_CancelTimer(OS_TIMER *pTimer);
PUBLIC atbm_void atbm_FreeTimer(OS_TIMER *pTimer);
PUBLIC atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond);
unsigned int atbm_GetOsTime(void);


	  
#endif /* ATBM_OS_TIMER_H */
