#ifndef ATBM_OS_TIMER_H
#define ATBM_OS_TIMER_H

#define TIMER_1ST_PARAM

typedef atbm_void (*TIMER_CALLBACK)(atbm_void * CallRef);

struct OS_TIMER_S
{
    atbm_uint32          TimerId;
    TIMER_CALLBACK  pCallback;
    atbm_void *          pCallRef;
	atbm_int8 *         pTimerName;
	atbm_uint32			TimerHander;
	int 			bTimerStart;
	struct OS_TIMER_S *hnext;
};


typedef struct OS_TIMER_S OS_TIMER;
#define	atbm_InitTimer(_pTimer,_pCallback,_CallRef)	\
	do{				\
		(_pTimer)->pTimerName = #_pCallback;	\
		atbm_akInitTimer(_pTimer,_pCallback,_CallRef);	\
	}while(0)
PUBLIC int   atbm_akInitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef);
PUBLIC int  atbm_StartTimer(OS_TIMER *pTimer, int Interval/*ms*/);
PUBLIC int atbm_CancelTimer(OS_TIMER *pTimer);
PUBLIC atbm_void atbm_FreeTimer(OS_TIMER *pTimer);
PUBLIC atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond);

PUBLIC unsigned int atbm_GetOsTimeMs();
PUBLIC unsigned int atbm_GetOsTime();

ATBM_BOOL atbm_TimeAfter(atbm_uint32 tickMs);
#define atbm_mdelay atbm_SleepMs
atbm_void atbm_wifi_ticks_timer_init(atbm_void);
#endif /* ATBM_OS_TIMER_H */
