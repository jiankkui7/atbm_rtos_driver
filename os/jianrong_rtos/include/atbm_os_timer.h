#ifndef ATBM_OS_TIMER_H
#define ATBM_OS_TIMER_H

#define TIMER_1ST_PARAM
typedef xTIMER T_hTimer;

typedef enum  {
	osTimerOnce	= 0,       ///< one-shot timer
	osTimerPeriodic	= 1        ///< repeating timer
} os_timer_type;


typedef atbm_void (*TIMER_CALLBACK)(atbm_void * CallRef);
typedef void (*timer_handler_t)(void *arg);

#if 0
struct OS_TIMER_S
{
    atbm_uint32          TimerId;
    TIMER_CALLBACK  pCallback;
    atbm_void *          pCallRef;
	atbm_uint32			TimerHander;
	int 			bTimerStart;
};
#endif

struct OS_TIMER_S {
	T_hTimer *handle;
	int flag;
	os_timer_type type;
	timer_handler_t func;
	unsigned long time_ms;
	void *arg;
};



typedef struct OS_TIMER_S OS_TIMER;
#define	atbm_InitTimer(_pTimer,_pCallback,_CallRef)	\
	do{				\
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
#define atbm_mdelay(x) atbm_SleepMs(x)
atbm_void atbm_wifi_ticks_timer_init(atbm_void);
#endif /* ATBM_OS_TIMER_H */
