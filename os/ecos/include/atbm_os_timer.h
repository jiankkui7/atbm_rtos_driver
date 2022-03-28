#ifndef ATBM_OS_TIMER_H
#define ATBM_OS_TIMER_H
#include <cyg/kernel/kapi.h>


//typedef void (*TIMER_CALLBACK)(void * CallRef);
typedef atbm_void (TIMER_CALLBACK) (cyg_handle_t alarm, cyg_addrword_t data);
#define TIMER_1ST_PARAM cyg_handle_t alarm,
//struct OS_TIMER_S
//{
//    uint32          TimerId;
//    TIMER_CALLBACK  pCallback;
//    void *          pCallRef;
//	uint32			TimerHander;
//	int 			bTimerStart;
//};
//typedef struct OS_TIMER_S OS_TIMER;
//typedef struct timer_list OS_TIMER;

typedef struct OS_TIMER_S
{
	cyg_handle_t 	counter_hdl;
	cyg_handle_t	alarm_hdl;
	cyg_alarm	alarm_obj;
	ATBM_BOOL	Valid; /* Set to True when call InitTimer */
	atbm_void*		data;
}OS_TIMER;

PUBLIC int   atbm_InitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef);
PUBLIC int  atbm_StartTimer(OS_TIMER *pTimer, int Interval/*ms*/);
PUBLIC int atbm_CancelTimer(OS_TIMER *pTimer);
PUBLIC atbm_void atbm_FreeTimer(OS_TIMER *pTimer);
PUBLIC atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond);
unsigned int atbm_GetOsTime(atbm_void);

//////////////////////////////////////////////////////////////////////////////////////////////////////
	  
#endif /* ATBM_OS_TIMER_H */
