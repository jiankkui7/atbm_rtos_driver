#include "atbm_hal.h"
#include "atbm_os_timer.h"

//#include "drv_api.h"
#include "wifi.h"
#include "akos_api.h"
//#include "os_malloc.h"
//#include "hal_sysdelay.h"

#define ATBM_TIME_HASH_MAX (8)
#define ATBM_AK_TIME_ALIG	(5)
static struct OS_TIMER_S *atbm_timer_hash[ATBM_TIME_HASH_MAX];
static atbm_mutex hash_lock;
static signed long cur_timeout_id = -1;
static atbm_uint32 set_start_timer = 0;

#define ATBM_AK_TIMEOUT_ALIG(_time)			((_time)+ATBM_AK_TIME_ALIG-((_time)%ATBM_AK_TIME_ALIG))
#define ATBM_AK_TIMEOUT_VAL(__val)			(((__val)%ATBM_AK_TIME_ALIG)== 0 ? (__val):ATBM_AK_TIMEOUT_ALIG(__val))
#define ATBM_AK_TIMER_NO_LOOP				(0)
#define TIMER_HASH(__index)					((__index)&(ATBM_TIME_HASH_MAX-1))

#define HASH_LOCK()							atbm_os_mutexLock(&hash_lock,0)
#define HASH_UNLOCK()						atbm_os_mutexUnLock(&hash_lock)
#define HASH_LOCK_INIT()					atbm_os_mutexLockInit(&hash_lock)
#define TIMER_HASH_GET(__index)				(atbm_timer_hash[__index])
#define TIMER_HASH_SET(__index,__timer)		atbm_timer_hash[__index] = __timer;

#define ATBM_SET_TIMER_IN_START(__start)	(*((volatile atbm_uint32*)(&set_start_timer)) = (atbm_uint32)(__start))
#define ATBM_GET_TIMER_IN_START()			*((volatile atbm_uint32*)(&set_start_timer))
#define ATBM_SET_CUR_ID(__id)				(*((volatile atbm_uint32*)(&cur_timeout_id)) = (atbm_uint32)(__id))
#define ATBM_GET_CUR_ID()					*((volatile atbm_uint32*)(&cur_timeout_id))

#define AKTIMER_DEBUG_LEVEL		WIFI_DBG_MSG
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
static void atbm_timer_hash_add(struct OS_TIMER_S *timer)
{
	unsigned int hash_index = TIMER_HASH(timer->TimerHander);
	timer->hnext = TIMER_HASH_GET(hash_index);
	TIMER_HASH_SET(hash_index,timer);
}

static struct OS_TIMER_S *atbm_timer_hash_get(atbm_uint32 timer_handle)
{
	unsigned int hash_index = TIMER_HASH(timer_handle);
	OS_TIMER *hash_pTimer = TIMER_HASH_GET(hash_index);

	while(hash_pTimer){
		if(hash_pTimer->TimerHander == timer_handle)
			break;
		hash_pTimer = hash_pTimer->hnext;
	}

	return hash_pTimer;
}
static void atbm_timer_hash_del_bytimer(struct OS_TIMER_S *timer)
{
	unsigned int hash_index = TIMER_HASH(timer->TimerHander);
	OS_TIMER *hash_pTimer = TIMER_HASH_GET(hash_index);
	
	wifi_printk(AKTIMER_DEBUG_LEVEL,"atbm_timer_hash_del_bytimer[%s][%d]\n",timer->pTimerName,timer->TimerHander);
	if(hash_pTimer == ATBM_NULL){
		wifi_printk(AKTIMER_DEBUG_LEVEL,"atbm_timer_hash_del_bytimer[%s][%d]hash_pTimer == ATBM_NULL\n",timer->pTimerName,
			timer->TimerHander);
		return;
	}

	if(hash_pTimer == timer){
		TIMER_HASH_SET(hash_index,timer->hnext);
		return;
	}

	while((hash_pTimer->hnext)&&(hash_pTimer->hnext != timer))
		hash_pTimer = hash_pTimer->hnext;

	if(hash_pTimer->hnext)
		hash_pTimer->hnext = timer->hnext;

	timer->hnext = ATBM_NULL;
}

static void atbm_timer_hash_del_byhandle(atbm_uint32 timer_handle)
{
	unsigned int hash_index = TIMER_HASH(timer_handle);
	OS_TIMER *hash_pTimer = atbm_timer_hash_get(timer_handle);
	if(hash_pTimer == ATBM_NULL){
		
		wifi_printk(AKTIMER_DEBUG_LEVEL,"atbm_timer_hash_del %d ERROR,hash_pTimer == ATBM_NULL\n",timer_handle);
		return;
	}

	atbm_timer_hash_del_bytimer(hash_pTimer);
}
PUBLIC int   atbm_akInitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef)
{
    pTimer->pCallback = pCallback;
    pTimer->pCallRef = CallRef;
//	pTimer->TimerHander = MMPF_OS_CREATE_TMR_INT_ERR;
	pTimer->bTimerStart  = 0;
	pTimer->hnext = ATBM_NULL;
	return 0;
}
PUBLIC void  atbm_TimerOutFunc(signed long timer_id, unsigned long delay)
{	
	OS_TIMER *pTimer;

	HASH_LOCK();
	pTimer = atbm_timer_hash_get(timer_id);
	HASH_UNLOCK();
	if(pTimer == ATBM_NULL){
		wifi_printk(AKTIMER_DEBUG_LEVEL,"atbm_TimerOutFunc %d ERROR\n",timer_id);
		if((ATBM_GET_TIMER_IN_START())&&(ATBM_GET_CUR_ID() == -1)){
			ATBM_SET_CUR_ID(timer_id);
		}
		else {
			wifi_printk(AKTIMER_DEBUG_LEVEL,"atbm_TimerOutFunc %d ERROR cur\n",timer_id);
		}
		return;
	}
	
	wifi_printk(AKTIMER_DEBUG_LEVEL,"TimerOutFunc[%s][%d]\n",pTimer->pTimerName,timer_id);
	HASH_LOCK();
	atbm_timer_hash_del_bytimer(pTimer);
	HASH_UNLOCK();
	
	if(pTimer->pCallback)
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
	atbm_uint32 init_ms = 0;
	
	atbm_CancelTimer(pTimer);

	if(Interval == 0){
		if(pTimer->pCallback)
			pTimer->pCallback(pTimer->pCallRef);
		return 0;
	}
	init_ms = ATBM_AK_TIMEOUT_VAL(Interval);
	ATBM_SET_TIMER_IN_START(1);
	pTimer->TimerHander = vtimer_start(init_ms,ATBM_AK_TIMER_NO_LOOP,atbm_TimerOutFunc);
	if (pTimer->TimerHander <0) 
	{
		wifi_printk(AKTIMER_DEBUG_LEVEL,"atbm_StartTimer %d ERROR\n",pTimer->TimerHander );
		return -1;
	}
	//iot_printf("atbm_StartTimer %d\n",pTimer->TimerHander );
	HASH_LOCK();
	pTimer->bTimerStart  = 1;
	atbm_timer_hash_add(pTimer);
	HASH_UNLOCK();
	
	wifi_printk(AKTIMER_DEBUG_LEVEL,"atbm_StartTimer[%s][%d]\n",pTimer->pTimerName,pTimer->TimerHander);
	if(ATBM_GET_CUR_ID() != -1){
		atbm_TimerOutFunc(ATBM_GET_CUR_ID(),0);
		ATBM_SET_CUR_ID(-1);
	}	
	ATBM_SET_TIMER_IN_START(0);
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
	if (pTimer->bTimerStart ==0) 
	{
		return -1;
	}
	HASH_LOCK();
	pTimer->bTimerStart  = 0;
	//iot_printf("atbm_CancelTimer %d\n",pTimer->TimerHander );
	atbm_timer_hash_del_bytimer(pTimer);
	HASH_UNLOCK();
	vtimer_stop(pTimer->TimerHander);
	return 0;
}
PUBLIC atbm_void atbm_FreeTimer(OS_TIMER *pTimer)
{
	if(pTimer->TimerHander != -1){
		atbm_CancelTimer(pTimer);
		pTimer->TimerHander = -1;
	}
}


PUBLIC atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond)
{
    mini_delay(uiMiliSecond);
}

ATBM_BOOL atbm_TimeAtSameRange(atbm_uint32 TimeFi,atbm_uint32 TimeSe)
{
	
}
static atbm_void atbm_get_wifi_tick(atbm_uint32 *start_tick,atbm_uint32 *ticks)
{
	
}

static atbm_void atbm_update_wifi_ticks(atbm_uint32 start_tick)
{
	
}
unsigned int atbm_GetOsTimeMs()
{
	unsigned int time = get_tick_count();
	return time;
}

unsigned int atbm_GetOsTime(void)
{
	unsigned int time = get_tick_count();
	return time;
}
int os_time_get(void){
	return 	atbm_GetOsTime();
}
ATBM_BOOL atbm_TimeAfter(atbm_uint32 tickMs)
{
	atbm_uint32 current_time = atbm_GetOsTimeMs();
	
	return ((signed int)((signed int)current_time - (signed int)tickMs < 0));
		
}

static atbm_void atbm_wifi_ticks_timer(unsigned long arg)
{
	
}

atbm_void atbm_wifi_ticks_timer_init(atbm_void)
{
	HASH_LOCK_INIT();
	memset(atbm_timer_hash,0,sizeof(atbm_timer_hash));
}
atbm_void atbm_wifi_ticks_timer_cancle(atbm_void)
{
	
}
