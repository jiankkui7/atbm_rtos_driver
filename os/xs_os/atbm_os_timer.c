#include <freertos/FreeRTOS.h>
#include <freertos/timers.h>
#include <xs/list.h>
#include "atbm_hal.h"

void _atbm_timer_handler(TimerHandle_t xTimer)
{
	OS_TIMER *pTimer;

	pTimer = (OS_TIMER *)pvTimerGetTimerID(xTimer);
	if(pTimer->pCallback)
		pTimer->pCallback(pTimer->pCallRef);
}


PUBLIC int   atbm_InitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef)
{
	if (pTimer == NULL) {
		wifi_printk(WIFI_ALWAYS,"null timer\n");
		return -1;
	}
	if (pTimer->TimerHander != NULL) {
		wifi_printk(WIFI_ALWAYS,"timer already exist\n");
		return 0;
	}

	pTimer->pCallback = pCallback;
	pTimer->pCallRef = CallRef;
	pTimer->bTimerStart =0;
	/*Set timer initial value 100ms. change it in atbm_StartTimer*/
	pTimer->TimerHander = (atbm_uint32)xTimerCreate("atbm", 1000 / portTICK_PERIOD_MS,
					pdFALSE, (void * const)pTimer, _atbm_timer_handler);

	return 0;
}

PUBLIC int  atbm_StartTimer(OS_TIMER *pTimer, int Interval/*ms*/)
{
	if (pTimer == NULL) {
		wifi_printk(WIFI_ALWAYS,"null timer\n");
		return -1;
	}
	if (pTimer->bTimerStart == 1) {
		wifi_printk(WIFI_ALWAYS,"timer already start\n");
		return 0;
	}


	/*xTimerChangePeriod will case timer start too */
	if (xTimerChangePeriod((TimerHandle_t)pTimer->TimerHander,
		Interval / portTICK_PERIOD_MS, 100 / portTICK_PERIOD_MS) == pdPASS) {
		/*The command was successfully sent.*/
		pTimer->bTimerStart =1;
		return 0;
	} else {
		/*TODO: Take appropriate action here.*/
		return -1;
	}
}

PUBLIC int atbm_CancelTimer(OS_TIMER *pTimer)
{
	if (pTimer == NULL) {
		wifi_printk(WIFI_ALWAYS,"null timer\n");
		return -1;
	}

	if (pTimer->bTimerStart == 1) {
		/*TODO:assert return value*/
		xTimerStop((TimerHandle_t)pTimer->TimerHander, 100 / portTICK_PERIOD_MS);
		pTimer->bTimerStart =0;
	}

	return 0;
}
PUBLIC atbm_void atbm_FreeTimer(OS_TIMER *pTimer)
{
	if (pTimer == NULL) {
		wifi_printk(WIFI_ALWAYS,"null timer\n");
		return -1;
	}

	if(pTimer->bTimerStart !=0){
		pTimer->bTimerStart = 0;
		/*TODO:assert return value*/
		xTimerStop((TimerHandle_t)pTimer->TimerHander, 100 / portTICK_PERIOD_MS);
	}
	/*TODO:assert return value*/
	xTimerDelete((TimerHandle_t)pTimer->TimerHander, 100 / portTICK_PERIOD_MS);
	pTimer->TimerHander = (atbm_uint32)ATBM_NULL;
}
PUBLIC atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond)
{
	vTaskDelay(uiMiliSecond / portTICK_PERIOD_MS);
}

unsigned int atbm_GetOsTimeMs(void)
{
	unsigned int ticks = (unsigned int)xTaskGetTickCount();
	return ticks * portTICK_PERIOD_MS;
}

unsigned int atbm_GetOsTime(void)
{
//
//	MMP_ULONG		time;
//	MMPF_OS_GetTime(&time);
//	time = _GetTime();
	//return os_time_get();
	return (unsigned int)xTaskGetTickCount();
}

ATBM_BOOL atbm_TimeAfter(atbm_uint32 tickMs)
{
	atbm_uint32 current_time = atbm_GetOsTimeMs();

	return ((signed int)current_time - (signed int)tickMs < 0);

}

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
	//wifi_printk(WIFI_DBG_ERROR,"atbm_wifi_ticks_timer:ticks(%d),tick_start(%d)\r\n",atbm_wifi_ticks,atbm_wifi_tick_start_tick);
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

atbm_void atbm_mdelay(atbm_uint32 ms)
{
	vTaskDelay(ms/portTICK_PERIOD_MS);
}
