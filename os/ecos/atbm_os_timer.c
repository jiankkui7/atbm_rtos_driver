#include "atbm_hal.h"
//#include "os_api.h"
#include <cyg/kernel/kapi.h>


PUBLIC int   atbm_InitTimer(OS_TIMER *pTimer, TIMER_CALLBACK pCallback, atbm_void * CallRef)
{
	int ret;
	
	if (!pTimer->Valid)
	{	
		cyg_clock_to_counter(cyg_real_time_clock(), &pTimer->counter_hdl);
		pTimer->data = CallRef;
		wifi_printk(WIFI_DBG_MSG,"atbm: atbm_InitTimer(), data=0x%x\n", pTimer->data);
		cyg_alarm_create(pTimer->counter_hdl,
						pCallback,
						(cyg_addrword_t) pTimer->data,
						&pTimer->alarm_hdl,
						&pTimer->alarm_obj);		
		wifi_printk(WIFI_DBG_MSG,"atbm: atbm_InitTimer(), alarm_obj=0x%x, 0x%x\n", pTimer->alarm_obj, &pTimer->alarm_obj);

		if (!pTimer->alarm_hdl)
		{
			wifi_printk(WIFI_DBG_ERROR, "error: timer init failed.\n");
			ret = WIFI_ERROR; //failed
		}else{
			pTimer->Valid = ATBM_TRUE;
			ret = WIFI_OK; //success
		}
	}

	return ret;
}
//PUBLIC int  atbm_TimerOutFunc(void *arg)
//{	
//	OS_TIMER *pTimer = pvTimerGetTimerID(arg);
//	pTimer->pCallback(pTimer->pCallRef);
//}
PUBLIC int  atbm_StartTimer(OS_TIMER *pTimer, int Interval/*ms*/)
{

	int ret;
	wifi_printk(WIFI_DBG_MSG, "atbm: atbm_StartTimer()====>\n");
	if ((pTimer->Valid) && (pTimer->alarm_hdl))
	{
		cyg_alarm_disable(pTimer->alarm_hdl);
		Interval = (Interval * HZ) / 1000;
		Interval = (Interval == 0) ? 1 : Interval;

		if (Interval > 0) {
			cyg_alarm_initialize(pTimer->alarm_hdl, cyg_current_time() + Interval, 0);
			cyg_alarm_enable(pTimer->alarm_hdl);
			ret = WIFI_OK; //success
		}
	} else {
		wifi_printk(WIFI_DBG_ERROR, "error: timer start failed.\n");
		ret = WIFI_ERROR;
	} /* End of if */
	wifi_printk(WIFI_DBG_MSG, "atbm: atbm_StartTimer()<====\n");
	return ret;
}


PUBLIC int atbm_CancelTimer(OS_TIMER *pTimer)
{
	int ret;
	wifi_printk(WIFI_DBG_MSG, "atbm: atbm_CancelTimer()====>\n");
	if ((pTimer->Valid) && (pTimer->alarm_hdl))
	{
		cyg_alarm_disable(pTimer->alarm_hdl);
		ret = WIFI_OK;
	} else {
		wifi_printk(WIFI_DBG_ERROR, "error: timer cancel failed.\n");
		ret = WIFI_ERROR;
	} /* End of if */   

	wifi_printk(WIFI_DBG_MSG, "atbm: atbm_CancelTimer()<====\n");
	return ret;

}
PUBLIC atbm_void atbm_FreeTimer(OS_TIMER *pTimer)
{
	wifi_printk(WIFI_DBG_MSG, "atbm: atbm_FreeTimer()====>\n");
	if ((pTimer->Valid) && (pTimer->alarm_hdl))
	{
		cyg_alarm_disable(pTimer->alarm_hdl);
	} else {
		wifi_printk(WIFI_DBG_ERROR, "error: timer free failed.\n");
	} /* End of if */   
	wifi_printk(WIFI_DBG_MSG, "atbm: atbm_FreeTimer()<====\n");
	return;
}
PUBLIC atbm_void atbm_SleepMs(atbm_uint32 uiMiliSecond)
{
	//atbm_mdelay(uiMiliSecond);
	cyg_thread_delay(uiMiliSecond/10);//per tick is 10ms
}


unsigned int atbm_GetOsTime(atbm_void)
{
//
//	MMP_ULONG		time;
//	MMPF_OS_GetTime(&time);
//	time = _GetTime();
//	return os_time_get();
	return cyg_current_time();//system tick
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

static atbm_void atbm_wifi_ticks_timer(TIMER_1ST_PARAM unsigned long arg)
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

