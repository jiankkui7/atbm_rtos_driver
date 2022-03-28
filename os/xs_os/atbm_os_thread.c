#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "atbm_hal.h"
#include "atbm_os_thread.h"

atbm_void * atbm_createThread(atbm_void(*task)(atbm_void *p_arg),atbm_void *p_arg,int prio)
{
	BaseType_t ret;
	TaskHandle_t handle;

	ret = xTaskCreate(task, "wifi", 1024, p_arg, portPRI_TASK_NORMAL, &handle);

	if(ret == pdPASS)
		return handle;
	else
		return NULL;

}


int atbm_stopThread(atbm_void * thread_id)
{	
	vTaskDelete(thread_id);

	return 0;
}

int atbm_ThreadStopEvent(pAtbm_thread_t thread_id)
{
	//Not used
	return 0;
}
