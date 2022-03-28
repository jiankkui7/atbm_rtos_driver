#include "atbm_os_workqueue.h"
#include "typedef.h"
#if (PLATFORM==JIANRONG_RTOS_3268)
#include "type.h"
#include "os/freeRTOS/kernel/inc/FreeRTOS.h"
#include "os/freeRTOS/kernel/inc/queue.h"
#else
#include "arch.h"
#include "os/freeRTOS/inc/FreeRTOS.h"
#include "os/freeRTOS/inc/queue.h"

#endif
const atbm_uint32 NullMessage;//½â¾ö¿ÕÖ¸ÕëÍ¶µÝµÄÎÊÌâ


atbm_uint32 work_queue_table_mux;
atbm_uint8 atbm_os_GetMessage(atbm_uint32 ulMQId, atbm_void **msg, atbm_uint32 ulTimeout)
{
	long ret = 0;
	void *Data = NULL;

	if(ulTimeout == 0) {
		if(xQueueReceive( ulMQId, &Data, 0UL ) !=  pdTRUE) {
			printf("[%s] [%d]the queue is empety\n", __func__, __LINE__);
			ret = -1;
		}
	} else if (ulTimeout == portMAX_DELAY) {
		if(xQueueReceive( ulMQId, &Data, portMAX_DELAY ) !=  pdTRUE) {
			printf("[%s] [%d]the queue is empety\n", __func__, __LINE__);
			ret = -1;
		}
	} else {
		if(xQueueReceive( ulMQId, &Data, ulTimeout/ portTICK_PERIOD_MS ) !=  pdTRUE) {
			printf("[%s] [%d]the queue is empety\n", __func__, __LINE__);
			ret = -1;
		}
	}
	if (Data != NULL)		
	{
        if (Data == (void*)&NullMessage)
        {
            *msg = NULL;
        }
        else
        {
            *msg = Data;
        }
	} else {
		//ulReturn = SYS_ARCH_TIMEOUT;
		//printf("%s, fetch the mbox msg is null\n",__func__);
	}

	return ret;

}
atbm_uint8 atbm_os_PutMessage(atbm_uint32 ulMQId, atbm_void *msg)
{
    long ret = 0;
	unsigned long ticks;
	//if(msec == 0)
	//	ticks = 0UL ;
	//else {
	//	ticks = msec/ portTICK_PERIOD_MS;
	//}
	ticks = 0;
    if (msg == NULL) {
		//printf("%s,%d\n", __func__, __LINE__);	
    	msg = (void*)&NullMessage;//½â¾ö¿ÕÖ¸ÕëÍ¶µÝµÄÎÊÌâ
    }

	if( xQueueSend(ulMQId, &msg, ticks) != pdPASS ) {
		ret = -1;
		printf("[%s][%d] msg queue put fail  \n",__func__,__LINE__);
	}
	return ret;    
}
atbm_uint8 atbm_os_DeleteMQueue(atbm_uint32 ulMQId)
{
	unsigned long ulMessagesWaiting;

	ulMessagesWaiting = uxQueueMessagesWaiting(ulMQId);
	configASSERT( ( ulMessagesWaiting == 0 ) );//?

#if SYS_STATS
	{
		if( ulMessagesWaiting != 0UL )
		{
			/**/
		}
	}
#endif /* SYS_STATS */

	vQueueDelete(ulMQId);   
}
