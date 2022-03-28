
/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/
#include "atbm_hal.h"

atbm_void atbm_os_init_waitevent(atbm_os_wait_queue_head_t* pulSemId)
{
	sema_init(pulSemId,0);
}
atbm_uint8 atbm_os_delete_waitevent(atbm_os_wait_queue_head_t* pulSemId)
{
	//Need Fixed
	return 0;
}