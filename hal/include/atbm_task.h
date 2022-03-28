/**************************************************************************************************************
 * altobeam RTOS
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#ifndef __ATBM_WORK_QUEUE_
#define __ATBM_WORK_QUEUE_

#define atbm_work int
struct atbm_work_struct {
	atbm_void *  param;
};

int atbm_init_task_work(struct atbmwifi_common *hw_priv);

atbm_work atbm_init_work(struct atbmwifi_common *hw_priv,atbm_void *fun, atbm_void *data);
atbm_void atbm_queue_work(struct atbmwifi_common *hw_priv,atbm_work workid);
int atbm_bh_schedule_rx(struct atbmwifi_common *hw_priv);
void atbm_bh_schedule_tx(struct atbmwifi_common *hw_priv);
atbm_void atbm_unregister_bh(struct atbmwifi_common *hw_priv);
int atbm_register_bh(struct atbmwifi_common *hw_priv);
atbm_void atbm_bh_wakeup(struct atbmwifi_common *hw_priv);
#define atbm_bh_is_term(a) ((a)->bh_term)
int atbm_destory_task_work(struct atbmwifi_common *hw_priv);
int __atbm_flush(struct atbmwifi_common *hw_priv, ATBM_BOOL drop, int if_id);
atbm_void atbm_wmm_status_set(ATBM_BOOL flag);
atbm_void atbm_task_work(atbm_void *arg);

#endif //__ATBM_WORK_QUEUE_
