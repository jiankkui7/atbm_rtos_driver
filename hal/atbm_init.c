
/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/
#include "atbm_hal.h"
extern struct atbm_net_device_ops wifi_net_ops;

struct atbm_net_device *atbm_netintf_init(atbm_void)
{
	struct atbm_net_device *ndev = ATBM_NULL;
	ndev = (struct atbm_net_device *)atbm_alloc_netdev(sizeof(struct atbmwifi_vif));
	if (!ndev){
		return ATBM_NULL;
	}
	//atbm_memcpy(ndev->nif->name,"ATBM_IOT",ATBM_IFNAMSIZ);	
	//atbm_memcpy(ndev->nif->hwaddr,default_macaddr,6);
	ndev->netdev_ops = &wifi_net_ops;	
	//atbm_register_netdevice(ndev);	
	return ndev;
}
int atbm_inital_common(struct atbmwifi_vif *priv)
{
	//int ret;
	struct config_edca_params *wmm_param;
	struct atbmwifi_common *hw_priv;
	hw_priv=priv->hw_priv;
	priv->rx_task_work		= atbm_init_work(hw_priv, atbm_rx_task_work,priv);	
	priv->join_work 		= atbm_init_work(hw_priv, atbm_join_work,priv);
	priv->event_handler 	= atbm_init_work(hw_priv, atbm_event_handler,priv);
	priv->set_tim_work 		= atbm_init_work(hw_priv, atbm_ap_set_tim_work,priv);

	priv->chantype_switch_work = atbm_init_work(hw_priv, atbmwifi_set_channel_work,priv);


	/*
	ret = atbm_create_workQueue("atbm_wq",ATBM_WORK_QUEUE_SIZE);
	if (ret!=ATBM_SUCCESS)
	{
		wifi_printk(WIFI_OS,"Work Queue Init Error!\n");
	}*/	
	priv->bf_control.bcn_count = 1;
	priv->disable_beacon_filter = 1;
	priv->rx_filter.bssid = 1;	 
	priv->rx_filter.promiscuous = 0;
	priv->rx_filter.fcs = 0;
	/*if host send the probe Responde set 1,else lmac send set 0*/
	priv->rx_filter.probeResponder = 0;
	priv->rx_filter.keepalive = 1;
	priv->join_status = ATBMWIFI__JOIN_STATUS_PASSIVE; 
	priv->extra_ie_len =0;

	//////////
	//initial WMM paramter

	//BE
	wmm_param=  &priv->wmm_params[ATBM_D11_ACI_AC_BE];
	wmm_param->wmep_acm = 0;
	wmm_param->aifns = 7;
	wmm_param->cwMin= 4;
	wmm_param->cwMax= 10;
	wmm_param->txOpLimit = 0;
	wmm_param->wmep_noackPolicy= 0;
	wmm_param->uapsdEnable = 1;

	//BK
	wmm_param=  &priv->wmm_params[ATBM_D11_ACI_AC_BK];
	wmm_param->wmep_acm = 0;
	wmm_param->aifns = 3;
	wmm_param->cwMin= 4;
	wmm_param->cwMax= 10;
	wmm_param->txOpLimit = 0;
	wmm_param->wmep_noackPolicy= 0;
	wmm_param->uapsdEnable = 1;

	//VI
	wmm_param=  &priv->wmm_params[ATBM_D11_ACI_AC_VI];
	wmm_param->wmep_acm = 0;
	wmm_param->aifns = 2;
	wmm_param->cwMin= 3;
	wmm_param->cwMax= 4;
	wmm_param->txOpLimit = 94;
	wmm_param->wmep_noackPolicy= 0;
	wmm_param->uapsdEnable = 1;
	//VO
	wmm_param=  &priv->wmm_params[ATBM_D11_ACI_AC_VO];
	wmm_param->wmep_acm = 0;
	wmm_param->aifns = 2;
	wmm_param->cwMin= 2;
	wmm_param->cwMax= 3;
	wmm_param->txOpLimit = 47;
	wmm_param->wmep_noackPolicy= 0;
	wmm_param->uapsdEnable = 1;
	return 0;
}
int atbm_free_common(struct atbmwifi_vif *priv)
{	
	struct atbmwifi_common *hw_priv;
	hw_priv=priv->hw_priv;
	
	atbm_os_DeleteMutex(&hw_priv->wsm_cmd_mux);	
	return 0;
}

int atbm_wifi_add_interfaces(struct atbmwifi_common *hw_priv,char *if_name)
{
	struct atbm_net_device *ndev = ATBM_NULL;
	struct atbmwifi_vif *priv = ATBM_NULL;
//	int ret = 0;
	ndev = atbm_netintf_init();
	if(!ndev)
		return -ATBM_ENOMEM;
	priv = (struct atbmwifi_vif *)netdev_drv_priv(ndev);
	priv->ndev = ndev;
	priv->hw_priv = hw_priv;
	ATBM_ASSERT(hw_priv->vif_current < 2);
	priv->if_id = hw_priv->vif_current++;
	priv->enabled = 0;
	priv->sta_asleep_mask = 0;
	priv->buffered_set_mask = 0;
	priv->link_id_map = 0;
	priv->extra_ie= ATBM_NULL;
	priv->extra_ie_len= 0;
	priv->bss.wmm_used = 1;
	priv->bss.uapsd_supported = 1;
	priv->bss.ht = 1;
	priv->bss.channel_type = CH_OFF_20;	
	
	atbm_memcpy(priv->mac_addr,hw_priv->addresses[priv->if_id].addr,6);
	hw_priv->vif_list[priv->if_id] = priv;	
	wifi_printk(WIFI_DBG_INIT,"atbm_wifi_add_interfaces name(%s)\n",if_name);
	atbm_memcpy(priv->if_name,if_name,ATBM_IFNAMSIZ);
#if ATBM_PKG_REORDER
	atbm_reorder_func_init(priv);
#endif
	return atbm_register_netdevice(ndev);
}
int atbm_wifi_initialed(void)
{
	return (g_vmac != ATBM_NULL);
}


