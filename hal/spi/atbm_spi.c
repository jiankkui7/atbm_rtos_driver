/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#include "atbm_hal.h"

//FLASH_FUNC void LMAC2HMAC_IRQ_HANDLER(unsigned IrqNum)
//{
//      wifi_printk(WIFI_DBG_MSG,"LMAC2HMAC_IRQ_HANDLER ++ \n");
//}

FLASH_FUNC atbm_void atbmwifi_send_intr2wifi(struct atbmwifi_common *hw_priv)
{
	//iot_printf("atbmwifi_send_intr2wifi \n");
	//atbmwifi_reg_write_32(hw_priv,M2W_INTERRPUTE_EN,0);
	//atbmwifi_reg_write_32(hw_priv,M2W_INTERRPUTE_EN,1);
	HiInternal_IrqHandler(0);
	OS_LMAC_SCHED_IRQ();
}
FLASH_FUNC atbm_void atbmwifi_rxcmplete_intr2wifi(struct atbmwifi_common *hw_priv)
{
	//iot_printf("atbmwifi_send_intr2wifi \n");
	//atbmwifi_reg_write_32(hw_priv,M2W_INTERRPUTE_EN,0);
	//atbmwifi_reg_write_32(hw_priv,M2W_INTERRPUTE_EN,1);
	HiInternal_IrqHandler_OutCmp(0);
	OS_LMAC_SCHED_IRQ();
}

FLASH_FUNC int atbmwifi_hwio_init(struct atbmwifi_common *hw_priv)
{	
	int loop =10000;
	//atbm_uint32 regdata = 0;
	//int ret;

	//wake up lmac
	atbmwifi_wakeup_lmac(hw_priv);
	
    wifi_printk(WIFI_DBG_INIT,"wait:lmac init\n");

	//wait low mac initial ok
	do {
		if(Hif_Internal.lmac_ready)
			break;
		OS_HMAC2LMAC_TRY_SCHED(1000);
	}while(loop--);
	
	ATBM_ASSERT(loop != 0);


	wifi_printk(WIFI_DBG_INIT,"lmac init ok\n");
    //
	//atbmwifi_reg_write_32(hw_priv,W2M_INTERRPUTE_MASK,0);
	//
	//IRQ_RegisterHandler(23, LMAC2HMAC_IRQ_HANDLER,0);
	//
	//hw_priv->wsm_caps.numInpChBufs = regdata>>16;
	//hw_priv->wsm_caps.sizeInpChBuf = regdata&0xffff;
	
	//tell lowmac ,hmac have been readly
	Hif_Internal.hmac_ready = 1;	
	//wifi_printk(WIFI_DBG_INIT,"hmac HMAC_READLY_FLAG \n");
	return 0;
}
FLASH_FUNC int atbmwifi_wakeup_lmac(struct atbmwifi_common *hw_priv)
{
	return 0;
}
/*readly wakeup return 1, wakeup ATBM_FALSE return -1, wait to wakeup return  0*/
FLASH_FUNC int atbmwifi_get_wakeup_status(struct atbmwifi_common *hw_priv)
{	
	return 1;
}

FLASH_FUNC int atbmwifi_sleep_lmac(struct atbmwifi_common *hw_priv)
{
	return 0;
}

FLASH_FUNC int atbmwifi_cansleep_lmac(struct atbmwifi_common *hw_priv)
{
	return 0;
}




FLASH_FUNC int atbmwifi_reg_read_32(struct atbmwifi_common *hw_priv,
				     atbm_uint32 addr, atbm_uint32 *val)
{
	///TODO: add register function FIXME!!!
	
	*val = *(atbm_uint32 * )addr;
	return 0;//atbmwifi_reg_write(hw_priv, addr, &val, sizeof(val));
}

FLASH_FUNC int atbmwifi_reg_write_32(struct atbmwifi_common *hw_priv,
				      atbm_uint32 addr, atbm_uint32 val)
{
	///TODO: add register function FIXME!!!
	
	*(atbm_uint32 * )addr = val;
	return 0;//atbmwifi_reg_write(hw_priv, addr, &val, sizeof(val));
}

/*used dma to read */
FLASH_FUNC int atbmwifi_data_read(struct atbmwifi_common *hw_priv, atbm_uint32 addr,atbm_void *buf, atbm_size_t buf_len)
{
	int ret=0;
	
#ifdef USED_DMA
	StartWifiDmaSync(dst, addr,buf_len);
#else
	atbm_memcpy32(buf, (atbm_void *)addr,buf_len);
#endif 


	return ret;
}
/*used dma to write */
FLASH_FUNC int atbmwifi_data_write(struct atbmwifi_common *hw_priv, atbm_uint32 addr, atbm_void *buf,
			atbm_size_t buf_len)
{
	int ret=0;

#ifdef USED_DMA
	StartWifiDmaSync(addr,src, buf_len);
#else	
	atbm_memcpy32((atbm_void *)addr, buf,buf_len);
#endif 

	return ret;
}



