/**************************************************************************************************************
 * altobeam RTOS WSM host interface (HI) implementation
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#include "atbm_hal.h"
#include "atbm_etf.h"

#define WSM_CMD_TIMEOUT		(6 * HZ) /* With respect to interrupt loss */
#define WSM_CMD_SCAN_TIMEOUT	(5 * HZ) /* With respect to interrupt loss */
#define WSM_CMD_JOIN_TIMEOUT	(8 * HZ) /* Join timeout is 5 sec. in FW   */
#define WSM_CMD_START_TIMEOUT	(7 * HZ)
#define WSM_CMD_RESET_TIMEOUT	(4 * HZ) /* 2 sec. timeout was observed.   */
#define WSM_CMD_DEFAULT_TIMEOUT	(4 * HZ)
#define WSM_SKIP(buf, size)						\
	do {								\
		if (atbm_unlikely((buf)->data + size > (buf)->end))		\
			goto underflow;					\
		(buf)->data += size;					\
	} while (0)

#define WSM_GET(buf, ptr, size)						\
	do {								\
		if (atbm_unlikely((buf)->data + size > (buf)->end))		\
			goto underflow;					\
		atbm_memcpy(ptr, (buf)->data, size);				\
		(buf)->data += size;					\
	} while (0)

#if 0

#define __WSM_GET(buf, type, cvt)					\
	do{								\
		type val;						\
		if (atbm_unlikely((buf)->data + sizeof(type) > (buf)->end))	\
			goto underflow;					\
		val = cvt(*(type *)(buf)->data);			\
		(buf)->data += sizeof(type);				\
		return val;							\
	)while(0)

#define WSM_GET8(buf)  __WSM_GET(buf, atbm_uint8, (atbm_uint8))
#define WSM_GET16(buf) __WSM_GET(buf, atbm_uint16, __atbm_le16_to_cpu)
#define WSM_GET32(buf) __WSM_GET(buf, atbm_uint32, __atbm_le32_to_cpu)

#endif
unsigned int  WSM_GET32(struct wsm_buf * buf)				
{						
	atbm_uint32 val;						
		val = __atbm_le32_to_cpu(*(atbm_uint32 *)(buf)->data);			
	(buf)->data += sizeof(atbm_uint32);				
	return val;							
}
unsigned int  WSM_GET16(struct wsm_buf * buf)				
{						
	atbm_uint16 val;						
		val = __atbm_le16_to_cpu(*(atbm_uint16 *)(buf)->data);			
	(buf)->data += sizeof(atbm_uint16);				
	return val;							
}
unsigned int  WSM_GET8(struct wsm_buf *buf)				
{						
	atbm_uint8 val;						
		val = (atbm_uint8)(*(atbm_uint8 *)(buf)->data);			
	(buf)->data += sizeof(atbm_uint8);				
	return val;							
}
#define WSM_PUT(buf, ptr, size)						\
	do {								\
		if (atbm_unlikely((buf)->data + size > (buf)->end))		{\
				wifi_printk(WIFI_ALWAYS,"%s WSM_PUT error:size %d \n",__FUNCTION__,size);	\
				goto nomem;				\
		}		\
		atbm_memcpy((buf)->data, ptr, size);				\
		(buf)->data += size;					\
	} while (0)

#define __WSM_PUT(buf, val, type, cvt)					\
	do {								\
		if (atbm_unlikely((buf)->data + sizeof(type) > (buf)->end))	{\
				goto nomem;				\
		}								\
		*(type *)(buf)->data = cvt(val);			\
		(buf)->data += sizeof(type);				\
	} while (0)

#define WSM_PUT8(buf, val)  __WSM_PUT(buf, val, atbm_uint8, (atbm_uint8))
#define WSM_PUT16(buf, val) __WSM_PUT(buf, val, atbm_uint16, __atbm_cpu_to_le16)
#define WSM_PUT32(buf, val) __WSM_PUT(buf, val, atbm_uint32, atbm_cpu_to_le32)

extern int wsm_release_vif_tx_buffer(struct atbmwifi_common *hw_priv, int if_id,
				int count);
extern int wsm_release_tx_buffer(struct atbmwifi_common *hw_priv, int count);

struct wsm_shmem_arg_s {
	atbm_void *buf;
	atbm_size_t buf_size;
};
static atbm_void wsm_buf_reset(struct wsm_buf *buf);
int get_interface_id_scanning(struct atbmwifi_common *hw_priv);
int wsm_write_shmem_confirm(struct atbmwifi_common *hw_priv,
				struct wsm_shmem_arg_s *arg,
				struct wsm_buf *buf);
int wsm_read_shmem_confirm(struct atbmwifi_common *hw_priv,
				struct wsm_shmem_arg_s *arg,
				struct wsm_buf *buf);

static int wsm_cmd_send(struct atbmwifi_common *hw_priv,
			struct wsm_buf *buf,
			atbm_void *arg, atbm_uint16 cmd, long tmo, int if_id);

static struct atbmwifi_vif * wsm_get_interface_for_tx(struct atbmwifi_common *hw_priv);

static  atbm_void wsm_cmd_lock(struct atbmwifi_common *hw_priv)
{
	atbm_os_mutexLock(&hw_priv->wsm_cmd_mux, 0);
}

static  atbm_void wsm_cmd_unlock(struct atbmwifi_common *hw_priv)
{
	atbm_os_mutexUnLock(&hw_priv->wsm_cmd_mux);
}

static  atbm_void wsm_oper_lock(struct atbmwifi_common *hw_priv)
{
	//atbm_os_mutexLock(&hw_priv->wsm_cmd_mux,0);
}

static  atbm_void wsm_oper_unlock(struct atbmwifi_common *hw_priv)
{
	//atbm_os_mutexUnLock(&hw_priv->wsm_cmd_mux);
}

/* ******************************************************************** */
/* WSM API implementation						*/

static int wsm_generic_confirm(struct atbmwifi_common *hw_priv,
			     atbm_void *arg,
			     struct wsm_buf *buf)
{
	atbm_uint32 status = WSM_GET32(buf);
	if (status != WSM_STATUS_SUCCESS){
		wifi_printk(WIFI_WSM|WIFI_DBG_ERROR,"wsm_generic_confirm status %d \n",status);
		return -ATBM_EINVAL;
	}
	return 0;

//underflow:
//	ATBM_WARN_ON_FUNC(1);
//	return -ATBM_EINVAL;
}

FLASH_FUNC int wsm_configuration(struct atbmwifi_common *hw_priv,
		      struct wsm_configuration *arg,
		      int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);
	WSM_PUT32(buf, arg->dot11MaxTransmitMsduLifeTime);

	WSM_PUT32(buf, arg->dot11MaxReceiveLifeTime);
	WSM_PUT32(buf, arg->dot11RtsThreshold);


	/* DPD block. */
	WSM_PUT16(buf, arg->dpdData_size + 12);

	WSM_PUT16(buf, 1); /* DPD version */

	WSM_PUT(buf, arg->dot11StationId, ATBM_ETH_ALEN);

	WSM_PUT16(buf, 5); /* DPD flags */

	WSM_PUT(buf, arg->dpdData, arg->dpdData_size);

	ret = wsm_cmd_send(hw_priv, buf, arg, WSM_CONFIGURATION_REQ_ID, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	
	wifi_printk(WIFI_ALWAYS,"wsm_configuration nomem\n");
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

static int wsm_configuration_confirm(struct atbmwifi_common *hw_priv,
				     struct wsm_configuration *arg,
				     struct wsm_buf *buf)
{
	int i;
	int status;

	status = WSM_GET32(buf);
	if (ATBM_WARN_ON(status != WSM_STATUS_SUCCESS)){		
		wifi_printk(WIFI_WSM," %s fail = %d\n", __FUNCTION__,status);
		return -ATBM_EINVAL;
	}

	WSM_GET(buf, arg->dot11StationId, ATBM_ETH_ALEN);
	arg->dot11FrequencyBandsSupported = WSM_GET8(buf);
	WSM_SKIP(buf, 1);
	arg->supportedRateMask = WSM_GET32(buf);
	for (i = 0; i < 2; ++i) {
		arg->txPowerRange[i].min_power_level = WSM_GET32(buf);
		arg->txPowerRange[i].max_power_level = WSM_GET32(buf);
		arg->txPowerRange[i].stepping = WSM_GET32(buf);
	}
	return 0;

underflow:
	ATBM_WARN_ON_FUNC(1);
	return -ATBM_EINVAL;
}

/* ******************************************************************** */

int wsm_reset(struct atbmwifi_common *hw_priv, const struct wsm_reset *arg,
		int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	atbm_uint16 cmd = 0x000A | WSM_TX_LINK_ID(arg->link_id);

	wsm_cmd_lock(hw_priv);

	WSM_PUT32(buf, arg->reset_statistics ? 0 : 1);
	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, cmd, WSM_CMD_RESET_TIMEOUT,
				if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

struct wsm_mib {
	atbm_uint16 mibId;
	atbm_void *buf;
	atbm_size_t buf_size;
};

int wsm_read_mib(struct atbmwifi_common *hw_priv, atbm_uint16 mibId, atbm_void *_buf,
			atbm_size_t buf_size,int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	struct wsm_mib mib_buf={0};
	mib_buf.mibId = mibId;
	mib_buf.buf = _buf;
	mib_buf.buf_size = buf_size;



	wsm_cmd_lock(hw_priv);

	WSM_PUT16(buf, mibId);
	WSM_PUT16(buf, 0);

	ret = wsm_cmd_send(hw_priv, buf, &mib_buf, WSM_READ_MIB_REQ_ID, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

static int wsm_read_mib_confirm(struct atbmwifi_common *hw_priv,
				struct wsm_mib *arg,
				struct wsm_buf *buf)
{
	atbm_uint16 size;
	if (ATBM_WARN_ON(WSM_GET32(buf) != WSM_STATUS_SUCCESS))
		return -ATBM_EINVAL;

	if (ATBM_WARN_ON(WSM_GET16(buf) != arg->mibId))
		return -ATBM_EINVAL;

	size = WSM_GET16(buf);
	if (size > arg->buf_size)
		size = arg->buf_size;

	WSM_GET(buf, arg->buf, size);
	arg->buf_size = size;
	return 0;

underflow:
	ATBM_WARN_ON_FUNC(1);
	return -ATBM_EINVAL;
}

/* ******************************************************************** */

int wsm_write_mib(struct atbmwifi_common *hw_priv, atbm_uint16 mibId, atbm_void *_buf,
			atbm_size_t buf_size, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	struct wsm_mib mib_buf={0};
	mib_buf.mibId = mibId;
	mib_buf.buf = _buf;
	mib_buf.buf_size = buf_size;

	wsm_cmd_lock(hw_priv);

	WSM_PUT16(buf, mibId);
	WSM_PUT16(buf, buf_size);
	WSM_PUT(buf, _buf, buf_size);

	ret = wsm_cmd_send(hw_priv, buf, &mib_buf, WSM_WRITE_MIB_REQ_ID, WSM_CMD_TIMEOUT,
			if_id);	
	if(ret == -3){
		goto disconnect;
	}
	else if(ret){
		goto nomem;
	}
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wifi_printk(WIFI_DBG_ERROR,"<WARNING> wsm_write_mib fail !!! mibId=%d\n",mibId);
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;

disconnect:
	wifi_printk(WIFI_DBG_ERROR,"<WARNING> wsm_write_mib fail !!! mibId=%d, HIF disconnect\n",mibId);
	wsm_cmd_unlock(hw_priv);
	return 0;

}

static int wsm_write_mib_confirm(struct atbmwifi_common *hw_priv,
				struct wsm_mib *arg,
				struct wsm_buf *buf,
				int interface_link_id)
{
	int ret;
	struct atbmwifi_vif *priv;

		interface_link_id = 0;

	ret = wsm_generic_confirm(hw_priv, arg, buf);
	if (ret)
		return ret;

	if (arg->mibId == WSM_MIB_ID_OPERATIONAL_POWER_MODE) {
//		const char *p = arg->buf;

		/* Power save is enabled before add_interface is called */
		if (!hw_priv->vif_list[interface_link_id])
			return 0;
		/* OperationalMode: update PM status. */
		priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv,
					interface_link_id);
		if (!priv)
			return 0;
		//atbm_enable_powersave(priv,
		//		(p[0] & 0x0F) ? ATBM_TRUE : ATBM_FALSE);
	}
	return 0;
}

/* ******************************************************************** */

int wsm_scan(struct atbmwifi_common *hw_priv, const struct wsm_scan *arg,
		int if_id)
{
	int i;
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	if (atbm_unlikely(arg->numOfChannels > 48))
		return -ATBM_EINVAL;

	if (atbm_unlikely(arg->numOfSSIDs > WSM_SCAN_MAX_NUM_OF_SSIDS))
		return -ATBM_EINVAL;

	if (atbm_unlikely(arg->band > 1))
		return -ATBM_EINVAL;

	wsm_oper_lock(hw_priv);
	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->band);
	WSM_PUT8(buf, arg->scanType);
	WSM_PUT8(buf, arg->scanFlags);
	WSM_PUT8(buf, arg->maxTransmitRate);
	WSM_PUT32(buf, arg->autoScanInterval);
	WSM_PUT8(buf, arg->numOfProbeRequests);
	WSM_PUT8(buf, arg->numOfChannels);
	WSM_PUT8(buf, arg->numOfSSIDs);
	WSM_PUT8(buf, arg->probeDelay);

	for (i = 0; i < arg->numOfChannels; ++i) {
		WSM_PUT16(buf, arg->ch[i].number);
		WSM_PUT16(buf, 0);
		WSM_PUT32(buf, arg->ch[i].minChannelTime);
		WSM_PUT32(buf, arg->ch[i].maxChannelTime);
		WSM_PUT32(buf, 0);
	}

	for (i = 0; i < arg->numOfSSIDs; ++i) {
		WSM_PUT32(buf, arg->ssids[i].length);
		WSM_PUT(buf, &arg->ssids[i].ssid[0],
				sizeof(arg->ssids[i].ssid));
	}

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_START_SCAN_REQ_ID, WSM_CMD_SCAN_TIMEOUT,
			   if_id);
	wsm_cmd_unlock(hw_priv);
	if (ret)
		wsm_oper_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	wsm_oper_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

int wsm_stop_scan(struct atbmwifi_common *hw_priv, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	wsm_cmd_lock(hw_priv);
	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_STOP_SCAN_REQ_ID, WSM_CMD_TIMEOUT,
			   if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;
}

static int wsm_multi_tx_rate_confirm(struct atbmwifi_common *hw_priv,
				struct wsm_buf *buf, int interface_link_id)
{
#if (RATE_CONTROL_MODE==1)
	struct wsm_tx_rate_confirm * tx_rate_confirm;
	struct atbmwifi_vif *	priv ;
//	struct atbmwifi_sta_priv * sta_priv;
	int link_id;
	//struct atbm_buff *skb=(struct atbm_buff *)buf->data;
	tx_rate_confirm= (struct wsm_tx_rate_confirm *)buf->data ;
	priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv, tx_rate_confirm->if_id);
	if((priv ==NULL)||(priv->enabled ==0)){
		wifi_printk(WIFI_DBG_ERROR,"wsm_multi_tx_rate_confirm priv NULL\n");
		return -1;
	}
	//sta_priv = atbmwifi_sta_find_form_hard_linkid(priv, tx_rate_confirm->link_id);
	link_id = tx_rate_confirm->link_id;
	if((priv->iftype == ATBM_NL80211_IFTYPE_AP)||(priv->iftype ==ATBM_NL80211_IFTYPE_P2P_GO)){
		if((link_id >0) && (link_id <= ATBMWIFI__MAX_STA_IN_AP_MODE )&&(priv->link_id_db[link_id-1].sta_priv.sta_rc_priv!=ATBM_NULL))
			mac80211_ratectrl->tx_status(&priv->link_id_db[link_id-1].sta_priv.rate,priv->link_id_db[link_id-1].sta_priv.sta_rc_priv,&tx_rate_confirm->txstatus);	
	}
	else {
		if(priv->bss.rc_priv)
			mac80211_ratectrl->tx_status(&priv->bss.rate,priv->bss.rc_priv,&tx_rate_confirm->txstatus);	
	}
#endif //#if (RATE_CONTROL_MODE==1)
	return 0;
}


static int wsm_tx_confirm(struct atbmwifi_common *hw_priv,
			  struct wsm_buf *buf,
			  int interface_link_id)
{
	struct wsm_tx_confirm * tx_confirm;
	int if_id;
	int link_id;
#if 0
	tx_confirm.packetID = WSM_GET32(buf);
	tx_confirm.status = WSM_GET32(buf);
	tx_confirm.txedRate = WSM_GET8(buf);
	tx_confirm.ackFailures = WSM_GET8(buf);
	tx_confirm.flags = WSM_GET16(buf);
	tx_confirm.mediaDelay = WSM_GET32(buf);
	tx_confirm.txQueueDelay = WSM_GET32(buf);
#else
	tx_confirm= (struct wsm_tx_confirm *)buf->data ;
	WSM_SKIP(buf,sizeof(struct wsm_tx_confirm));
#endif
	/* TODO:COMBO:linkID will be stored in packetID*/
	/* TODO:COMBO: Extract traffic resumption map */
	if_id = atbmwifi_queue_get_if_id(tx_confirm->packetID);
	link_id = atbmwifi_queue_get_link_id(tx_confirm->packetID);
	atbm_spin_lock(&hw_priv->tx_com_lock);

	hw_priv->wsm_txconfirm_num++;
	atbm_spin_unlock(&hw_priv->tx_com_lock);

	wsm_release_vif_tx_buffer(hw_priv, if_id, 1);

	atbmwifi_tx_confirm_cb(hw_priv, tx_confirm,if_id,link_id);
	return 0;

underflow:
	ATBM_WARN_ON_FUNC(1);
	return -ATBM_EINVAL;
}

static int wsm_multi_tx_confirm(struct atbmwifi_common *hw_priv,
				struct wsm_buf *buf, int interface_link_id)
{
//	struct atbmwifi_vif *priv;
	int ret;
	int count;
	int i;
	count = WSM_GET32(buf);

	if (ATBM_WARN_ON(count <= 0))
		return -ATBM_EINVAL;
	else if (count > 1) {
		ret = wsm_release_tx_buffer(hw_priv,  count - 1);
		if (ret < 0)
			return ret;
		//if (ret > 0)
		//	atbm_bh_wakeup(hw_priv);
	}
	//priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv, interface_link_id);
	//if (priv) {
		//atbm_debug_txed_multi(priv, count);
	//}
	for (i = 0; i < count; ++i) {
		ret = wsm_tx_confirm(hw_priv, buf, interface_link_id);
		if (ret)
			return ret;
	}
	return ret;

//underflow:
//	ATBM_WARN_ON_FUNC(1);
//	return -ATBM_EINVAL;
}

/* ******************************************************************** */
extern 	atbm_void atbmwifi_join_complete(struct atbmwifi_vif *priv);
FLASH_FUNC static int wsm_join_confirm(struct atbmwifi_common *hw_priv,
			    struct wsm_join *arg,
			    struct wsm_buf *buf)
{
	atbm_uint32 ret=0;
	wsm_oper_unlock(hw_priv);
	ret = WSM_GET32(buf);

	if (ret != WSM_STATUS_SUCCESS){
		wifi_printk(WIFI_WSM,"wsm_join_confirm ERROR<%x>!!\n",ret);
		return -ATBM_EINVAL;
	}

	arg->minPowerLevel = WSM_GET32(buf);
	arg->maxPowerLevel = WSM_GET32(buf);

	return 0;

//underflow:
//	ATBM_WARN_ON_FUNC(1);
//	return -ATBM_EINVAL;
}

int wsm_join(struct atbmwifi_common *hw_priv, struct wsm_join *arg,
	     int if_id)
/*TODO: combo: make it work per vif.*/
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_oper_lock(hw_priv);
	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->mode);
	WSM_PUT8(buf, arg->band);
	WSM_PUT16(buf, arg->channelNumber);
	WSM_PUT(buf, &arg->bssid[0], sizeof(arg->bssid));
	WSM_PUT16(buf, arg->atimWindow);
	WSM_PUT8(buf, arg->preambleType);
	WSM_PUT8(buf, arg->probeForJoin);
	WSM_PUT8(buf, arg->dtimPeriod);
	WSM_PUT8(buf, arg->flags);
	WSM_PUT32(buf, arg->ssidLength);
	WSM_PUT(buf, &arg->ssid[0], sizeof(arg->ssid));
	WSM_PUT32(buf, arg->beaconInterval);
	WSM_PUT32(buf, arg->basicRateSet);
	WSM_PUT32(buf, arg->channel_type);

	hw_priv->tx_burst_idx = -1;
	ret = wsm_cmd_send(hw_priv, buf, arg, WSM_JOIN_REQ_ID, WSM_CMD_JOIN_TIMEOUT,
			   if_id);
	wsm_cmd_unlock(hw_priv);
	if (ret)
		wsm_oper_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	wsm_oper_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

int wsm_set_bss_params(struct atbmwifi_common *hw_priv,
			const struct wsm_set_bss_params *arg,
			int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, 0);
	WSM_PUT8(buf, arg->beaconLostCount);
	WSM_PUT16(buf, arg->aid);
	WSM_PUT32(buf, arg->operationalRateSet);

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_SET_BSS_PARAMS_REQ_ID, WSM_CMD_TIMEOUT,
			if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

int wsm_add_key(struct atbmwifi_common *hw_priv, const struct wsm_add_key *arg,
			int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT(buf, arg, sizeof(*arg));

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_ADD_KEY_REQ_ID, WSM_CMD_TIMEOUT,if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

int wsm_remove_key(struct atbmwifi_common *hw_priv, const struct wsm_add_key *arg,
			int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT(buf, arg, sizeof(*arg));

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_REMOVE_KEY_REQ_ID, WSM_CMD_TIMEOUT,
				if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

int wsm_set_tx_queue_params(struct atbmwifi_common *hw_priv,
				const struct wsm_set_tx_queue_params *arg,
				atbm_uint8 id, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	atbm_uint8 queue_id_to_wmm_aci[] = {3, 2, 0, 1};

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, queue_id_to_wmm_aci[id]);
	WSM_PUT8(buf, 0);
	WSM_PUT8(buf, arg->ackPolicy);
	WSM_PUT8(buf, 0);
	WSM_PUT32(buf, arg->maxTransmitLifetime);
	WSM_PUT16(buf, arg->allowedMediumTime);
	WSM_PUT16(buf, 0);

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_QUEUE_PARAMS_REQ_ID, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

int wsm_set_edca_params(struct atbmwifi_common *hw_priv,
				const struct wsm_edca_params *arg,
				int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	/* Implemented according to specification. */

	WSM_PUT16(buf, arg->params[3].cwMin);
	WSM_PUT16(buf, arg->params[2].cwMin);
	WSM_PUT16(buf, arg->params[1].cwMin);
	WSM_PUT16(buf, arg->params[0].cwMin);

	WSM_PUT16(buf, arg->params[3].cwMax);
	WSM_PUT16(buf, arg->params[2].cwMax);
	WSM_PUT16(buf, arg->params[1].cwMax);
	WSM_PUT16(buf, arg->params[0].cwMax);

	WSM_PUT8(buf, arg->params[3].aifns);
	WSM_PUT8(buf, arg->params[2].aifns);
	WSM_PUT8(buf, arg->params[1].aifns);
	WSM_PUT8(buf, arg->params[0].aifns);

	WSM_PUT16(buf, arg->params[3].txOpLimit);
	WSM_PUT16(buf, arg->params[2].txOpLimit);
	WSM_PUT16(buf, arg->params[1].txOpLimit);
	WSM_PUT16(buf, arg->params[0].txOpLimit);

	WSM_PUT32(buf, arg->params[3].maxReceiveLifetime);
	WSM_PUT32(buf, arg->params[2].maxReceiveLifetime);
	WSM_PUT32(buf, arg->params[1].maxReceiveLifetime);
	WSM_PUT32(buf, arg->params[0].maxReceiveLifetime);

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_EDCA_PARAMS_REQ_ID, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */
//It is only used 40M
int wsm_switch_channel(struct atbmwifi_common *hw_priv,
		       const struct wsm_switch_channel *arg,
		       int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_lock_tx(hw_priv);
	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->channelMode);
	WSM_PUT8(buf, arg->channelSwitchCount);
	WSM_PUT16(buf, arg->newChannelNumber);

	hw_priv->channel_switch_in_progress = 1;

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_SWITCH_CHANNEL_REQ_ID, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	if (ret) {
		wsm_unlock_tx(hw_priv);
		hw_priv->channel_switch_in_progress = 0;
	}
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	wsm_unlock_tx(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

int wsm_set_pm(struct atbmwifi_common *hw_priv, const struct wsm_set_pm *arg,
		int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_oper_lock(hw_priv);

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->pmMode);
	WSM_PUT8(buf, arg->fastPsmIdlePeriod);
	WSM_PUT8(buf, arg->apPsmChangePeriod);
	WSM_PUT8(buf, arg->minAutoPsPollPeriod);

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_SET_PM_REQ_ID, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	if (ret)
        wsm_oper_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	wsm_oper_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

int wsm_start(struct atbmwifi_common *hw_priv, const struct wsm_start *arg,
		int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->mode);
	WSM_PUT8(buf, arg->band);
	WSM_PUT16(buf, arg->channelNumber);
	WSM_PUT32(buf, arg->CTWindow);
	WSM_PUT32(buf, arg->beaconInterval);
	WSM_PUT8(buf, arg->DTIMPeriod);
	WSM_PUT8(buf, arg->preambleType);
	WSM_PUT8(buf, arg->probeDelay);
	WSM_PUT8(buf, arg->ssidLength);
	WSM_PUT(buf, arg->ssid, sizeof(arg->ssid));
	WSM_PUT32(buf, arg->basicRateSet);
	WSM_PUT32(buf, arg->channel_type);

	hw_priv->tx_burst_idx = -1;
	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_START_REQ_ID, WSM_CMD_START_TIMEOUT,
			if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}


/* ******************************************************************** */

int wsm_start_find(struct atbmwifi_common *hw_priv, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);
	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_START_FIND_ID, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;
}

/* ******************************************************************** */

int wsm_stop_find(struct atbmwifi_common *hw_priv, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);
	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_STOP_FIND_ID, WSM_CMD_TIMEOUT, if_id);
	wsm_cmd_unlock(hw_priv);
	return ret;
}

/* ******************************************************************** */

int wsm_map_link(struct atbmwifi_common *hw_priv, const struct wsm_map_link *arg,
		int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	atbm_uint16 cmd = WSM_MAP_LINK_REQ_ID;

	wsm_cmd_lock(hw_priv);

	WSM_PUT(buf, &arg->mac_addr[0], sizeof(arg->mac_addr));

	WSM_PUT8(buf, arg->unmap);
	WSM_PUT8(buf, arg->link_id);



	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, cmd, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

/* ******************************************************************** */

int wsm_update_ie(struct atbmwifi_common *hw_priv,
		  const struct wsm_update_ie *arg, int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wsm_cmd_lock(hw_priv);

	WSM_PUT16(buf, arg->what);
	WSM_PUT16(buf, arg->count);
	WSM_PUT(buf, arg->ies, arg->length);

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_UPDATE_IE_REQ_ID, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;

}


FLASH_FUNC int wsm_set_keepalive_filter(struct atbmwifi_vif *priv, ATBM_BOOL enable)
{
        struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);

        priv->rx_filter.keepalive = enable;
        return wsm_set_rx_filter(hw_priv, &priv->rx_filter, priv->if_id);
}

FLASH_FUNC int wsm_set_probe_responder(struct atbmwifi_vif *priv, ATBM_BOOL enable)
{
        struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);

        priv->rx_filter.probeResponder = enable;
        return wsm_set_rx_filter(hw_priv, &priv->rx_filter, priv->if_id);
}
/* ******************************************************************** */
/* WSM indication events implementation					*/
static int wsm_startup_indication(struct atbmwifi_common *hw_priv,
					struct wsm_buf *buf)
{
	atbm_uint16 status;
	char fw_label[129];
	static const char * const fw_types[] = {
		"ETF",
		"WFM",
		"WSM",
		"HI test",
		"Platform test"
	};
	atbm_uint32 Config[4];
	atbm_uint16 firmwareCap2;

	hw_priv->wsm_caps.numInpChBufs	= WSM_GET16(buf);
	hw_priv->wsm_caps.sizeInpChBuf	= WSM_GET16(buf);
	hw_priv->wsm_caps.hardwareId	= WSM_GET16(buf);
	hw_priv->wsm_caps.hardwareSubId	= WSM_GET16(buf);
	status				= WSM_GET16(buf);
	hw_priv->wsm_caps.firmwareCap	= WSM_GET16(buf);
	wifi_printk(WIFI_DBG_INIT,"firmwareCap %x\n",hw_priv->wsm_caps.firmwareCap);
	hw_priv->wsm_caps.firmwareType	= WSM_GET16(buf);
	hw_priv->wsm_caps.firmwareApiVer	= WSM_GET16(buf);
	hw_priv->wsm_caps.firmwareBuildNumber = WSM_GET16(buf);
	hw_priv->wsm_caps.firmwareVersion	= WSM_GET16(buf);
	WSM_GET(buf, &fw_label[0], sizeof(fw_label) - 1);
	fw_label[sizeof(fw_label) - 1] = 0; /* Do not trust FW too much. */
	Config[0]	= WSM_GET32(buf);
	Config[1]	= WSM_GET32(buf);
	Config[2]	= WSM_GET32(buf);
	Config[3]	= WSM_GET32(buf);
	firmwareCap2 =WSM_GET16(buf);
	wifi_printk(WIFI_DBG_INIT,"firmwareCap2 %x\n",firmwareCap2);
	hw_priv->wsm_caps.firmwareCap	|= (firmwareCap2<<16);
	
#define CAPABILITIES_NEW_RATE_POLICY 	BIT(1)
#define CAPABILITIES_IPC 				BIT(2)
#define CAPABILITIES_NO_CONFIRM 		BIT(3)
#define CAPABILITIES_SDIO_PATCH 		BIT(4)
#define CAPABILITIES_SIGMA_STAR 		BIT(5)
#define CAPABILITIES_CFO 				BIT(6)
#define CAPABILITIES_AGC 				BIT(7)
#define CAPABILITIES_TXCAL 				BIT(8)
#define CAPABILITIES_MONITOR 			BIT(9)
#define CAPABILITIES_CUSTOM 			BIT(10)
#define CAPABILITIES_SMARTCONFIG		BIT(11)
#define CAPABILITIES_ETF				BIT(12)
#define CAPABILITIES_LMAC_RATECTL		BIT(13)
#define CAPABILITIES_LMAC_TPC			BIT(14)
#define CAPABILITIES_LMAC_TEMPC			BIT(15)
#define CAPABILITIES_CTS_BUG			BIT(16)
#define CAPABILITIES_USB_RECOVERY_BUG	BIT(17)
#define CAPABILITIES_VIFADDR_LOCAL_BIT	BIT(18)


	wifi_printk(WIFI_DBG_INIT,"wsm_caps.firmwareCap %x \n",hw_priv->wsm_caps.firmwareCap);
	wifi_printk(WIFI_DBG_INIT,"firmware used %s-rate policy \n",hw_priv->wsm_caps.firmwareCap&CAPABILITIES_NEW_RATE_POLICY?"new":"old");

	if(!!(hw_priv->wsm_caps.firmwareCap & CAPABILITIES_NEW_RATE_POLICY)){
		wifi_printk(WIFI_DBG_INIT, "\n\n\n******************************************************\n");
		wifi_printk(WIFI_DBG_INIT, "\n ERROR!!!!!!! lmac version error,please check!!\n");
		wifi_printk(WIFI_DBG_INIT, "\n ERROR!!!!!!!need used old ratecontrol policy,please check!!\n");
		wifi_printk(WIFI_DBG_INIT, "\n******************************************************\n\n\n");
		ATBM_BUG_ON(1);
	}
	if (ATBM_WARN_ON(status))
		return -ATBM_EINVAL;

	if (ATBM_WARN_ON(hw_priv->wsm_caps.firmwareType > 4))
		return -ATBM_EINVAL;

	wifi_printk(WIFI_DBG_INIT,"apollo wifi WSM init done.\n"
		"   Input buffers: %d x %d bytes\n"
		"   Hardware: %d.%d\n"
		"   %s firmware [%s]\n",
		hw_priv->wsm_caps.numInpChBufs,
		hw_priv->wsm_caps.sizeInpChBuf,
		hw_priv->wsm_caps.hardwareId,
		hw_priv->wsm_caps.hardwareSubId,
		fw_types[hw_priv->wsm_caps.firmwareType],
		&fw_label[0]);
	
	wifi_printk(WIFI_DBG_INIT,"LmacVersion: %d, build: %d,"
		    " api: %d, cap: 0x%.4X Config[%x]  expection %x, ep0 cmd addr %x\n",
		hw_priv->wsm_caps.firmwareVersion,
		hw_priv->wsm_caps.firmwareBuildNumber,
		hw_priv->wsm_caps.firmwareApiVer,
		hw_priv->wsm_caps.firmwareCap,Config[0],Config[1],Config[2]);

	hw_priv->wsm_caps.firmwareReady = 1;
	hw_priv->wsm_caps.exceptionaddr =Config[1];
	hw_priv->wsm_caps.HiHwCnfBufaddr = Config[2];//ep0 addr

	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_NEW_RATE_POLICY   [%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_NEW_RATE_POLICY)); 
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_IPC 		[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_IPC));  
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_NO_CONFIRM 		   [%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_NO_CONFIRM));
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_SDIO_PATCH 		   [%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_SDIO_PATCH));
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_SIGMA_STAR 		   [%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_SIGMA_STAR));
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_CFO 		[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_CFO ));  
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_AGC 		[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_AGC ));  
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_TXCAL 		[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_TXCAL ) );  
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_MONITOR 		[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_MONITOR) );  
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_CUSTOM 		[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_CUSTOM));
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_SMARTCONFIG	[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_SMARTCONFIG));
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_ETF			[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_ETF));
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_LMAC_RATECTL	[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_LMAC_RATECTL));  
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_LMAC_TPC		[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_LMAC_TPC) );  
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_LMAC_TEMPC		[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_LMAC_TEMPC) );  
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_CTS_BUG		[%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_CTS_BUG	) );
	wifi_printk(WIFI_DBG_INIT,"CAPABILITIES_USB_RECOVERY_BUG	 [%d]\n" ,!!(hw_priv->wsm_caps.firmwareCap &CAPABILITIES_USB_RECOVERY_BUG)); 

	
#if ATBM_TX_SKB_NO_TXCONFIRM
	if((hw_priv->wsm_caps.firmwareCap &CAPABILITIES_NO_CONFIRM)==0){
		
		wifi_printk(WIFI_DBG_ERROR, "LMAC NOT CAPABILITIES_NO_CONFIRM <ERROR>\n");
		ATBM_BUG_ON(1);
	}
#else
	if((hw_priv->wsm_caps.firmwareCap &CAPABILITIES_NO_CONFIRM)){
		
		wifi_printk(WIFI_DBG_ERROR,"LMAC SET CAPABILITIES_NO_CONFIRM <ERROR>\n");
		ATBM_BUG_ON(1);
	}
#endif

#ifdef	ATBM_P2P_ADDR_USE_LOCAL_BIT
	if((hw_priv->wsm_caps.firmwareCap &CAPABILITIES_VIFADDR_LOCAL_BIT)==0){
		
		wifi_printk(WIFI_DBG_ERROR, "LMAC NOT CAPABILITIES_VIFADDR_LOCAL_BIT <ERROR>\n");
	}
#else
	if((hw_priv->wsm_caps.firmwareCap &CAPABILITIES_VIFADDR_LOCAL_BIT)){
		
		wifi_printk(WIFI_DBG_ERROR, "LMAC SET CAPABILITIES_VIFADDR_LOCAL_BIT <ERROR>\n");
	}
#endif
	atbm_os_wakeup_event(&hw_priv->wsm_startup_done);
	return 0;
underflow:
	ATBM_WARN_ON_FUNC(1);
	return -ATBM_EINVAL;
}

#define DBG_PRINT_BUF_SIZE_MAX 380
static int wsm_debug_print_indication(struct atbmwifi_common *hw_priv,
					struct wsm_buf *buf)
{
	char fw_debug_print[DBG_PRINT_BUF_SIZE_MAX + 1];
	atbm_uint16 length;

	length = WSM_GET16(buf);
	if (length > DBG_PRINT_BUF_SIZE_MAX)
		length = DBG_PRINT_BUF_SIZE_MAX;
	WSM_GET(buf, &fw_debug_print[0], length);
	fw_debug_print[length] = '\0';

	wifi_printk(WIFI_DBG_ANY,"[lmac]:%s", fw_debug_print);
	return 0;
underflow:
	wifi_printk(WIFI_WSM,"wsm_debug_print_indication:ATBM_EINVAL\n");
	return -ATBM_EINVAL;
}

extern void etf_v2_scan_rx(struct atbmwifi_common *hw_priv,struct atbm_buff *skb,atbm_uint8 rssi );

static int atbmwifi_is_probe_resp(atbm_uint16 fc)
{
	return (fc & atbm_cpu_to_le16(0x000c | 0x00f0)) == (atbm_cpu_to_le16(0x0000 | 0x0050));
}

static int wsm_receive_indication(struct atbmwifi_common *hw_priv,
					int interface_link_id,
					struct wsm_buf *buf,
					struct atbm_buff **skb_p)
{
	struct atbmwifi_vif *priv;
	int link_id;
	int if_id;
	//hw_priv->rx_timestamp = atbm_GetOsTimeMs;
	{
		struct wsm_rx * rx;
		atbm_size_t hdr_len;
		atbm_uint16 fctl;

#if 0
		rx.status = WSM_GET32(buf);
		rx.channelNumber = WSM_GET16(buf);
		rx.rxedRate = WSM_GET8(buf);
		rx.rcpiRssi = WSM_GET8(buf);
		rx.flags = WSM_GET32(buf);
		rx.channelType = WSM_GET32(buf); 
#else
		
		rx= (struct wsm_rx *)buf->data ;
		WSM_SKIP(buf,sizeof(struct wsm_rx));
#endif

//#define ATBM_SUPPORT_SMARTCONFIG
#if ATBM_SUPPORT_SMARTCONFIG
		if (rx->flags & WSM_RX_STATUS_SMARTCONFIG){
			struct atbmwifi_ieee80211_rx_status *hdr = ATBM_IEEE80211_SKB_RXCB(*skb_p);
			if(rx->rxedRate >= 14){
				hdr->flag |= ATBM_RX_FLAG_HT;
			}else if(rx->rxedRate >= 4){
				hdr->rate_idx = rx->rxedRate -2;
			}else{
				hdr->rate_idx = rx->rxedRate;
			}
			hdr->signal = (atbm_int8)rx->rcpiRssi;
			fctl = *(atbm_uint16 *)buf->data;
			hdr_len = buf->data - buf->begin;
			atbm_skb_pull(*skb_p, hdr_len);
			smartconfig_start_rx(hw_priv,*skb_p,rx->channelNumber);
			//if (*skb_p)
			//	skb_push(*skb_p, hdr_len);
			return 0;
		}
#endif

		if (hw_priv->bStartTx && hw_priv->etf_test_v2){
			fctl = *(atbm_uint16*)buf->data;
			//wifi_printk(WIFI_DBG_ERROR,"rx etf data %x\n",fctl);
			if(atbmwifi_is_probe_resp(fctl )){
				hdr_len = buf->data - buf->begin;
				atbm_skb_pull(*skb_p, hdr_len);
				etf_v2_scan_rx(hw_priv,*skb_p,rx->rcpiRssi);
				if (*skb_p)
					atbm_skb_push(*skb_p, hdr_len);
				return 0;
			}
		}



		/* TODO:COMBO: Frames received from scanning are received
		* with interface ID == 2 */
		if (interface_link_id == ATBM_WIFI_GENERIC_IF_ID) {
			/* Frames received in response to SCAN
			 * Request */
			interface_link_id = get_interface_id_scanning(hw_priv);
			if (interface_link_id == -1) {
				interface_link_id = -1;//hw_priv->roc_if_id;
			}

		}
		/* linkid (peer sta id is encoded in bit 25-28 of
		   flags field */
		link_id = ((rx->flags & (0xf << 25)) >> 25);
		if_id = interface_link_id;


		priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv, if_id);
		if (!priv) {
			wifi_printk(WIFI_WSM,"wsm_receive_ind: ATBM_NULL priv drop\n");
			return 0;
		} 
		fctl = *(atbm_uint16 *)buf->data;
		hdr_len = buf->data - buf->begin;
		atbm_skb_pull(*skb_p, hdr_len);
		atbmwifi_rx_cb(priv, rx, skb_p,link_id);
		//if (*skb_p)
		//	skb_push(*skb_p, hdr_len);
	}
	return 0;
underflow:
	return -ATBM_EINVAL;
}
extern atbm_void atbmwifi_event_handler(struct atbmwifi_vif *priv,atbm_uint32 eventId,atbm_uint32 eventData);

FLASH_FUNC static int wsm_event_indication(struct atbmwifi_common *hw_priv,
				struct wsm_buf *buf,
				int interface_link_id)
{
	struct atbmwifi_vif *priv;
	int first;
	struct atbm_wsm_event *event;
	unsigned long flags=0;
	priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv, interface_link_id);

	if (atbm_unlikely(!priv)) {
		return 0;
	}


	event = atbm_kzalloc(sizeof(struct atbm_wsm_event),GFP_KERNEL);

	event->evt.eventId = __atbm_le32_to_cpu(WSM_GET32(buf));
	event->evt.eventData = __atbm_le32_to_cpu(WSM_GET32(buf));
	event->if_id = interface_link_id;

	wifi_printk(WIFI_WSM|WIFI_DBG_ANY, "[WSM] Event: %d(%d)\n",
		event->evt.eventId ,event->evt.eventData);

	atbm_spin_lock_irqsave(&hw_priv->event_queue_lock,flags);
	first = atbm_list_empty(&hw_priv->event_queue);
	atbm_list_add_tail(&event->link, &hw_priv->event_queue);
	atbm_spin_unlock_irqrestore(&hw_priv->event_queue_lock,flags);

	if (first){
		//iot_printf("atbm_queue_work event_work %d event %x\n",event->evt.eventId,event);
		atbm_queue_work(hw_priv, hw_priv->event_work);
	}
	//atbmwifi_event_handler(priv,WSM_GET32(buf),WSM_GET32(buf));
	return 0;

//underflow:
//	return -ATBM_EINVAL;
}


FLASH_FUNC int atbm_wsm_event_work(struct atbm_work_struct *work)
{
//for compile
	struct atbmwifi_vif *priv;
	struct atbmwifi_common *hw_priv =(struct atbmwifi_common *)work;	
	unsigned long flags=0;

	if(atbm_bh_is_term(hw_priv))
	{
		return 0;
	}
	atbm_spin_lock_irqsave(&hw_priv->event_queue_lock,flags);
	while (!atbm_list_empty(&hw_priv->event_queue)) {
		    struct atbm_wsm_event *event = atbm_list_first_entry(&hw_priv->event_queue, struct atbm_wsm_event, link);
			
			priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv, event->if_id);
			
			atbm_spin_unlock_irqrestore(&hw_priv->event_queue_lock,flags);
			
			//iot_printf("atbm_wsm_event_work event_%d %d,event %x\n",event->evt.eventId,event->evt.eventData,event);
			atbmwifi_event_handler(priv,event->evt.eventId,event->evt.eventData);			
			atbm_spin_lock_irqsave(&hw_priv->event_queue_lock,flags);
			
			atbm_list_del(&event->link);
			atbm_kfree(event);
	}
	atbm_spin_unlock_irqrestore(&hw_priv->event_queue_lock,flags);

	return 0;

}

static int wsm_set_pm_indication(struct atbmwifi_common *hw_priv,
					struct wsm_buf *buf)
{
	wsm_oper_unlock(hw_priv);
	return 0;
}

static int wsm_scan_complete_indication(struct atbmwifi_common *hw_priv,
					struct wsm_buf *buf)
{
	wsm_oper_unlock(hw_priv);
	if (hw_priv->wsm_cbc.scan_complete) {
		struct wsm_scan_complete arg;
		arg.status = WSM_GET32(buf);
		arg.psm = WSM_GET8(buf);
		arg.numChannels = WSM_GET8(buf);
		/*Get the busyRatio From scan complete*/
		if(hw_priv->ApScan_in_process==1){
	 		atbm_memcpy(&hw_priv->busy_ratio[1],buf->data,sizeof(hw_priv->busy_ratio));
			hw_priv->ApScan_in_process=0;
		}else{
			hw_priv->wsm_cbc.scan_complete(hw_priv, &arg);
		}
	}
	return 0;

//underflow:
//	return -ATBM_EINVAL;
}

static int wsm_find_complete_indication(struct atbmwifi_common *hw_priv,
					struct wsm_buf *buf)
{
	/* TODO: Implement me. */
	//STUB();
	return 0;
}

static int wsm_suspend_resume_indication(struct atbmwifi_common *hw_priv,
					 int interface_link_id,
					 struct wsm_buf *buf)
{
	if (hw_priv->wsm_cbc.suspend_resume) {
		atbm_uint32 flags;
		struct wsm_suspend_resume arg;
		struct atbmwifi_vif *priv;

		int i;
		arg.if_id = interface_link_id;
		/* TODO:COMBO: Extract bitmap from suspend-resume
		* TX indication */
		atbm_for_each_vif(hw_priv, priv, i) {
			if (!priv)
					continue;
				if (priv->join_status ==
					 ATBMWIFI__JOIN_STATUS_AP) {
				 arg.if_id = priv->if_id;
				 break;
			}
			arg.link_id = 0;
		}


		flags = WSM_GET32(buf);
		arg.stop = !(flags & 1);
		arg.multicast = !!(flags & 8);
		arg.queue = (flags >> 1) & 3;

		priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv, arg.if_id);
		if (atbm_unlikely(!priv)) {
			wifi_printk(WIFI_WSM,"[WSM] suspend-resume indication"
				   " for removed interface!\n");
			return 0;
		}
		hw_priv->wsm_cbc.suspend_resume(priv, &arg);
	}
	return 0;

//underflow:
//	return -ATBM_EINVAL;
}

/* ******************************************************************** */
/* WSM TX								*/

int wsm_cmd_send(struct atbmwifi_common *hw_priv,
		 struct wsm_buf *buf,
		 atbm_void *arg, atbm_uint16 cmd, long tmo, int if_id)
{
	atbm_size_t buf_len = buf->data - buf->begin;
	struct wsm_hdr_tx * wsm_h = (struct wsm_hdr_tx *)buf->begin;
	int ret;	
	int ret_flush; 
    if(hw_priv->bh_term == 1)
	{
        return -3;
	}
		
	if (cmd == 0x0006) /* Write MIB */
		wifi_printk(WIFI_WSM, "[WSM] >>> 0x%x [MIB: 0x%x] (%d)\n",
			cmd, __atbm_le16_to_cpu(((atbm_uint16 *)buf->begin)[2]),
			buf_len);
	else
		wifi_printk(WIFI_WSM, "[WSM] >>> 0x%x (%d)\n", cmd, buf_len);

	/* Fill HI message header */
	/* BH will add sequence number */

	/* TODO:COMBO: Add if_id from  to the WSM header */
	/* if_id == -1 indicates that command is HW specific,
	 * eg. wsm_configuration which is called during driver initialzation
	 *  (mac80211 .start callback called when first ifce is created. )*/

	/* send hw specific commands on if 0 */
	if (if_id == -1)
		if_id = 0;

	//((atbm_uint16 *)buf->begin)[0] = __atbm_cpu_to_le16(buf_len);
	//((atbm_uint16 *)buf->begin)[1] = __atbm_cpu_to_le16(cmd |	(if_id << 6));

	wsm_h = (struct wsm_hdr_tx *)buf->begin;
	wsm_h->len =__atbm_cpu_to_le16(buf_len);
	wsm_h->id =  __atbm_cpu_to_le16(cmd |(if_id << 6) );

	atbm_spin_lock(&hw_priv->wsm_cmd.lock);
	ATBM_BUG_ON(hw_priv->wsm_cmd.ptr);
	hw_priv->wsm_cmd.done = 0;
	hw_priv->wsm_cmd.ptr = buf->begin;
	hw_priv->wsm_cmd.len = buf_len;
	hw_priv->wsm_cmd.arg = arg;
	hw_priv->wsm_cmd.cmd = cmd;
	atbm_spin_unlock(&hw_priv->wsm_cmd.lock);
	/*if we have cmd to send , we send cmd first , so not send frame  at this time */
	atbm_bh_wakeup(hw_priv);
	atbm_os_wait_event_timeout(&hw_priv->wsm_cmd_wq,40*HZ);	
	atbm_spin_lock(&hw_priv->wsm_cmd.lock);
	ret = hw_priv->wsm_cmd.ret;
	atbm_spin_unlock(&hw_priv->wsm_cmd.lock);
	if(!hw_priv->wsm_cmd.done){
	#if ATBM_SDIO_BUS
		ret_flush=wsm_sync_channle_process(hw_priv,OUT_BH);
	#else
		ret_flush=wsm_recovery(hw_priv);
	#endif
		if(ret_flush!=RECOVERY_ERR){
			hw_priv->wsm_cmd.done = 0;
			hw_priv->wsm_cmd.ptr = buf->begin;
			hw_priv->wsm_cmd.len = buf_len;
			hw_priv->wsm_cmd.arg = arg;
			hw_priv->wsm_cmd.cmd = cmd;
			atbm_bh_wakeup(hw_priv);
			atbm_os_wait_event_timeout(&hw_priv->wsm_cmd_wq,40*HZ); 
		}else{
			ATBM_BUG_ON(!hw_priv->wsm_cmd.done);
		}
	}
	wsm_buf_reset(buf);
	
	return ret;
}
/* ******************************************************************** */
/* WSM TX port control							*/

atbm_void wsm_lock_tx(struct atbmwifi_common *hw_priv)
{
}

atbm_void wsm_vif_lock_tx(struct atbmwifi_vif *priv)
{
}

atbm_void wsm_lock_tx_async(struct atbmwifi_common *hw_priv)
{
	tcp_opt->net_disable(g_vmac->ndev);
}

atbm_void wsm_unlock_tx_async(struct atbmwifi_common *hw_priv)
{
	tcp_opt->net_enable(g_vmac->ndev);
}

ATBM_BOOL wsm_flush_tx(struct atbmwifi_common *hw_priv)
{
	return 0;
}
ATBM_BOOL wsm_vif_flush_tx(struct atbmwifi_vif *priv)
{
	return 0;
}
atbm_void wsm_unlock_tx(struct atbmwifi_common *hw_priv)
{

}
/* ******************************************************************** */
/* WSM RX								*/

FLASH_FUNC int wsm_handle_exception(struct atbmwifi_common *hw_priv, atbm_uint8 * data, atbm_uint32 len)
{
	wifi_printk(WIFI_ALWAYS,"Firmware exception start\n");
	
	struct wsm_buf buf;
//	atbm_uint32 reason;
	atbm_uint32 reg[18];
	char fname[32];
	atbm_uint32 i;

	buf.begin = buf.data = data;
	buf.end = &buf.begin[len];

//	reason = WSM_GET32(&buf);
	for (i = 0; i < ATBM_ARRAY_SIZE(reg); ++i)
		reg[i] = WSM_GET32(&buf);
	WSM_GET(&buf, fname, sizeof(fname));

	wifi_printk(WIFI_ALWAYS,
			"Firmware assert at %d,%s, Msg %x, ErrCode =%x \n",
			(int)sizeof(fname), fname, (int)reg[1],(int)reg[2]);

	for (i = 0; i < 12; i += 4)
		wifi_printk(WIFI_ALWAYS,
			"R%d: 0x%.8X, R%d: 0x%.8X, R%d: 0x%.8X, R%d: 0x%.8X,\n",
			i + 0, reg[i + 0], i + 1, reg[i + 1],
			i + 2, reg[i + 2], i + 3, reg[i + 3]);
	wifi_printk(WIFI_ALWAYS,
		"R12: 0x%.8X, SP: 0x%.8X, LR: 0x%.8X, PC: 0x%.8X,\n",
		reg[i + 0], reg[i + 1], reg[i + 2], reg[i + 3]);
	i += 4;
	wifi_printk(WIFI_ALWAYS,
		"CPSR: 0x%.8X, SPSR: 0x%.8X\n",
		reg[i + 0], reg[i + 1]);
	
underflow:
	wifi_printk(WIFI_ALWAYS,
		"Firmware exception....End \n");
	frame_hexdump("Data",data,len);
	return 0;
}
int wsm_handle_rx(struct atbmwifi_common *hw_priv, int id,
		  struct wsm_hdr *wsm, struct atbm_buff **skb_p)
{
	int ret = 0;
	struct wsm_buf wsm_buf;

	int interface_link_id = (id >> 6) & 0x0F;

	/* Strip link id. */
	id &= ~WSM_TX_LINK_ID(WSM_TX_LINK_ID_MAX);

	wsm_buf.begin = (atbm_uint8 *)&wsm[0];
	wsm_buf.data = (atbm_uint8 *)&wsm[1];
	wsm_buf.end = &wsm_buf.begin[__atbm_le32_to_cpu(wsm->len)];

	wifi_printk(WIFI_WSM, "[WSM] <<< 0x%x (%d)\n", id,
			wsm_buf.end - wsm_buf.begin);
	if (id == WSM_TX_REQ_ID) {
		ret = wsm_tx_confirm(hw_priv, &wsm_buf, interface_link_id);
	} else if (id == WSM_LEGACY_MULTI_TX_CNF_ID) {
		ret = wsm_multi_tx_confirm(hw_priv, &wsm_buf,
					   interface_link_id);
	}
	else if(id == WSM_RATE_MULTI_TX_CNF_ID){
		ret = wsm_multi_tx_rate_confirm(hw_priv, &wsm_buf,
					   interface_link_id);
	}
	else if (id & WSM_CNF_BASE) {
		atbm_void *wsm_arg;
		atbm_uint16 wsm_cmd;

		/* Do not trust FW too much. Protection against repeated
		 * response and race condition removal (see above). */
		atbm_spin_lock(&hw_priv->wsm_cmd.lock);
		wsm_arg = hw_priv->wsm_cmd.arg;
		wsm_cmd = hw_priv->wsm_cmd.cmd &
				~WSM_TX_LINK_ID(WSM_TX_LINK_ID_MAX);
		hw_priv->wsm_cmd.cmd = 0xFFFF;
		atbm_spin_unlock(&hw_priv->wsm_cmd.lock);
		
		if (ATBM_WARN_ON((id & ~WSM_CNF_BASE) != wsm_cmd)) {
			/* Note that any non-zero is a fatal retcode. */
			ret = -ATBM_EINVAL;
			goto out;
		}
		switch (id) {
		case 0x0400:
			if (atbm_likely(wsm_arg))
				ret = wsm_read_shmem_confirm(hw_priv,
									wsm_arg,
									&wsm_buf);
			break;
		case 0x0401:
			if (atbm_likely(wsm_arg))
				ret = wsm_write_shmem_confirm(hw_priv,
									wsm_arg,
									&wsm_buf);
			break;
		case WSM_CONFIGURATION_RESP_ID:
			/* Note that wsm_arg can be NULL in case of timeout in
			 * wsm_cmd_send(). */
			if (atbm_likely(wsm_arg))
				ret = wsm_configuration_confirm(hw_priv,
								wsm_arg,
								&wsm_buf);
			break;
		case WSM_READ_MIB_RESP_ID:
			if (atbm_likely(wsm_arg))
				ret = wsm_read_mib_confirm(hw_priv, wsm_arg,
								&wsm_buf);
			break;
		case WSM_WRITE_MIB_RESP_ID:
			if (atbm_likely(wsm_arg))
				ret = wsm_write_mib_confirm(hw_priv, wsm_arg,
							    &wsm_buf,
							    interface_link_id);
			break;
		case WSM_JOIN_RESP_ID:
			if (atbm_likely(wsm_arg))
				ret = wsm_join_confirm(hw_priv, wsm_arg,
						       &wsm_buf);
			break;


#ifdef ATBM_SUPPORT_WIDTH_40M

		case WSM_GET_CCA_RESP_ID:
			 ret = wsm_get_cca_confirm(hw_priv,wsm_arg,&wsm_buf);
			 break;
#endif
		case WSM_START_SCAN_RESP_ID: /* start-scan */

		case WSM_SET_CHANTYPE_RESP_ID:
		case WSM_SEND_CHTYPE_CHG_REQUEST_RESP_ID:

		case WSM_STOP_SCAN_RESP_ID: /* stop-scan */
		case WSM_RESET_RESP_ID: /* wsm_reset */
		case WSM_ADD_KEY_RESP_ID: /* add_key */
		case WSM_REMOVE_KEY_RESP_ID: /* remove_key */
		case WSM_SET_PM_RESP_ID: /* wsm_set_pm */
		case WSM_SET_BSS_PARAMS_RESP_ID: /* set_bss_params */
		case WSM_QUEUE_PARAMS_RESP_ID: /* set_tx_queue_params */
		case WSM_EDCA_PARAMS_RESP_ID: /* set_edca_params */
		case WSM_SWITCH_CHANNEL_RESP_ID: /* switch_channel */
		case WSM_START_RESP_ID: /* start */
		case WSM_BEACON_TRANSMIT_RESP_ID: /* beacon_transmit */
		case WSM_START_FIND_RESP_ID: /* start_find */
		case WSM_STOP_FIND_RESP_ID: /* stop_find */
		case WSM_UPDATE_IE_RESP_ID: /* update_ie */
		case WSM_MAP_LINK_RESP_ID: /* map_link */

			ATBM_WARN_ON_FUNC(wsm_arg != ATBM_NULL);
			ret = wsm_generic_confirm(hw_priv, wsm_arg, &wsm_buf);
			if (ret)
				wifi_printk(WIFI_ALWAYS,
					"wsm_generic_confirm "
					"failed for request,wsm_id:%x\n", id);
			break;
		default:
			ATBM_BUG_ON(1);
		}

		atbm_spin_lock(&hw_priv->wsm_cmd.lock);
		hw_priv->wsm_cmd.ret = ret;
		hw_priv->wsm_cmd.done = 1;
		atbm_spin_unlock(&hw_priv->wsm_cmd.lock);

		ret = 0; /* Error response from device should ne stop BH. */
		atbm_os_wakeup_event(&hw_priv->wsm_cmd_wq);
	} else if (id & WSM_IND_BASE) {
		switch (id) {
		case WSM_DEBUG_PRINT_IND_ID:
			ret = wsm_debug_print_indication(hw_priv, &wsm_buf);
			break;
		case WSM_STARTUP_IND_ID:
			ret = wsm_startup_indication(hw_priv, &wsm_buf);
			break;
		case WSM_RECEIVE_INDICATION_ID:
			ret = wsm_receive_indication(hw_priv, interface_link_id,
					&wsm_buf, skb_p);
			break;
		case WSM_EVENT_INDICATION_ID:
			ret = wsm_event_indication(hw_priv, &wsm_buf,
					interface_link_id);
			break;
		case WSM_SWITCH_CHANNLE_IND_ID:
			ret = 0;//wsm_channel_switch_indication(hw_priv, &wsm_buf);
			break;
		case WSM_SET_PM_MODE_CMPL_IND_ID:
			wifi_printk(WIFI_WSM,"wsm_set_pm_indication\n");
			ret = wsm_set_pm_indication(hw_priv, &wsm_buf);
			break;
		case WSM_SCAN_COMPLETE_IND_ID:

			ret = wsm_scan_complete_indication(hw_priv, &wsm_buf);
			break;
		case WSM_FIND_CMPL_IND_ID:
			ret = wsm_find_complete_indication(hw_priv, &wsm_buf);
			break;
		case WSM_SUSP_RESUME_TX_IND_ID:
			ret = wsm_suspend_resume_indication(hw_priv,
					interface_link_id, &wsm_buf);
			break;
		case WSM_DEBUG_IND_ID:
			//ret = wsm_debug_indication(hw_priv, &wsm_buf);
			break;
			
		case WSM_SEND_CHTYPE_CHG_REQUEST_IND_ID:
			ret = wsm_req_chtype_indication(hw_priv, &wsm_buf);
			break;

		default:
			//STUB();
			break;
		}
	} else {
		ATBM_WARN_ON_FUNC(1);
		ret = -ATBM_EINVAL;
	}
out:
	return ret;
}
FLASH_FUNC static int atbmwifi_get_prio_queue(struct atbmwifi_vif *priv,
				 atbm_uint32 link_id_map,int * total)
{
    int queued;
	int i;
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
#if 0

	static atbm_uint32 urgent;
	struct wsm_edca_queue_params *edca;
	unsigned score, best = -1;
	int winner = -1;
	//int queued;
	//int i;
	urgent = BIT(priv->link_id_after_dtim) | BIT(priv->link_id_uapsd);

	/* search for a winner using edca params */
	for (i = 0; i < 4; ++i) {
		queued = atbmwifi_queue_get_num_queued(priv,
				&hw_priv->tx_queue[i],
				link_id_map);
		if (!queued)
			continue;
		*total += queued;
		edca = &priv->edca.params[i];
		score = ((edca->aifns + edca->cwMin) << 16) +
				(edca->cwMax - edca->cwMin) *
				(RTL_GetRandomNumber() & 0xFFFF);
		if (score < best && (winner < 0 || i != 3)) {
			best = score;
			winner = i;
		}
	}

	/* override winner if bursting */
	if (winner >= 0 && hw_priv->tx_burst_idx >= 0 &&
			winner != hw_priv->tx_burst_idx &&
			!atbmwifi_queue_get_num_queued(priv,
				&hw_priv->tx_queue[winner],
				link_id_map & urgent) &&
			atbmwifi_queue_get_num_queued(priv,
				&hw_priv->tx_queue[hw_priv->tx_burst_idx],
				link_id_map))
	winner = hw_priv->tx_burst_idx;
	return winner;
#endif /*0*/
	/* search for a winner using edca params */
	for (i = 0; i < 4; ++i) {
		queued = atbmwifi_queue_get_num_queued(priv,
				&hw_priv->tx_queue[i],
				link_id_map);
		if (!queued)
			continue;
		*total = queued;
		return i;
	}

	return -1;
}

FLASH_FUNC static int wsm_get_tx_queue_and_mask(struct atbmwifi_vif *priv,
				     struct atbmwifi_queue **queue_p,
				     atbm_uint32 *tx_allowed_mask_p,atbm_uint32 *more)
{
	struct atbmwifi_common *hw_priv = _atbmwifi_vifpriv_to_hwpriv(priv);
	int idx;
	atbm_uint32 tx_allowed_mask;
	int total=0;
	/* Search for a queue with multicast frames buffered */
	if (priv->tx_multicast) {
		tx_allowed_mask = BIT(priv->link_id_after_dtim);
		idx = atbmwifi_get_prio_queue(priv,tx_allowed_mask, &total);
		if (idx >= 0) {
			goto found;
		}
	}

	/* Search for unicast traffic */
	tx_allowed_mask = ~priv->sta_asleep_mask;
	tx_allowed_mask |= BIT(priv->link_id_after_dtim);
	if (priv->sta_asleep_mask) {
		/*Allowed the link_id receive ps-poll to tx packet,otherwise the packet bufferd*/
		tx_allowed_mask |= priv->pspoll_mask;
		/*Allowed the link_id receive qosData or qosNullData*/
		tx_allowed_mask |= priv->link_id_uapsd_mask;
		tx_allowed_mask &= ~BIT(priv->link_id_after_dtim);
	} else {
		/*Allowed the link_id tx muticase/boradcast packet*/
		tx_allowed_mask |= BIT(priv->link_id_after_dtim);
	}
	idx = atbmwifi_get_prio_queue(priv,tx_allowed_mask,&total);
	if (idx < 0)
		return -ATBM_ENOENT;
	
found:
	*queue_p = &hw_priv->tx_queue[idx];
	*tx_allowed_mask_p = tx_allowed_mask;
	*more = total;
	return 0;
}

FLASH_FUNC int wsm_get_tx(struct atbmwifi_common *hw_priv, atbm_uint8 **data,
	       atbm_size_t *tx_len, int *burst, int *vif_selected)
{
	struct wsm_tx *wsm = ATBM_NULL;
	struct atbmwifi_queue *queue = ATBM_NULL;
	int queue_num;
	atbm_uint32 tx_allowed_mask = 0;
	struct atbmwifi_txpriv *txpriv = ATBM_NULL;
	atbm_uint32 total=0;
	struct atbmwifi_ieee80211_hdr *hdr;
	atbm_uint8 *qoshdr = ATBM_NULL;
	/*
	 * Count was intended as an input for wsm->more flag.
	 * During implementation it was found that wsm->more
	 * is not usable, see details above. It is kept just
	 * in case you would like to try to implement it again.
	 */
	int count = 0;
	int if_pending = 1;

	/*if we have cmd to send , we send cmd first , so not send frame  at this time */
	if (hw_priv->wsm_cmd.ptr) {
		++count;
		atbm_spin_lock(&hw_priv->wsm_cmd.lock);
		ATBM_BUG_ON(!hw_priv->wsm_cmd.ptr);
		*data = hw_priv->wsm_cmd.ptr;
		*tx_len = hw_priv->wsm_cmd.len;
		*burst = 1;
		*vif_selected = -1;
		atbm_spin_unlock(&hw_priv->wsm_cmd.lock);
	} else {
		/*get data frame to send  */
		for (;;) {
			int ret;
			struct atbmwifi_vif *priv;
	
			priv = wsm_get_interface_for_tx(hw_priv);
			/* go to next interface ID to select next packet */
			hw_priv->if_id_selected ^= 1;

			/* There might be no interface before add_interface
			 * call */
			if (!priv) {
				if (if_pending) {
					if_pending = 0;
					continue;
				}
				break;
			}
			/* This can be removed probably: atbmwifi_vif will not
			 * be in hw_priv->vif_list (as returned from
			 * wsm_get_interface_for_tx) until it's fully
			 * enabled, so statement above will take case of that*/
			if (!priv->enabled) {
//				spin_unlock(&priv->vif_lock);
				break;
			}

			/* TODO:COMBO: Find the next interface for which
			* packet needs to be found */
			ret = wsm_get_tx_queue_and_mask(priv, &queue,
					&tx_allowed_mask,&total);
			queue_num = queue - hw_priv->tx_queue;
			
			if (priv->buffered_multicasts &&
							(ret || !total) &&
							(priv->tx_multicast ||
							 !priv->sta_asleep_mask)) {
						priv->buffered_multicasts = ATBM_FALSE;
						if (priv->tx_multicast) {
							priv->tx_multicast = ATBM_FALSE;
							atbm_queue_work(priv->hw_priv, priv->set_tim_work);							
						}
					}
			if (ret) {
//				spin_unlock(&priv->vif_lock);
				if (if_pending == 1) {
					if_pending = 0;
					continue;
				}
				break;
			}

			if (atbmwifi_queue_get(queue,
					priv->if_id,
					tx_allowed_mask,
					&wsm,  &txpriv)) {
//				spin_unlock(&priv->vif_lock);
				if_pending = 0;
				wifi_printk(WIFI_ALWAYS," atbmwifi_queue_get @@@@@@@@@@@@@@@@@@@@@\n");
				continue;
			}

			wsm->hdr.id &= __atbm_cpu_to_le16(
					~WSM_TX_IF_ID(WSM_TX_IF_ID_MAX));

			wsm->hdr.id |= atbm_cpu_to_le16(
				WSM_TX_IF_ID(priv->if_id));

			*vif_selected = priv->if_id;
			
			/*here need clear ps mask when txed packet*/
			if(priv->pspoll_mask & BIT(txpriv->raw_link_id)){
				priv->pspoll_mask &= ~BIT(txpriv->raw_link_id);
			}else if(priv->link_id_uapsd_mask & BIT(txpriv->raw_link_id)){
				priv->link_id_uapsd_mask&= ~BIT(txpriv->raw_link_id);
			}

			/*set the frame buffer and len to send to low mac */
			*data = (atbm_uint8 *)wsm;
			*tx_len = __atbm_le16_to_cpu(wsm->hdr.len);
			*burst = total;
			
			hdr=(struct atbmwifi_ieee80211_hdr *)
				&((atbm_uint8 *)wsm)[txpriv->offset];

			/* store index of bursting queue */
			if (*burst > 1)
				hw_priv->tx_burst_idx = queue_num;
			else
				hw_priv->tx_burst_idx = -1;
			if (total>1) {			
				/* more buffered multicast/broadcast frames
				*  ==> set MoreData flag in IEEE 802.11 header
				*  to inform PS STAs */
				hdr->frame_control |=atbm_cpu_to_le16(ATBM_IEEE80211_FCTL_MOREDATA);
				if((atbm_test_bit(WLAN_STA_SP,&priv->link_id_db[txpriv->raw_link_id].sta_priv.flags))&&
					atbmwifi_ieee80211_is_data_qos(hdr->frame_control)){
					qoshdr = atbmwifi_ieee80211_get_qos_ctl(hdr);
					*qoshdr |= ATBM_IEEE80211_QOS_CTL_EOSP;
				}
			}else {	
				if((atbm_test_bit(WLAN_STA_SP,&priv->link_id_db[txpriv->raw_link_id].sta_priv.flags))&&
					atbmwifi_ieee80211_is_data_qos(hdr->frame_control)){
					qoshdr = atbmwifi_ieee80211_get_qos_ctl(hdr);
					*qoshdr |= ATBM_IEEE80211_QOS_CTL_EOSP;
				}				
			}
			wifi_printk(WIFI_WSM, "[WSM] >>> 0x%.4X (%d) %p %c\n",
				0x0004, *tx_len, *data,
				wsm->more ? 'M' : ' ');

			wifi_printk(WIFI_WSM, "[WSM] >>>%x (%d)\n", 
				0x0004, *tx_len);
			++count;
//			spin_unlock(&priv->vif_lock);
			break;
		}
	}

	return count;
}
int wsm_txed(struct atbmwifi_common *hw_priv, atbm_uint8 *data)
{
	if (data == hw_priv->wsm_cmd.ptr) {
		atbm_spin_lock(&hw_priv->wsm_cmd.lock);
		hw_priv->wsm_cmd.ptr = ATBM_NULL;
		atbm_spin_unlock(&hw_priv->wsm_cmd.lock);;
		return  1;
	}
	return 0;
}

/* ******************************************************************** */
/* WSM buffer		*/
#define MAX_WSM_BUF_LEN (1632)//


atbm_void wsm_buf_init(struct wsm_buf *buf)
{
	ATBM_BUG_ON(buf->begin);
	buf->begin = atbm_kmalloc(/*ATBM_SDIO_BLOCK_SIZE*/ MAX_WSM_BUF_LEN,GFP_KERNEL);
	buf->end = buf->begin ? &buf->begin[MAX_WSM_BUF_LEN] : buf->begin;
	wsm_buf_reset(buf);
	//iot_printf("%s hw_priv->wsm_cmd_buf begin 0x%x.data 0x%x \n",__FUNCTION__,buf->begin,buf->data);

}

atbm_void wsm_buf_deinit(struct wsm_buf *buf)
{
	if(buf->begin)
		atbm_kfree(buf->begin);
	buf->begin = buf->data = buf->end = ATBM_NULL;
}

static atbm_void wsm_buf_reset(struct wsm_buf *buf)
{
	if(buf->begin) {
		buf->data = &buf->begin[sizeof(struct wsm_hdr_tx)];
		*(atbm_uint32 *)buf->begin = 0;
	}
	else
		buf->data = buf->begin;
}
 int get_interface_id_scanning(struct atbmwifi_common *hw_priv)
{
	if(hw_priv->scan.in_progress==1||hw_priv->ApScan_in_process==1){
		return hw_priv->scan.if_id;
	}
	else{
		return -1;
	}
}
int wsm_read_shmem(struct atbmwifi_common *hw_priv, atbm_uint32 address, atbm_void *buffer,
			atbm_size_t buf_size)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	atbm_uint16 flags = 0;//0x80|0x40;

	struct wsm_shmem_arg_s wsm_shmem_arg={0};
	wsm_shmem_arg.buf = buffer;
	wsm_shmem_arg.buf_size = buf_size;

	wsm_cmd_lock(hw_priv);

	WSM_PUT32(buf, address);
	WSM_PUT16(buf, buf_size);
	WSM_PUT16(buf, flags);
	ret = wsm_cmd_send(hw_priv, buf, &wsm_shmem_arg, 0x0000, WSM_CMD_TIMEOUT,0);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}
#define HI_STATUS_SUCCESS (0)

int wsm_read_shmem_confirm(struct atbmwifi_common *hw_priv,
				struct wsm_shmem_arg_s *arg, struct wsm_buf *buf)
{
	atbm_uint8 *ret_buf = arg->buf;

	if (ATBM_WARN_ON(WSM_GET32(buf) != HI_STATUS_SUCCESS))
		return -ATBM_EINVAL;

	WSM_GET(buf, ret_buf, arg->buf_size);

	return 0;

underflow:
	ATBM_WARN_ON_FUNC(1);
	return -ATBM_EINVAL;
}

int wsm_write_shmem(struct atbmwifi_common *hw_priv, atbm_uint32 address,atbm_size_t size,
						atbm_void *buffer)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	atbm_uint16 flags = 0;//0x80|0x40;
	struct wsm_shmem_arg_s wsm_shmem_arg={0};
	wsm_shmem_arg.buf = buffer;
	wsm_shmem_arg.buf_size = size;

	wsm_cmd_lock(hw_priv);

	WSM_PUT32(buf, address);
	WSM_PUT16(buf, size);
	WSM_PUT16(buf, flags);
	WSM_PUT(buf, buffer, size);

	ret = wsm_cmd_send(hw_priv, buf, &wsm_shmem_arg, 0x0001, WSM_CMD_TIMEOUT,0);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}


int wsm_write_shmem_confirm(struct atbmwifi_common *hw_priv,
				struct wsm_shmem_arg_s *arg, struct wsm_buf *buf)
{
	if (ATBM_WARN_ON(WSM_GET32(buf) != HI_STATUS_SUCCESS))
		return -ATBM_EINVAL;
	return 0;

//underflow:
//	ATBM_WARN_ON_FUNC(1);
//	return -ATBM_EINVAL;
}

FLASH_FUNC struct atbmwifi_vif *	wsm_get_interface_for_tx(struct atbmwifi_common *hw_priv)
{
	struct atbmwifi_vif *priv = ATBM_NULL;
	
	int i = hw_priv->if_id_selected;
	priv = _atbmwifi_hwpriv_to_vifpriv(hw_priv, i);

	return priv;
}

FLASH_FUNC  int wsm_set_output_power(struct atbmwifi_common *hw_priv,
				       int power_level, int if_id)
{
	atbm_uint32 val = atbm_cpu_to_le32(power_level);
	return wsm_write_mib(hw_priv, WSM_MIB_ID_DOT11_CURRENT_TX_POWER_LEVEL,
			     &val, sizeof(val), if_id);
}

FLASH_FUNC  int wsm_set_beacon_wakeup_period(struct atbmwifi_common *hw_priv,
					       unsigned dtim_interval,
					       unsigned listen_interval,
					       int if_id)
{
	struct {
		atbm_uint8 numBeaconPeriods;
		atbm_uint8 reserved;
		atbm_uint16 listenInterval;
	} val;
	val.numBeaconPeriods=dtim_interval;
	val.reserved=0; 
	val.listenInterval=__atbm_cpu_to_le16(listen_interval);
	if (dtim_interval > 0xFF || listen_interval > 0xFFFF)
		return -22;
	else
		return wsm_write_mib(hw_priv, WSM_MIB_ID_BEACON_WAKEUP_PERIOD,
				     &val, sizeof(val), if_id);
}
FLASH_FUNC  int wsm_set_rcpi_rssi_threshold(struct atbmwifi_common *hw_priv,
					struct wsm_rcpi_rssi_threshold *arg,
					int if_id)
{
	return wsm_write_mib(hw_priv, WSM_MIB_ID_RCPI_RSSI_THRESHOLD, arg,
			     sizeof(*arg), if_id);
}
FLASH_FUNC  int wsm_get_counters_table(struct atbmwifi_common *hw_priv,
					 struct wsm_counters_table *arg,int if_id)
{
	return wsm_read_mib(hw_priv, WSM_MIB_ID_COUNTERS_TABLE,
			arg, sizeof(*arg),if_id);
}

FLASH_FUNC  int wsm_get_station_id(struct atbmwifi_common *hw_priv, atbm_uint8 *mac,int if_id)
{
	return wsm_read_mib(hw_priv, WSM_MIB_ID_DOT11_STATION_ID, mac,
			    ATBM_ETH_ALEN,if_id);
}
FLASH_FUNC  int wsm_set_rx_filter(struct atbmwifi_common *hw_priv,
				    const struct wsm_rx_filter *arg,
				    int if_id)
{
	atbm_uint32 val = 0;
	if (arg->promiscuous)
		val |= atbm_cpu_to_le32(BIT(0));
	if (arg->bssid)
		val |= atbm_cpu_to_le32(BIT(1));
	if (arg->fcs)
		val |= atbm_cpu_to_le32(BIT(2));
	if (arg->probeResponder)
		val |= atbm_cpu_to_le32(BIT(3));
	if (arg->keepalive)
		val |= atbm_cpu_to_le32(BIT(4));
	return wsm_write_mib(hw_priv, WSM_MIB_ID_RX_FILTER, &val, sizeof(val),
			if_id);
}
FLASH_FUNC  int wsm_set_beacon_filter_table(struct atbmwifi_common *hw_priv,
					struct wsm_beacon_filter_table *ft,
					int if_id)
{
	atbm_size_t size = __atbm_le32_to_cpu(ft->numOfIEs) *
		     sizeof(struct wsm_beacon_filter_table_entry) +
		     sizeof(atbm_uint32);

	return wsm_write_mib(hw_priv, WSM_MIB_ID_BEACON_FILTER_TABLE, ft, size,
			if_id);
}
FLASH_FUNC  int wsm_beacon_filter_control(struct atbmwifi_common *hw_priv,
					struct wsm_beacon_filter_control *arg,
					int if_id)
{
	struct {
		atbm_uint32 enabled;
		atbm_uint32 bcn_count;
	} val;
	val.enabled = atbm_cpu_to_le32(arg->enabled);
	val.bcn_count = atbm_cpu_to_le32(arg->bcn_count);
	return wsm_write_mib(hw_priv, WSM_MIB_ID_BEACON_FILTER_ENABLE, &val,
			     sizeof(val), if_id);
}
FLASH_FUNC  int wsm_set_operational_mode(struct atbmwifi_common *hw_priv,
					const struct wsm_operational_mode *arg,
					int if_id)
{
	atbm_uint32 val = arg->power_mode;
	if (arg->disableMoreFlagUsage)
		val |= BIT(4);
	if (arg->performAntDiversity)
		val |= BIT(5);
	return wsm_write_mib(hw_priv, WSM_MIB_ID_OPERATIONAL_POWER_MODE, &val,
			     sizeof(val), if_id);
}
/*AP ?㏒那?那㊣℅??‘2谷?∩????sta 那?﹞?∩|?迆powersave ?㏒那?*/
FLASH_FUNC  int wsm_set_inactivity(struct atbmwifi_common *hw_priv,
					const struct wsm_inactivity *arg,
					int if_id)
{
	struct {
	       atbm_uint8	min_inactive;
	       atbm_uint8	max_inactive;
	       atbm_uint16	reserved;
	} val;

	val.max_inactive = arg->max_inactivity;
	val.min_inactive = arg->min_inactivity;
	val.reserved = 0;

	return wsm_write_mib(hw_priv, WSM_MIB_ID_SET_INACTIVITY, &val,
			     sizeof(val), if_id);
}
FLASH_FUNC  int wsm_set_template_frame(struct atbmwifi_common *hw_priv,
					 struct wsm_template_frame *arg,
					 int if_id)
{
	int ret;
	atbm_uint8 *p = atbm_skb_push(arg->skb, 4);
	p[0] = arg->frame_type;
	p[1] = arg->rate;
	if (arg->disable)
		((atbm_uint16 *) p)[1] = 0;
	else
		((atbm_uint16 *) p)[1] = __atbm_cpu_to_le16(ATBM_OS_SKB_LEN(arg->skb) - 4);
	//dump_mem(p,16);
	//wifi_printk(WIFI_ALWAYS,"Len=%d,arg->disable =%d,arg->rate =%d\n",ATBM_OS_SKB_LEN(arg->skb),arg->disable,hw_priv->etf_rate);
	ret = wsm_write_mib(hw_priv, WSM_MIB_ID_TEMPLATE_FRAME, p,
			    ATBM_OS_SKB_LEN(arg->skb), if_id);
	atbm_skb_pull(arg->skb, 4);
	return ret;
}

FLASH_FUNC  int
wsm_set_protected_mgmt_policy(struct atbmwifi_common *hw_priv,
			      struct wsm_protected_mgmt_policy *arg,
			      int if_id)
{
	atbm_uint32 val = 0;
	int ret;
	if (arg->protectedMgmtEnable)
		val |= atbm_cpu_to_le32(BIT(0));
	if (arg->unprotectedMgmtFramesAllowed)
		val |= atbm_cpu_to_le32(BIT(1));
	if (arg->encryptionForAuthFrame)
		val |= atbm_cpu_to_le32(BIT(2));
	ret = wsm_write_mib(hw_priv, WSM_MIB_ID_PROTECTED_MGMT_POLICY, &val,
			    sizeof(val), if_id);
	return ret;
}

FLASH_FUNC  int wsm_set_block_ack_policy(struct atbmwifi_common *hw_priv,
					   atbm_uint8 blockAckTxTidPolicy,
					   atbm_uint8 blockAckRxTidPolicy,
					   int if_id)
{
	struct {
		atbm_uint8 blockAckTxTidPolicy;
		atbm_uint8 reserved1;
		atbm_uint8 blockAckRxTidPolicy;
		atbm_uint8 reserved2;
	} val;
	val.blockAckTxTidPolicy = blockAckTxTidPolicy;
	val.blockAckRxTidPolicy = blockAckRxTidPolicy;
	return wsm_write_mib(hw_priv, WSM_MIB_ID_BLOCK_ACK_POLICY, &val,
			     sizeof(val), if_id);
}
FLASH_FUNC  int wsm_set_association_mode(struct atbmwifi_common *hw_priv,
					   struct wsm_association_mode *arg,
					   int if_id)
{
	return wsm_write_mib(hw_priv, WSM_MIB_ID_SET_ASSOCIATION_MODE, arg,
			     sizeof(*arg), if_id);
}
FLASH_FUNC  int wsm_set_tx_rate_retry_policy(struct atbmwifi_common *hw_priv,
				struct wsm_set_tx_rate_retry_policy *arg,
				int if_id)
{
	atbm_size_t size = sizeof(struct wsm_set_tx_rate_retry_policy_header) +
	    arg->hdr.numTxRatePolicies *
	    sizeof(struct wsm_set_tx_rate_retry_policy_policy);
	return wsm_write_mib(hw_priv, WSM_MIB_ID_SET_TX_RATE_RETRY_POLICY, arg,
			     size, if_id);
}
FLASH_FUNC  int wsm_set_ether_type_filter(struct atbmwifi_common *hw_priv,
				struct wsm_ether_type_filter_hdr *arg,
				int if_id)
{
	atbm_size_t size = sizeof(struct wsm_ether_type_filter_hdr) +
		arg->nrFilters * sizeof(struct wsm_ether_type_filter);
	return wsm_write_mib(hw_priv, WSM_MIB_ID_SET_ETHERTYPE_DATAFRAME_FILTER,
		arg, size, if_id);
}
FLASH_FUNC  int wsm_set_udp_port_filter(struct atbmwifi_common *hw_priv,
				struct wsm_udp_port_filter_hdr *arg,
				int if_id)
{
	atbm_size_t size = sizeof(struct wsm_udp_port_filter_hdr) +
		arg->nrFilters * sizeof(struct wsm_udp_port_filter);
	return wsm_write_mib(hw_priv, WSM_MIB_ID_SET_UDPPORT_DATAFRAME_FILTER,
		arg, size, if_id);
}
FLASH_FUNC  int wsm_keep_alive_period(struct atbmwifi_common *hw_priv,
					int period, int if_id)
{
	struct wsm_keep_alive_period arg;
	arg.keepAlivePeriod = __atbm_cpu_to_le16(period);
	return wsm_write_mib(hw_priv, WSM_MIB_ID_KEEP_ALIVE_PERIOD,
			&arg, sizeof(arg), if_id);
}
FLASH_FUNC  int wsm_set_bssid_filtering(struct atbmwifi_common *hw_priv,
					  ATBM_BOOL enabled, int if_id)
{
	struct wsm_set_bssid_filtering arg;
	arg.filter = !enabled;
	return wsm_write_mib(hw_priv, WSM_MIB_ID_DISABLE_BSSID_FILTER,
			&arg, sizeof(arg), if_id);
}
FLASH_FUNC  int wsm_set_multicast_filter(struct atbmwifi_common *hw_priv,
					   struct wsm_multicast_filter *fp,
					   int if_id)
{
	return wsm_write_mib(hw_priv, WSM_MIB_ID_DOT11_GROUP_ADDRESSES_TABLE,
			     fp, sizeof(*fp), if_id);
}


FLASH_FUNC  int wsm_set_arp_ipv4_filter(struct atbmwifi_common *hw_priv,
					  struct wsm_arp_ipv4_filter *fp,
					  int if_id)
{
	return wsm_write_mib(hw_priv, WSM_MIB_ID_ARP_IP_ADDRESSES_TABLE,
			    fp, sizeof(*fp), if_id);
}

#ifdef IPV6_FILTERING
FLASH_FUNC  int wsm_set_ndp_ipv6_filter(struct atbmwifi_common *priv,
					  struct wsm_ndp_ipv6_filter *fp,
					  int if_id)
{
	return wsm_write_mib(priv, WSM_MIB_ID_NS_IP_ADDRESSES_TABLE,
			    fp, sizeof(*fp), if_id);
}
#endif /*IPV6_FILTERING*/

FLASH_FUNC  int wsm_set_p2p_ps_modeinfo(struct atbmwifi_common *hw_priv,
					  struct wsm_p2p_ps_modeinfo *mi,
					  int if_id)
{
	return wsm_write_mib(hw_priv, WSM_MIB_ID_P2P_PS_MODE_INFO,
			     mi, sizeof(*mi), if_id);
}

FLASH_FUNC  int wsm_get_p2p_ps_modeinfo(struct atbmwifi_common *hw_priv,
					  struct wsm_p2p_ps_modeinfo *mi,int if_id)
{
	return wsm_read_mib(hw_priv, WSM_MIB_ID_P2P_PS_MODE_INFO,
			    mi, sizeof(*mi),if_id);
}

/* UseMultiTxConfMessage */

FLASH_FUNC  int wsm_use_multi_tx_conf(struct atbmwifi_common *hw_priv,
					ATBM_BOOL enabled, int if_id)
{
	atbm_uint32 arg = enabled ? atbm_cpu_to_le32(1) : 0;

	return wsm_write_mib(hw_priv, WSM_MIB_USE_MULTI_TX_CONF,
			&arg, sizeof(arg), if_id);
}
FLASH_FUNC  int wsm_set_uapsd_info(struct atbmwifi_common *hw_priv,
				     struct wsm_uapsd_info *arg,
				     int if_id)
{
	/* TODO:COMBO:UAPSD will be supported only on one interface */
	return wsm_write_mib(hw_priv, WSM_MIB_ID_SET_UAPSD_INFORMATION,
				arg, sizeof(*arg), if_id);
}
FLASH_FUNC  int
wsm_set_override_internal_txrate(struct atbmwifi_common *hw_priv,
				     struct wsm_override_internal_txrate *arg,
				     int if_id)
{
	return wsm_write_mib(hw_priv, WSM_MIB_ID_OVERRIDE_INTERNAL_TX_RATE,
				arg, sizeof(*arg), if_id);
}

static  int wsm_get_mac_address(struct atbmwifi_common *hw_priv, atbm_uint8 *mac)
{
	return wsm_read_mib(hw_priv, WSM_MIB_ID_MAC_ADDRESS_FROM_EFUSE, mac,
			    ATBM_ETH_ALEN,-1);
}

FLASH_FUNC int wsm_set_wol_enable(struct atbmwifi_common *hw_priv, atbm_uint8 enable, int if_id){
	atbm_uint8 wol_enable = enable;
	return wsm_write_mib(hw_priv, WSM_MIB_ID_START_WOL, &wol_enable,
			    sizeof(atbm_uint8), if_id);
}

/* ******************************************************************** */
/* Queue mapping: WSM <---> linux					*/
/* Linux: VO VI BE BK							*/
/* WSM:   BE BK VI VO							*/

FLASH_FUNC  atbm_uint8 wsm_queue_id_to_linux(atbm_uint8 queueId)
{
	static const atbm_uint8 queue_mapping[] = {
		2, 3, 1, 0
	};
	return queue_mapping[queueId];
}

FLASH_FUNC  atbm_uint8 wsm_queue_id_to_wsm(atbm_uint8 queueId)
{
	static const atbm_uint8 queue_mapping[] = {
		3, 2, 0, 1
	};
	return queue_mapping[queueId];
}






int wsm_set_chantype_func(struct atbmwifi_common *hw_priv,
				    struct wsm_set_chantype *arg,int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	if (atbm_unlikely(arg->band > 1))
		return -ATBM_EINVAL;
	
	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->band);
	WSM_PUT8(buf, arg->flag);
	WSM_PUT16(buf, arg->channelNumber);
	WSM_PUT32(buf, arg->channelType);

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_SET_CHANTYPE_ID, WSM_CMD_TIMEOUT,
			if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}
int wsm_req_chtype_indication(struct atbmwifi_common *hw_priv,
					 struct wsm_buf *buf)
{
	struct wsm_req_chtype_change_ind arg_ind;

	arg_ind.status = WSM_GET32(buf);

	wifi_printk(WIFI_WSM,"%s:status(%d)\n",__FUNCTION__,arg_ind.status);
	return 0;
//underflow:
//	ATBM_WARN_ON_FUNC(1);
//	return -ATBM_EINVAL;
}
int wsm_req_chtype_change_func(struct atbmwifi_common *hw_priv,
				    struct wsm_req_chtype_change *arg,int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;

	wifi_printk(WIFI_WSM,"%s\n",__FUNCTION__);
	wsm_cmd_lock(hw_priv);
	WSM_PUT(buf,arg->MacAddr,6);
	WSM_PUT16(buf, arg->flags);

	ret = wsm_cmd_send(hw_priv, buf, ATBM_NULL, WSM_SEND_CHTYPE_CHG_REQUEST_ID, WSM_CMD_TIMEOUT,
			if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

int wsm_get_cca(struct atbmwifi_common *hw_priv,struct wsm_get_cca_req *arg,
				struct wsm_get_cca_resp *cca_res,
				int if_id)
{
	int ret;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	//iot_printf("%s\n",__FUNCTION__);
	if (atbm_unlikely(arg->rx_phy_enable_num_req<=0))
		return -ATBM_EINVAL;
	
	wsm_cmd_lock(hw_priv);

	WSM_PUT32(buf, arg->flags);
	WSM_PUT32(buf, arg->rx_phy_enable_num_req);
	ret = wsm_cmd_send(hw_priv, buf, cca_res, WSM_GET_CCA_ID, WSM_CMD_TIMEOUT,
			if_id);

	wsm_cmd_unlock(hw_priv);
	
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -ATBM_ENOMEM;
}

int wsm_get_cca_confirm(struct atbmwifi_common *hw_priv,
				struct wsm_get_cca_resp *arg, struct wsm_buf *buf)
{
	atbm_uint32 status = 0;
	status = WSM_GET32(buf);	
	if (ATBM_WARN_ON(status  != HI_STATUS_SUCCESS))
		return -ATBM_EINVAL;

	arg->status = status;
	arg->rx_phy_enable_num_cnf =  WSM_GET32(buf);
	arg->pri_channel_idle_cnt =  WSM_GET32(buf);
	arg->pri_snd_channel_idle_cnt=  WSM_GET32(buf);
	return 0;
//underflow:
		
//     ATBM_WARN_ON_FUNC(1);
 //    return -ATBM_EINVAL;
}
atbm_void atbm_get_mac_address(struct atbmwifi_common *hw_priv)
{
//	int i;
	atbm_uint8 macAddr[6] = {0x00,0x11,0x22,0x44,0x57,0x73};
	
	atbm_memcpy(hw_priv->addresses[0].addr,hw_priv->mac_addr,ATBM_ETH_ALEN);
	atbm_memcpy(hw_priv->addresses[1].addr,hw_priv->mac_addr,ATBM_ETH_ALEN);
	hw_priv->addresses[1].addr[5] = hw_priv->addresses[0].addr[5] + 1;

	
	if (wsm_get_mac_address(hw_priv, &macAddr[0]) == 0)
	{
		if (macAddr[0]| macAddr[1]|macAddr[2]|macAddr[3]|macAddr[4]|macAddr[5])
		{
			atbm_memcpy(hw_priv->addresses[0].addr,macAddr,ATBM_ETH_ALEN);
			atbm_memcpy(hw_priv->addresses[1].addr,hw_priv->addresses[0].addr,ATBM_ETH_ALEN);
			hw_priv->addresses[1].addr[5] =	hw_priv->addresses[0].addr[5] + 1;
		}
	}	

	if (hw_priv->addresses[0].addr[3] == 0 &&
		hw_priv->addresses[0].addr[4] == 0 &&
		hw_priv->addresses[0].addr[5] == 0) {
		hw_priv->addresses[0].addr[3] = (atbm_uint8)atbm_os_random();
		hw_priv->addresses[0].addr[4] = (atbm_uint8)atbm_os_random();
		hw_priv->addresses[0].addr[5] = (atbm_uint8)atbm_os_random();
		hw_priv->addresses[1].addr[3] = hw_priv->addresses[0].addr[3];
		hw_priv->addresses[1].addr[4] = hw_priv->addresses[0].addr[4];
		hw_priv->addresses[1].addr[5] =	hw_priv->addresses[0].addr[5] + 1;
	}
	//atbm_memcpy(hw_priv->addresses[0].addr,macAddr,ATBM_ETH_ALEN);
	//atbm_memcpy(hw_priv->addresses[1].addr,hw_priv->addresses[0].addr,ATBM_ETH_ALEN);
	//hw_priv->addresses[1].addr[5] =	hw_priv->addresses[0].addr[5] + 1;

	wifi_printk(WIFI_ALWAYS,"addresses[0]:[%02x:%02x:%02x:%02x:%02x:%02x]\n",hw_priv->addresses[0].addr[0],
								hw_priv->addresses[0].addr[1],
								hw_priv->addresses[0].addr[2],
								hw_priv->addresses[0].addr[3],
								hw_priv->addresses[0].addr[4],
								hw_priv->addresses[0].addr[5]);
	//iot_printf("addresses[1]:[%pM]\n",hw_priv->addresses[1].addr);
	atbm_memcpy(hw_priv->mac_addr,hw_priv->addresses[0].addr,ATBM_ETH_ALEN);
	//SET_IEEE80211_PERM_ADDR(hw_priv->hw, hw_priv->addresses[0].addr);

}

int wsm_start_tx_param_set(struct atbmwifi_common *hw_priv, struct atbmwifi_vif *priv,ATBM_BOOL start)
{
	struct wsm_template_frame frame;
	struct wsm_set_chantype arg;
//	atbm_uint32 len = hw_priv->etf_len;	
	atbm_uint32 ret;
	
	arg.band = 0;			//0:2.4G,1:5G
	arg.flag = start? BIT(WSM_SET_CHANTYPE_FLAGS__ETF_TEST_START):0;		
	arg.channelNumber = hw_priv->etf_channel;// channel number
	arg.channelType =  hw_priv->etf_channel_type;	// channel type
	
	frame.disable = 0;
	frame.rate = hw_priv->etf_rate;
	frame.frame_type = WSM_FRAME_TYPE_PROBE_REQUEST;

	if(hw_priv->etf_greedfiled == 1){
		arg.flag |= BIT(WSM_SET_CHANTYPE_FLAGS__ETF_GREEDFILED);
	}

	//printk("hw_priv->etf_greedfiled:%d\n", hw_priv->etf_greedfiled);
	
	wifi_printk(WIFI_ALWAYS, "etf_channel = %d etf_channel_type %d\n", hw_priv->etf_channel,hw_priv->etf_channel_type);
	wsm_set_chantype_func(hw_priv,&arg,0);

	if(start==0)
		return -1;

	frame.skb = atbmwifi_ieee80211_send_probe_req(priv,ATBM_NULL,priv->extra_ie,priv->extra_ie_len,0);

	if (!frame.skb)
		return -ATBM_ENOMEM;

	ret = wsm_set_template_frame(hw_priv, &frame, 0);
	if (frame.skb)
		atbm_dev_kfree_skb(frame.skb);
	
	return ret;


}
extern struct test_threshold gthreshold_param;
extern int Atbm_Test_Success;
int wsm_start_tx_param_set_v2(struct atbmwifi_common *hw_priv, struct atbmwifi_vif *priv,ATBM_BOOL start)
{
	struct wsm_template_frame frame;
	struct wsm_set_chantype arg;
//	atbm_uint32 len = hw_priv->etf_len;	
	atbm_uint32 ret;
	
	arg.band = 0;			//0:2.4G,1:5G
	arg.flag = start? BIT(WSM_SET_CHANTYPE_PRB_TPC):0;		
	arg.channelNumber = hw_priv->etf_channel;// channel number
	arg.channelType =  hw_priv->etf_channel_type;	// channel type
	
	frame.disable = 0;
	frame.rate = hw_priv->etf_rate;
	frame.frame_type = WSM_FRAME_TYPE_PROBE_REQUEST;

	if(hw_priv->etf_greedfiled == 1){
		arg.flag |= BIT(WSM_SET_CHANTYPE_FLAGS__ETF_GREEDFILED);
	}

	//printk("hw_priv->etf_greedfiled:%d\n", hw_priv->etf_greedfiled);
	
	wifi_printk(WIFI_ALWAYS, "etf_channel = %d etf_channel_type %d\n", hw_priv->etf_channel,hw_priv->etf_channel_type);
	wsm_set_chantype_func(hw_priv,&arg,0);

	if(start==0)
		return 1;

	{
		struct ATBM_TEST_IE  Atbm_Ie;
		atbm_uint8 out[3]=ATBM_OUI;
		int i;

		Atbm_Ie.ie_id = D11_WIFI_ELT_ID;
		Atbm_Ie.len = sizeof(struct ATBM_TEST_IE)-2;
		memcpy(Atbm_Ie.oui, out,3);
		Atbm_Ie.oui_type = WIFI_ATBM_IE_OUI_TYPE;
		Atbm_Ie.test_type = TXRX_TEST_REQ;
		Atbm_Ie.featureid= gthreshold_param.featureid;
		Atbm_Ie.result[0] = gthreshold_param.rssifilter;
		Atbm_Ie.result[1] = gthreshold_param.rxevm;

		//send test resutl to Golden
		if(Atbm_Test_Success == 1){
			Atbm_Ie.test_type = TXRX_TEST_RESULT;
			Atbm_Ie.resverd = TXRX_TEST_PASS;
			wifi_printk(WIFI_ALWAYS, "Test success and send result to Godlen\n");
		}
		else if(Atbm_Test_Success == -1)
		{
			Atbm_Ie.test_type = TXRX_TEST_RESULT;
			Atbm_Ie.resverd = TXRX_TEST_FAIL;
			wifi_printk(WIFI_ALWAYS, "Test fial and send result to Godlen\n");
		}
		
		if(priv->extra_ie){
			atbm_kfree(priv->extra_ie);
		}
		
		priv->extra_ie = atbm_kmalloc(sizeof(struct ATBM_TEST_IE) * 10, GFP_KERNEL);
		priv->extra_ie_len = sizeof(struct ATBM_TEST_IE) * 10;

		for(i=0; i<10; i++) 
		{
			memcpy(priv->extra_ie + sizeof(struct ATBM_TEST_IE)*i, &Atbm_Ie,sizeof(struct ATBM_TEST_IE));
		}
	}

	frame.skb = atbmwifi_ieee80211_send_probe_req(priv,ATBM_NULL,priv->extra_ie,priv->extra_ie_len,0);

	if (!frame.skb)
		return -ATBM_ENOMEM;

	ret = wsm_set_template_frame(hw_priv, &frame, 0);
	if (frame.skb)
		atbm_dev_kfree_skb(frame.skb);
	
	return ret;
}


int wsm_start_scan_etf(struct atbmwifi_common *hw_priv, struct atbmwifi_vif *priv )
{
	
	struct wsm_scan scan;
	struct wsm_ssid  ssids; 
	struct wsm_scan_ch	ch[2];	


	atbm_uint32 channel = hw_priv->etf_channel;
	atbm_uint32 rate = hw_priv->etf_rate;
	hw_priv->scan.if_id = priv->if_id;
	atbm_memset(&scan,0,sizeof(struct wsm_scan));
	

	
	scan.scanFlags = 0; /* bit 0 set => forced background scan */
	scan.maxTransmitRate = rate;
	scan.autoScanInterval = (0xba << 24)|(30 * 1024); /* 30 seconds, -70 rssi */
	scan.numOfProbeRequests = 0xff;
	scan.numOfChannels =2;
	scan.numOfSSIDs = 1;
	scan.probeDelay = 1;	
	scan.scanType =WSM_SCAN_TYPE_FOREGROUND;


	scan.ssids = &ssids;
	scan.ssids->length = 4;
	atbm_memcpy(ssids.ssid,"tttt",4);
	scan.ch = &ch[0];
	scan.ch[0].number = channel;
	scan.ch[0].minChannelTime= 10;
	scan.ch[0].maxChannelTime= 11;
	scan.ch[0].txPowerLevel= 3;
	scan.ch[1].number = channel;
	scan.ch[1].minChannelTime= 10;
	scan.ch[1].maxChannelTime= 11;
	scan.ch[1].txPowerLevel= 3;

	return wsm_scan(hw_priv,&scan,0);
}

int wsm_start_scan_etf_v2(struct atbmwifi_common *hw_priv, struct atbmwifi_vif *priv )
{
	struct wsm_scan scan;
	struct wsm_ssid  ssids; 
	struct wsm_scan_ch	ch[2];	


	atbm_uint32 channel = hw_priv->etf_channel;
	atbm_uint32 rate = hw_priv->etf_rate;
	hw_priv->scan.if_id = priv->if_id;
	hw_priv->scan.in_progress = 1;
	atbm_memset(&scan,0,sizeof(struct wsm_scan));
	

	
	scan.scanFlags = 0; /* bit 0 set => forced background scan */
	scan.maxTransmitRate = rate;
	scan.autoScanInterval = (0xba << 24)|(30 * 1024); /* 30 seconds, -70 rssi */
	scan.numOfProbeRequests = 200;
	scan.numOfChannels =1;
	scan.numOfSSIDs = 1;
	scan.probeDelay = 5;	
	scan.scanType =WSM_SCAN_TYPE_FOREGROUND;


	scan.ssids = &ssids;
	scan.ssids->length = 0;
	atbm_memcpy(ssids.ssid,"tttttttt",8);
	scan.ch = &ch[0];
	scan.ch[0].number = channel;
	scan.ch[0].minChannelTime= 10;
	scan.ch[0].maxChannelTime= 11;
	scan.ch[0].txPowerLevel= 3;

	return wsm_scan(hw_priv,&scan,0);
}


int wsm_start_tx(struct atbmwifi_common *hw_priv, struct atbmwifi_vif *priv )
{
	hw_priv->bStartTx = 1;
	hw_priv->bStartTxWantCancel = 0;
	wsm_start_tx_param_set(hw_priv,priv,1);
	wsm_start_scan_etf(hw_priv,priv);

	return 0;
}


int wsm_start_tx_v2(struct atbmwifi_common *hw_priv, struct atbmwifi_vif *priv )
{
//	struct wsm_set_chantype arg;
//	struct efuse_headr efuse_data_etf;

	hw_priv->bStartTx = 1;
	hw_priv->bStartTxWantCancel = 1;
	hw_priv->etf_test_v2 = 1;
	priv->if_id = 0;

	//memset(&efuse_data_etf, 0, sizeof(struct efuse_headr));
	//wsm_get_efuse_data(hw_priv,(void *)&efuse_data_etf,sizeof(struct efuse_headr));
	//if(efuse_data_etf.version != 0)
	{
		//wifi_printk(WIFI_DBG_ERROR, "This board already tested and passed!\n");
	}
	priv->scan_no_connect = 1;

	wsm_start_tx_param_set_v2(hw_priv,priv,1);
	wsm_start_scan_etf_v2(hw_priv,priv);

	return 0;
}


int wsm_stop_tx(struct atbmwifi_common *hw_priv, struct atbmwifi_vif *priv )
{
	int ret = 0;
	
	wsm_start_tx_param_set(hw_priv,priv,0);
//	hw_priv->bStartTx = 0;
	hw_priv->bStartTxWantCancel = 1;

	return ret;
}
int wsm_release_vif_tx_buffer(struct atbmwifi_common *hw_priv, int if_id,
				int count)
{
	int ret = 0;

	atbm_spin_lock(&hw_priv->tx_com_lock);
	hw_priv->hw_bufs_used_vif[if_id] -= count;
	atbm_spin_unlock(&hw_priv->tx_com_lock);

	if (!hw_priv->hw_bufs_used_vif[if_id]){
		//FIXME??
		//atbm_os_wakeup_event(&hw_priv->bh_wq);
	}
	if (ATBM_WARN_ON(hw_priv->hw_bufs_used_vif[if_id] < 0))
		ret = -1;
	return ret;
}


atbm_void wsm_alloc_tx_buffer(struct atbmwifi_common *hw_priv)
{
	atbm_spin_lock(&hw_priv->tx_com_lock);
	++hw_priv->hw_bufs_used;
	atbm_spin_unlock(&hw_priv->tx_com_lock);
}

int wsm_release_tx_buffer(struct atbmwifi_common *hw_priv, int count)
{
	int ret = 0;
	atbm_spin_lock(&hw_priv->tx_com_lock);
	hw_priv->hw_bufs_used -= count;
	atbm_spin_unlock(&hw_priv->tx_com_lock);
	if (!(hw_priv->hw_bufs_used )){
		//FIXME??
		//wifi_printk(WIFI_BH,"atbm_bh_wakeup tx_buffer\n");
		//atbm_os_wakeup_event(&hw_priv->bh_wq);
	}
	ret = 1;
	return ret;
}

/*
	@name: wsm_efuse_change_data_cmd
	@param: arg		efuse data
	@returns:	0,											success
				LMC_STATUS_CODE__EFUSE_VERSION_CHANGE	failed because efuse version change  
				LMC_STATUS_CODE__EFUSE_FIRST_WRITE,		failed because efuse by first write   
				LMC_STATUS_CODE__EFUSE_PARSE_FAILED,  		failed because efuse data wrong, cannot be parase
				LMC_STATUS_CODE__EFUSE_FULL,				failed because efuse have be writen full
				
	@description: this function proccesses change efuse data to chip
*/
int wsm_efuse_change_data_cmd(struct atbmwifi_common *hw_priv, const struct efuse_headr *arg, int if_id)
{
	int ret = 0;
	struct wsm_buf *buf = &hw_priv->wsm_cmd_buf;
	atbm_uint16 cmd = WSM_HI_EFUSE_CHANGE_DATA_REQ_ID;

	wsm_cmd_lock(hw_priv);

	WSM_PUT8(buf, arg->specific);
	WSM_PUT8(buf, arg->version);
	WSM_PUT8(buf, arg->dcxo_trim);
	WSM_PUT8(buf, arg->delta_gain1);
	WSM_PUT8(buf, arg->delta_gain2);
	WSM_PUT8(buf, arg->delta_gain3);
	WSM_PUT8(buf, arg->Tj_room);
	WSM_PUT8(buf, arg->topref_ctrl_bias_res_trim);
	WSM_PUT8(buf, arg->PowerSupplySel);
	WSM_PUT(buf, &arg->mac[0], sizeof(arg->mac));

	ret = wsm_cmd_send(hw_priv, buf, NULL, cmd, WSM_CMD_TIMEOUT, if_id);

	wsm_cmd_unlock(hw_priv);
	return ret;

nomem:
	wsm_cmd_unlock(hw_priv);
	return -1;
}


#if ATBM_USB_BUS
enum HW_RESET_TYPE{
	HW_RESET_HIF,//clean channels
	HW_RESET_HIF_SYSTEM,
	HW_RESET_HIF_SYSTEM_USB,
	HW_HOLD_CPU,
	HW_RUN_CPU,
	HW_RESET_HIF_SYSTEM_CPU,
};
#if (PROJ_TYPE>=ARES_B)
#define HW_RESET_REG_CPU   				BIT(16)
#define HW_RESET_REG_HIF   				BIT(17)
#define HW_RESET_REG_SYS   				BIT(18)
#define HW_RESRT_REG_CHIP  				BIT(19)
#define HW_RESET_REG_NEED_IRQ_TO_LMAC	BIT(20)
int atbm_usb_ep0_hw_reset_cmd(struct sbus_priv *self,enum HW_RESET_TYPE type,ATBM_BOOL irq_lmac)
{
	atbm_uint8 request = VENDOR_HW_RESET; //SW
	atbm_uint16 wvalue ;
	atbm_uint16 index ;
	
	static int tmpdata =0;
	if(type==HW_RESET_HIF){
		tmpdata = HW_RESET_REG_HIF;
	}
	else if(type==HW_RESET_HIF_SYSTEM){
		tmpdata = HW_RESET_REG_HIF|HW_RESET_REG_SYS;
	}
	else if(type==HW_RESET_HIF_SYSTEM_USB){
		tmpdata = HW_RESRT_REG_CHIP;
	}
	else if(type==HW_HOLD_CPU){
		tmpdata = HW_RESET_REG_CPU;
	}
	else if(type==HW_RUN_CPU){
		tmpdata = 0;
	}else if (type == HW_RESET_HIF_SYSTEM_CPU)
	{
		tmpdata = HW_RESET_REG_CPU|HW_RESET_REG_HIF|HW_RESET_REG_SYS;
	}
	if(irq_lmac){
		tmpdata |= HW_RESET_REG_NEED_IRQ_TO_LMAC;
	}
	//tmpdata |= 0x40;
	//tmpdata |= VENDOR_HW_RESET<<8;
	wvalue = (tmpdata>>16)&0xff;
	wvalue |= ((request + 0x40 + ((tmpdata>>16)&0xff))<<8)&0xff00;
	index = wvalue;
	wifi_printk(WIFI_ALWAYS,"ep0_hw_reset request %d wvalue %x\n",request,wvalue);
	return atbm_usbctrl_vendorreq_sync(self,request,1,wvalue, index, &tmpdata,0);
}
#endif

#define EP0_CMD_TXFLUSH 0x17690122
#define EP0_CMD_RECOVERY 0x17690123
#define EP0_CMD_LEN 	32
struct atbm_EP0Cmd{
	atbm_uint32 cmd_id;
	atbm_uint32 lmac_seq;
	atbm_uint32 hmac_seq;
	atbm_uint32 data[EP0_CMD_LEN];
};
int atbm_usb_ep0_cmd(struct sbus_priv *self);
void atbm_usb_kill_all_txurb(struct sbus_priv *self);
void atbm_usb_urb_map_show(struct sbus_priv *self);

int wsm_recovery(struct atbmwifi_common *hw_priv)
{
	atbm_uint32 addr = hw_priv->wsm_caps.HiHwCnfBufaddr;
	int ret;
	atbm_uint32 buf[DOWNLOAD_BLOCK_SIZE/4];
	int tx_size=12;
//	int i;
//	unsigned long flags=0;
	struct atbm_EP0Cmd *cmd = (struct atbm_EP0Cmd *)buf;
#if (PROJ_TYPE<ARES_B)
	int loop=5;
#endif	
	if(atbm_bh_is_term(hw_priv)){
		wifi_printk(WIFI_ALWAYS,"wsm_recovery: bh is stop\n");
		return RECOVERY_ERR;
	}
	wifi_printk(WIFI_ALWAYS,"wsm_recovery++,wsm_txframe_num(%d),wsm_txconfirm_num(%d),cmd(%x),hw_bufs_used_vif0[%d],hw_bufs_used_vif1[%d]\n",
		hw_priv->wsm_txframe_num,
		hw_priv->wsm_txconfirm_num,hw_priv->wsm_cmd.cmd,
		hw_priv->hw_bufs_used_vif[0],hw_priv->hw_bufs_used_vif[1]);
	atbm_mdelay(50);
	//atbm_usb_rxlock(hw_priv->sbus_priv);
	__atbm_usb_suspend(hw_priv->sbus_priv);
	wsm_lock_tx_async(hw_priv);
	

#if (PROJ_TYPE<ARES_B)
step1:
	/*
	step1:	try to flush tx data in lmac
	step2:	try to reinitil  lmac.clear all rx/tx data
	*/
	wifi_printk(WIFI_ALWAYS,"wsm_recovery++step1 \n");
	cmd->cmd_id=EP0_CMD_TXFLUSH;
	cmd->lmac_seq=11;
	cmd->hmac_seq=12;

	//printk("wsm_recovery cmd_id %x buf %x tx_size %x addr %x\n",cmd->cmd_id,buf,tx_size,addr);
	
	/* send the block to sram */
	ret = atbm_ep0_write(hw_priv,addr,buf, tx_size);
	if (ret < 0) {
		wifi_printk(WIFI_ALWAYS,"%s:err\n",__func__);
		goto error;

	}
	atbm_usb_ep0_cmd(hw_priv->sbus_priv);
	atbm_mdelay(50);
	atbm_ep0_read(hw_priv,addr,buf, 4);
	atbm_ep0_read(hw_priv,addr+4,buf+1, 4);
	atbm_ep0_read(hw_priv,addr+8,buf+2, 4);
	atbm_ep0_read(hw_priv,addr+12,buf+3, 4);
	atbm_ep0_read(hw_priv,addr+16,buf+4, 4);
	atbm_ep0_read(hw_priv,addr+20,buf+5, 4);
	if(cmd->hmac_seq == cmd->lmac_seq){
		if(cmd->data[0]==cmd->data[1]){
			if(hw_priv->hw_bufs_used <0){
				hw_priv->hw_bufs_used = 0;
			}
			if(hw_priv->hw_bufs_used_vif[0] <0){
				hw_priv->hw_bufs_used_vif[0] = 0;
			}
			if(hw_priv->hw_bufs_used_vif[1] <0){
				hw_priv->hw_bufs_used_vif[1] = 0;
			}			
			__atbm_usb_resume(hw_priv->sbus_priv);
			wsm_unlock_tx_async(hw_priv);
			return RECOVERY_STEP1_SUCCESS;
		}
		else {
			loop--;
			if(loop >0){
				goto step1;
			}
			else{
				goto step2;
			}
		}
	}
step2:
#endif  //(PROJ_TYPE<ARES_B)
	 {

		//lmac may stuck,we need reinitial it
		wifi_printk(WIFI_ALWAYS,"step2 lmac may stuck,we need reinitial it\n");
		cmd->cmd_id=EP0_CMD_RECOVERY;
		cmd->lmac_seq=11;
		cmd->hmac_seq=12;
		tx_size=12;
		atbm_mdelay(50);
		atbm_usb_kill_all_txurb(hw_priv->sbus_priv);
		atbm_usb_kill_all_rxurb(hw_priv->sbus_priv);
		atbm_mdelay(50);
#if (PROJ_TYPE<ARES_B)
		/* send the block to sram */
		ret = atbm_ep0_write(hw_priv,addr,buf, tx_size);
		if (ret < 0) {
			wifi_printk(WIFI_ALWAYS,"%s:err\n",__func__);
			goto error;
		
		}
		atbm_spin_lock_bh(&hw_priv->wsm_cmd.lock);
			hw_priv->hw_bufs_used = 0;
			hw_priv->hw_bufs_used_vif[0] = 0;
			hw_priv->hw_bufs_used_vif[1] = 0;
		//	hw_priv->wsm_tx_seq=0;
		//	hw_priv->wsm_rx_seq=0;
		atbm_spin_unlock_bh(&hw_priv->wsm_cmd.lock);
		atbm_usb_ep0_cmd(hw_priv->sbus_priv);
		atbm_mdelay(50);
		atbm_ep0_read(hw_priv,addr,buf, 4);
		atbm_ep0_read(hw_priv,addr+4,buf+1, 4);
		atbm_ep0_read(hw_priv,addr+8,buf+2, 4);
		atbm_ep0_read(hw_priv,addr+12,buf+3, 4);
		atbm_ep0_read(hw_priv,addr+16,buf+4, 4);
		if(cmd->hmac_seq == cmd->lmac_seq){		
			int i=0;
			/*Delete tx cmp list entry*/
			for (i = 0; i < 4; ++i){
				atbmwifi_queue_clear(&hw_priv->tx_queue[i], ATBM_WIFI_ALL_IFS);
			}
			hw_priv->hw_bufs_used_vif[1] = 0;
			hw_priv->hw_bufs_used_vif[0] = 0;
			hw_priv->hw_bufs_used = 0;
			__atbm_usb_resume(hw_priv->sbus_priv);
			wsm_unlock_tx_async(hw_priv);
			return RECOVERY_STEP2_SUCCESS;
		}
#else //#if (PROJ_TYPE>=ARES_B)
		/* send the block to sram */
        ret = atbm_ep0_write(hw_priv,addr,buf, tx_size);
        if (ret < 0) {
                wifi_printk(WIFI_ALWAYS,"%s:err\n",__func__);
                goto error;

        }
		atbm_usb_ep0_hw_reset_cmd(hw_priv->sbus_priv,HW_RESET_HIF,1);
		hw_priv->wsm_tx_seq=0;	
		hw_priv->wsm_rx_seq=0;
		atbm_mdelay(50);
		{
			int retryCont = 0;
			while (1){
			//printk("wsm_recovery atbm_ep0_read\n");
				atbm_ep0_read(hw_priv,addr,buf, 4);
				if(cmd->cmd_id == 0xffffabcd){
					wifi_printk(WIFI_ALWAYS,"wsm_recovery ARES_B cmd->cmd_id %x\n",cmd->cmd_id);
					break;
				}
				atbm_mdelay(50);
				retryCont++;
				if (retryCont > 20)
				{
					wifi_printk(WIFI_ALWAYS,"wsm_recovery ARES_B atbm_ep0_read retryCont timeout\n");
					break;
				}
			}
		}
		if(cmd->cmd_id == 0xffffabcd){		
			atbm_ep0_read(hw_priv,addr+4,buf+1, 4);
			atbm_ep0_read(hw_priv,addr+8,buf+2, 4);
			atbm_ep0_read(hw_priv,addr+12,buf+3, 4);
			atbm_ep0_read(hw_priv,addr+16,buf+4, 4);
			atbm_ep0_read(hw_priv,addr+20,buf+5, 4);
			wifi_printk(WIFI_ALWAYS,"wsm_recovery hiReq %d,hiConf %d,lmaclastcmd %x\n", cmd->data[0], cmd->data[1],cmd->data[2]);
			{
				int i=0;
				for (i = 0; i < 4; ++i){
					atbmwifi_queue_clear(&hw_priv->tx_queue[i], ATBM_WIFI_ALL_IFS);
				}
				hw_priv->hw_bufs_used_vif[1] = 0;
				hw_priv->hw_bufs_used_vif[0] = 0;
				hw_priv->hw_bufs_used = 0;
			}
			atbm_mdelay(50);
			//atbm_usb_rxunlock(hw_priv->sbus_priv);
			wsm_unlock_tx_async(hw_priv);
			 __atbm_usb_resume(hw_priv->sbus_priv);
			atbm_mdelay(50);
			 /*atbm receive packet form the device*/
			//hw_priv->sbus_ops->lock(hw_priv->sbus_priv);
			//hw_priv->sbus_ops->sbus_memcpy_fromio(hw_priv->sbus_priv,0x2,NULL,RX_BUFFER_SIZE);
			//hw_priv->sbus_ops->unlock(hw_priv->sbus_priv);
			return RECOVERY_STEP2_SUCCESS;
		}
#endif //#if (PROJ_TYPE<ARES_B)
	}
//	atbm_usb_rxunlock(hw_priv->sbus_priv);
	wsm_unlock_tx_async(hw_priv);
	__atbm_usb_resume(hw_priv->sbus_priv);
error:
	return RECOVERY_ERR;
}
int  wsm_recovery_done(struct atbmwifi_common *hw_priv,int type){
   return RECOVERY_STEP2_SUCCESS;
}
#else
struct atbm_SdioCmd{
	atbm_uint32 cmd_id;
	atbm_uint32 lmac_seq;
	atbm_uint32 hmac_seq;
	atbm_uint32 data[32];
};
void wsm_sync_channl_reset(struct atbm_work_struct *work)
{
	struct atbmwifi_vif *priv;
	struct atbmwifi_common *hw_priv =(struct atbmwifi_common *)work;	
	atbm_uint32 addr = hw_priv->wsm_caps.HiHwCnfBufaddr;
	atbm_uint32 buf[DOWNLOAD_BLOCK_SIZE/4];
	struct atbm_SdioCmd *cmd = (struct atbm_SdioCmd *)buf;
	struct wsm_hdr_tx *wsm_tx;
	int ret;
	atbm_uint32 val;
	int loop=100;
	int retry=0;
	
	atbm_uint32 wsm_flag_atbm_uint32  = 0;
	atbm_uint16 wsm_len_atbm_uint16[2];
	atbm_uint16 wsm_len_sum;
	atbm_uint8 forcePacket[16]={0};	
	if(atbm_bh_is_term(hw_priv)){
		wifi_printk(WIFI_ALWAYS, "wsm_sync_channl start error \n");
		return;
	}
	wsm_lock_tx_async(hw_priv);
	ret=atbm_sdio_suspend(hw_priv); 
    hw_priv->sbus_ops->lock(hw_priv->sbus_priv);
	//Do force Packet,just hw_version >=aresB have register 
	wsm_tx=(struct wsm_hdr_tx*)&forcePacket[0];
	
	wsm_flag_atbm_uint32  = (0x10) & 0xffff;
	wsm_len_atbm_uint16[0] = wsm_flag_atbm_uint32  & 0xff;
	wsm_len_atbm_uint16[1] = (wsm_flag_atbm_uint32  >> 8)& 0xff;
	wsm_len_sum = wsm_len_atbm_uint16[0] + wsm_len_atbm_uint16[1];
	if (wsm_len_sum & BIT(8))
	{
		wsm_flag_atbm_uint32  |= ((wsm_len_sum + 1) & 0xff) << 24;
	}else
	{
		wsm_flag_atbm_uint32  |= (wsm_len_sum & 0xff) << 24;
	}
	wsm_tx->flag=atbm_cpu_to_le32(wsm_flag_atbm_uint32 );
	wsm_tx->len=0x10;
	wsm_tx->id=0x55aa;
	do{
		ret=atbm_direct_read_unlock(hw_priv,0xab0016c,&val);
		if(ret<0){
			wifi_printk(WIFI_ALWAYS,"Error %d\n",__LINE__);
			continue;
		}
		if((val&0xe)==0x0){
			wifi_printk(WIFI_ALWAYS,"[%d]: 0xab0016c=%x\n",__LINE__, val);
			break;
		}
		else if((val&0xe)==0x8){
			atbm_data_force_write(hw_priv,(void*)&forcePacket[0],sizeof(forcePacket)/sizeof(forcePacket[0]));
			wifi_printk(WIFI_ALWAYS,"wait LMAC clear error%d\n",__LINE__);
		}
		atbm_mdelay(10);
		wifi_printk(WIFI_ALWAYS,"wsm_sync_channl_reset 2\n");
	}while(1);
	//step 1--> Reuse softirq intr to reninitial lmac 
	atbm_direct_write_unlock(hw_priv,addr,0);
	do{
		ret=atbm_direct_read_unlock(hw_priv,addr,buf);
		if(cmd->cmd_id==0){
			wifi_printk(WIFI_ALWAYS,"Write Mem Success by DirectMode %x=%x\n",addr,cmd->cmd_id);
			break;
		}else{
			wifi_printk(WIFI_ALWAYS,"%s Write Mem Fail by DirectMode,what'happend!!! %d\n",__func__,__LINE__);
			//force transmit last channId
			//atbm_data_force_write(hw_priv,(void*)&forcePacket[0],sizeof(forcePacket)/sizeof(forcePacket[0]));
			atbm_direct_write_unlock(hw_priv,addr,0);
			retry++;
		}
		if(retry>20){
			wifi_printk(WIFI_ALWAYS, "What'happend(RetryTimes) %d\n",retry);
			ATBM_BUG_ON(1);
		}
		atbm_mdelay(100);
	}while(1);
	atbm_direct_read_unlock(hw_priv,0x1610000c,&val);
	val|=BIT(0);
	atbm_direct_write_unlock(hw_priv,0x1610000c,val);
	do{
		//step 2-->Change directMode to read the Lmac reinital status
		ret=atbm_direct_read_unlock(hw_priv,addr,buf);
		if(ret){
			wifi_printk(WIFI_ALWAYS,"Direct Mode ReadErr, what'happend !!!\n");
		}
		//step3-->wait for Lmac initial ok
		if(cmd->cmd_id==0xffffabcd){
			int i=0;
			for (i = 0; i < 4; ++i){
				atbmwifi_queue_clear(&hw_priv->tx_queue[i], ATBM_WIFI_ALL_IFS);
			}
			hw_priv->hw_bufs_used_vif[1] = 0;
			hw_priv->hw_bufs_used_vif[0] = 0;
			hw_priv->hw_bufs_used = 0;
			hw_priv->wsm_tx_seq=0;
			hw_priv->buf_id_tx=0;
			ret=atbm_direct_read_unlock(hw_priv,0xab00160,&val);
			hw_priv->wsm_rx_seq=0;//(((val>>12)&0x7)-1);
			hw_priv->buf_id_rx=hw_priv->wsm_rx_seq;
			break;
		}
		atbm_mdelay(100);
	}while(loop--);
	hw_priv->syncChanl_done=1;
	wsm_unlock_tx_async(hw_priv);
    hw_priv->sbus_ops->unlock(hw_priv->sbus_priv);
 	atbm_sdio_resume(hw_priv);
	atbm_os_wakeup_event(&hw_priv->wsm_synchanl_done);
	wifi_printk(WIFI_ALWAYS,"wsm_sync_channl reset end \n");
}

int  wsm_sync_channle_process(struct atbmwifi_common *hw_priv,int type) 
{
	int retFlush; 
	retFlush=wsm_recovery(hw_priv); 
	if(retFlush==RECOVERY_STEP2_SUCCESS){ 
		retFlush=wsm_recovery_done(hw_priv,type); 
		return retFlush;
	} 
	return retFlush;
}
int wsm_recovery(struct atbmwifi_common *hw_priv)
{
#if(PROJ_TYPE < ARES_A)
	return RECOVERY_ERR;
#endif
	if(hw_priv->syncChanl_done==0){
	  return RECOVERY_STEP1_SUCCESS;
	}
	//sync channle
	hw_priv->syncChanl_done=0;
	atbm_queue_work(hw_priv,hw_priv->wsm_sync_channl);
	return RECOVERY_STEP2_SUCCESS;
}
int  wsm_recovery_done(struct atbmwifi_common *hw_priv,int type)
{
	int status;
	if(type==OUT_BH){
	    status=atbm_os_wait_event_timeout(&hw_priv->wsm_synchanl_done,120*HZ);
	}
    if(status<=0){
        wifi_printk(WIFI_ALWAYS,"sync Channle timeout,what happend !!!  Do wtd_process\n");
        return RECOVERY_ERR; 
    }
	return RECOVERY_STEP2_SUCCESS;
}
#endif


