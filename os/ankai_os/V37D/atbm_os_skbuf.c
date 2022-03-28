#include "atbm_hal.h"
#include "lwip/netif.h"
#include "netif/etharp.h"
#include "atbm_os_skbuf.h"

int lwip_queue_enable = 0;
int lwip_enable = 0;
extern struct atbmwifi_vif *  g_vmac;
extern void atbm6031_wifi_input(void *buf,int len);

atbm_void atbm_set_netif(struct netif *pNetIf)
{
	wifi_printk(WIFI_ALWAYS,"%s %d\n",__func__,__LINE__);
	if(g_vmac){
		g_vmac->ndev->nif = pNetIf;
		pNetIf->state = g_vmac->ndev; 
	}
}
atbm_void atbm_netdev_registed(struct netif *pNetIf)
{
	
}
atbm_void atbm_lwip_init(struct atbm_net_device *dev)
{
	//hal_create_mutex(&lwip_mutex);
}
extern int atbm_akwifi_netif_init(void);

atbm_void atbm_lwip_enable(struct atbm_net_device *dev)
{
	struct atbmwifi_vif * priv = netdev_drv_priv(dev);
	lwip_queue_enable = 1;
	lwip_enable = 1;

	if(priv->join_status == ATBMWIFI__JOIN_STATUS_AP)
		atbm_akwifi_netif_init();
	//FIXME add callback event here


}

atbm_void atbm_lwip_disable(struct atbm_net_device *dev)
{
	//lwip_queue_enable = 0;
	lwip_enable = 0;
	lwip_queue_enable = 0;
	//FIXME add callback event here

	//netif_set_down(xNetIf);


}

atbm_void atbm_lwip_txdone(struct atbm_net_device *dev)
{
}

atbm_void atbm_lwip_wake_queue(struct atbm_net_device *dev,int num)
{
	if(!lwip_queue_enable && lwip_enable){
		lwip_queue_enable = 1;
	}
}

atbm_void atbm_lwip_stop_queue(struct atbm_net_device *dev,int num)
{
	if(lwip_queue_enable && lwip_enable){
		//hal_wait_for_mutex(&lwip_mutex,2000);
		lwip_queue_enable = 0;
	}
}

atbm_void atbm_lwip_task_event(struct atbm_net_device *dev)
{
}
struct atbm_net_device * atbm_alloc_netdev(atbm_int32 size)
{
	struct atbm_net_device *  netdev = atbm_kmalloc(size + sizeof(struct atbm_net_device),GFP_KERNEL);

	ATBM_ASSERT((netdev != ATBM_NULL));
	if(netdev)
		atbm_memset(netdev,0,(size + sizeof(struct atbm_net_device)));

	netdev->nif = atbm_kmalloc(sizeof(struct netif),GFP_KERNEL);
	ATBM_ASSERT(netdev->nif != ATBM_NULL);
	if(netdev->nif)
		atbm_memset(netdev->nif,0,sizeof(struct netif));
	wifi_printk(WIFI_ALWAYS,"atbm_alloc_netdev,netdev(%x),nif(%x)\n",netdev,netdev->nif);
	return  netdev;
}
atbm_void * netdev_drv_priv(struct atbm_net_device *ndev)
{
	return &ndev->drv_priv[0];

}


atbm_void atbm_free_netdev(struct atbm_net_device * netdev)
{
	if(netdev != ATBM_NULL)
		atbm_kfree(netdev);
}


FLASH_FUNC int  atbm_register_netdevice(struct atbm_net_device *netdev)
{
#if 0
#ifdef ATBM_COMB_IF
	err_t main_netif_init(struct netif *netif);
	extern err_t tcpip_input(struct pbuf *p, struct netif *inp);
//	int ifindex = if_netdev2index(netdev);
	static int ifindex = 0;
	struct ip_addr netmask, gw, ip_addr;
	wifi_printk(WIFI_DBG_INIT,"register_netdevice %x\n",netdev);

	netmask.addr = 0;
	gw.addr = 0;
	ip_addr.addr = 0;
	if(netif_add(netdev->nif, &ip_addr, &netmask, &gw, 0, main_netif_init, tcpip_input) == ATBM_NULL){
//		DEBUG(1,1,"netif_add failed\n");
		return -1;
	}
	netif_set_default(netdev);
	ifindex++;
#else
	extern struct netif main_netdev;
	netdev->nif = &main_netdev;
	netdev->nif->state = netdev;
	atbm_netdev_registed(netdev->nif);
#endif
#else
	netdev = netdev;
#endif
	return 0;
}

FLASH_FUNC atbm_void atbm_unregister_netdevice(struct netif * netdev)
{
#ifdef ATBM_COMB_IF	
//	int ifindex =  if_netdev2index(netdev);
	netif_set_down(netdev);
	netif_set_default(ATBM_NULL);
//	g_wifinetif[ifindex] = NULL;

	netif_remove(netdev);
#endif	
	return ;
}


#if defined (WLAN_ZERO_COPY1)	
int atbm_os_skb_alloc_cnt =0;
int atbm_os_skb_free_cnt =0;

struct atbm_buff * atbm_dev_decriptor_os_skb(struct atbm_buff *atbm_buf , struct pbuf *p) 
{
	ATBM_OS_SKB_HEAD(atbm_buf) = p->aheadroom;
	ATBM_OS_SKB_DATA(atbm_buf) = p->payload;
	//atbm_buf->dlen = p->len;

	atbm_buf->ref = 1;
	atbm_buf->bufferLen = p->len + WLAN_HEADROOM_SIZE;
	
	atbm_buf->pOsBuffer = p;
	atbm_buf->is_os_buffer = 1;
	atbm_os_skb_alloc_cnt++;
	/*add for wifi*/
	ATBM_OS_SKB_LEN(atbm_buf) = p->len;
	atbm_buf->Tail = ATBM_OS_SKB_DATA(atbm_buf)+ATBM_OS_SKB_LEN(atbm_buf);
}



struct atbm_buff * atbm_dev_save_free_os_skb(struct atbm_buff * atbm_buf) 
{
	struct pbuf *p = atbm_buf->pOsBuffer;
	
	if(atbm_buf->is_os_buffer){
		atbm_os_skb_free_cnt++;
		//just save addr1 and framecontrol 
		ATBM_OS_SKB_DATA(atbm_buf) = ATBM_MEM_ALIGN((void *)((atbm_uint8 *)atbm_buf + sizeof(struct atbm_buff) + ATBM_HWBUF_EXTERN_HEADROM_LEN));
		memcpy(ATBM_OS_SKB_DATA(atbm_buf),p->payload,10);
		//free tcpip pbuf
		_pbuf_free(p);
		atbm_buf->pOsBuffer = ATBM_NULL;
		atbm_buf->is_os_buffer = 0;
		atbm_skb_reinit(atbm_buf);
	}
		
	
	//atbm_dev_kfree_skb(atbm_buf);
}

struct atbm_buff * atbm_dev_free_os_skb(struct atbm_buff * atbm_buf) 
{
	struct pbuf *p = atbm_buf->pOsBuffer;
	
	if(atbm_buf->is_os_buffer){
		atbm_os_skb_free_cnt++;
		_pbuf_free(p);
		atbm_buf->pOsBuffer = ATBM_NULL;
		atbm_buf->is_os_buffer = 0;
	}		
	
	//atbm_dev_kfree_skb(atbm_buf);
}

#endif  //#if defined (WLAN_ZERO_COPY1)	

/****************************************************************************
* Function:   	atbm_wifi_tx_pkt
*
* Purpose:   	This function is used to send packet to wifi driver
*
* Parameters: point to buffer of packet
*
* Returns:	None.
******************************************************************************/
err_t atbm_wifi_tx_pkt_netvif(struct netif *netif, struct pbuf *p)
{
	struct pbuf *q = p;
	struct pbuf *temp_pbuf=ATBM_NULL;
	struct atbm_buff *AtbmBuf = ATBM_NULL;
	struct atbmwifi_vif *priv = (struct atbmwifi_vif *)(netif->state);
	if(priv == ATBM_NULL)
	{
		return -1;
	}
	//If the atbmQueue is full,pls drop??? 
	if(!lwip_queue_enable){
		return 0;
	}
	

	AtbmBuf = atbm_dev_alloc_skb(p->tot_len);
	if (!AtbmBuf)
	{
		ATBM_BUG_ON(1);
		wifi_printk(WIFI_TX,"<ERROR> tx_pkt alloc skb \n");
		return;
	}
	/*Here should copy pubf chain packet to atbmBuf*/
    for (temp_pbuf = p; temp_pbuf != NULL; temp_pbuf = temp_pbuf->next){
		atbm_memcpy(atbm_skb_put(AtbmBuf,temp_pbuf->len), temp_pbuf->payload, temp_pbuf->len);
		/*if q->len==q->tot_len,it means that it is the last packet*/
		if ( temp_pbuf->len == temp_pbuf->tot_len) {
			break;
		}
	}
	if(priv->ndev && priv->ndev->netdev_ops){
		priv->ndev->netdev_ops->ndo_start_xmit(priv, AtbmBuf);
	}else{
		ATBM_BUG_ON(1);
		atbm_dev_kfree_skb(AtbmBuf);
	}

	return 0;
}
#if 0 //charlie add
atbm_void atbm_wifi_tx_pkt(atbm_void *p)//(atbm_void *AtbmBuf)
{

	extern int gbWifiConnect;
	atbm_wifi_tx_pkt_netvif(g_vmac->ndev->nif,p);
	return;
}
#else
atbm_void atbm_wifi_tx_pkt(atbm_void *AtbmBuf)
{
	atbm_int32 retry = 5;
    struct atbmwifi_vif *priv = g_vmac;

	while(!lwip_queue_enable){
		if(retry){
			atbm_SleepMs(20);
		}else{
			return;
		}
		retry--;
	}

    if(priv->ndev && priv->ndev->netdev_ops){
	    priv->ndev->netdev_ops->ndo_start_xmit(priv, AtbmBuf);
    } else {
        ATBM_BUG_ON(1);
        atbm_dev_kfree_skb(AtbmBuf);
    }
}
#endif

//void  ethernetif_input(struct netif *netif, void *p_buf,int size);
static atbm_void __atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *atbm_skb) 
{
	atbm_uint16 len = 0;
	atbm_uint8 *data=ATBM_NULL;
	ATBM_NETIF *netif = dev->nif;
	data = ATBM_OS_SKB_DATA(atbm_skb);
	/* Obtain the size of the packet and put it into the "len" variable. */
	len = ATBM_OS_SKB_LEN(atbm_skb);
	if(netif==NULL){
		goto RcvErr;
	}
	if (0 == len) {
		goto RcvErr;
	}

	atbm6031_wifi_input(data, len);
	atbm_dev_kfree_skb(atbm_skb);
	return;
RcvErr:
	atbm_dev_kfree_skb(atbm_skb);
	atbm_skb=ATBM_NULL;
	return;
	
}

//not required here ,   lwip_tcp_opt.net_rx = ethernetif_input.
atbm_void atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)   
{
#if 1 //charlie add
	struct eth_hdr *ethhdr;

	ethhdr = (struct eth_hdr *)ATBM_OS_SKB_DATA(at_skb);

	switch (htons(ethhdr->type)) {
	  /* IP or ARP packet? */
	  case ETHTYPE_IP:
	  case ETHTYPE_ARP:
	  case 0x888E:
#if PPPOE_SUPPORT
	  /* PPPoE packet? */
	  case ETHTYPE_PPPOEDISC:
	  case ETHTYPE_PPPOE:
#endif /* PPPOE_SUPPORT */
	    /* full packet send to tcpip_thread to process */
	   
	    __atbm_wifi_rx_pkt(dev,at_skb);
	    break;

	  default:
	  	//wifi_printk(WIFI_ALWAYS,"atbm_wifi_rx_pkt free ather pkg\n");
	    atbm_dev_kfree_skb(at_skb);
	    break;
	}
	/* Receive the complete packet */
#else
	atbm_uint16 len = 0;
	atbm_uint8 *data=ATBM_NULL;

	data = ATBM_OS_SKB_DATA(at_skb);
	len = ATBM_OS_SKB_LEN(at_skb);

    atbm6031_wifi_input(data, len);
    atbm_dev_kfree_skb(at_skb);

#endif

}




struct tcpip_opt lwip_tcp_opt ={
	.net_init = atbm_lwip_init,
	.net_enable = atbm_lwip_enable,//
	.net_disable = atbm_lwip_disable,//
	.net_rx = atbm_wifi_rx_pkt,
	.net_tx_done =	atbm_lwip_txdone,
	.net_start_queue =	atbm_lwip_wake_queue,
	.net_stop_queue =	atbm_lwip_stop_queue,
	.net_task_event =	atbm_lwip_task_event,//
};
atbm_void atbm_skbbuffer_init(void)
{
}

