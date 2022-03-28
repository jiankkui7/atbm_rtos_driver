#include "atbm_hal.h"
#include "atbm_os_skbuf.h"
int lwip_queue_enable = 0;
int lwip_enable = 0;
extern struct atbmwifi_vif *  g_vmac;
extern 	struct netif *p_netif;

err_t atbm_wifi_tx_pkt_netvif(ATBM_NETIF *netif, struct pbuf *p);
atbm_void atbm_set_netif(ATBM_NETIF *pNetIf)
{
	if(g_vmac){
		g_vmac->ndev->nif = pNetIf;
		pNetIf->state = g_vmac->ndev; 
	}
}
struct netif *atbm_priv_get_netif(void)
{
	return g_vmac->ndev->nif;
}

atbm_void atbm_netdev_registed(ATBM_NETIF*pNetIf)
{
	
}
atbm_void atbm_lwip_init(struct atbm_net_device *dev)
{
}
extern int atbm_akwifi_netif_init(void);

atbm_void atbm_lwip_enable(struct atbm_net_device *dev)
{
	struct atbmwifi_vif * priv = netdev_drv_priv(dev);
	lwip_queue_enable = 1;
	lwip_enable = 1;
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

static atbm_low_level_init(ATBM_NETIF *netif){
	struct atbmwifi_vif *priv = (struct atbmwifi_vif *)(netif->state);
	
	/*Set interface name*/
	netif->name[0] = 'w';
	netif->name[1] = 'l';
	/* set MAC hardware address length */
	netif->hwaddr_len = ETHARP_HWADDR_LEN;
	/* maximum transfer unit */
	netif->mtu = 1500;
	atbm_memcpy(netif->hwaddr,priv->mac_addr,netif->hwaddr_len);
	
	/* device capabilities */
	/* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
	
}
err_t atbm_lwip_netif_init(ATBM_NETIF *netif)
{
	netif->state = g_vmac;
	netif->output = etharp_output;
	netif->linkoutput = atbm_wifi_tx_pkt_netvif;
	atbm_low_level_init(netif);
	return 0;
}
FLASH_FUNC int  atbm_register_netdevice(struct atbm_net_device *netdev)
{
	ip_addr_t ipaddr;
	ip_addr_t netmask;
	ip_addr_t gw;

	ATBM_NETIF *p_netif_atbm = ATBM_NULL;
	if(!netdev){
		wifi_printk(WIFI_ALWAYS,"NetDev is Null return \n");
		return 0;
	}	
		
	IP4_ADDR(&ipaddr, AP_GW_ADDR0, AP_GW_ADDR1, AP_GW_ADDR2, AP_GW_ADDR3);
	IP4_ADDR(&netmask, AP_NETMASK_ADDR0, AP_NETMASK_ADDR1 , AP_NETMASK_ADDR2, AP_NETMASK_ADDR3);
	IP4_ADDR(&gw, AP_GW_ADDR0, AP_GW_ADDR1, AP_GW_ADDR2, AP_GW_ADDR3);

	p_netif_atbm = netdev->nif;
	p_netif=p_netif_atbm;

	if(p_netif_atbm == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init p_netif_atbm == ATBM_NULL\n");	
		return 0;
	}
	netif_remove(p_netif_atbm);
	if (netif_add(p_netif_atbm, &ipaddr, &netmask, &gw, (void*)g_vmac, atbm_lwip_netif_init, tcpip_input) == 0)
	{
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init netif_add err\n");	
		return  - 1;
	}
	netif_set_default(p_netif_atbm);
	netif_set_up(p_netif_atbm);
	return 0;

}
FLASH_FUNC int  atbm_register_Station_netdevice(struct atbm_net_device *netdev)
{
	ip_addr_t ipaddr;
	ip_addr_t netmask;
	ip_addr_t gw;

	ATBM_NETIF *p_netif = ATBM_NULL;
	if(!netdev){
		wifi_printk(WIFI_ALWAYS,"NetDev is Null return \n");
		return 0;
	}	
		
	IP4_ADDR(&ipaddr, IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
	IP4_ADDR(&netmask, NETMASK_ADDR0, NETMASK_ADDR1 , NETMASK_ADDR2, NETMASK_ADDR3);
	IP4_ADDR(&gw, GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);

	p_netif = netdev->nif;

	if(p_netif == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init p_netif == ATBM_NULL\n");	
		return 0;
	}
	netif_remove(p_netif);
	if (netif_add(p_netif, &ipaddr, &netmask, &gw, (void*)g_vmac, atbm_lwip_netif_init, tcpip_input) == 0)
	{
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init netif_add err\n");	
		return  - 1;
	}
	netif_set_default(p_netif);
	netif_set_up(p_netif);
	
	if (dhcp_start(p_netif) !=0)
	{
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init dhcp_start err\n");	
		return -1;
	}
	return 0;

}

FLASH_FUNC atbm_void atbm_unregister_netdevice(struct atbm_net_device * netdev)
{
	ATBM_NETIF *p_netif = ATBM_NULL;
	p_netif = netdev->nif;
	/* set interface down */
	netif_set_down(p_netif);
	/*  Registers the default network interface to NULL */
	netif_set_default(ATBM_NULL);
	//Remove the interface
	netif_remove(p_netif);

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
extern long data_count;
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
	unsigned long flags;
	struct pbuf *temp_pbuf=ATBM_NULL;
	struct atbm_buff *AtbmBuf = ATBM_NULL;
	atbm_uint32 t1;
	struct atbmwifi_vif *priv = (struct atbmwifi_vif *)netif->state;
	if(priv == ATBM_NULL ||p==ATBM_NULL)
	{
		ATBM_BUG_ON(1);
		wifi_printk(WIFI_ALWAYS,"atbm_wifi_tx_pkt priv== ATBM_NULL\n");
		return 0;
	}
	//If the atbmQueue is full,pls drop??? 
	t1 = atbm_GetOsTime();
	while(!lwip_queue_enable && 200>(atbm_uint32)(atbm_GetOsTime()-t1)){
		atbm_SleepMs(10);
		//return 0;
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

atbm_void atbm_wifi_tx_pkt(atbm_void *p)
{
	extern int gbWifiConnect;
	atbm_wifi_tx_pkt_netvif(g_vmac->ndev->nif,p);
	return;
}

//void  ethernetif_input(struct netif *netif, void *p_buf,int size);
static atbm_void __atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *atbm_skb) 
{
	struct pbuf *p=ATBM_NULL;
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
	p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
	//p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
	if (p == ATBM_NULL){
		ATBM_BUG_ON(1);
		goto AllocErr;
	}	
	pbuf_take(p,data,len);
	/* full packet send to tcpip_thread to process */
	if(netif->input){
		if(netif->input(p,netif)!=ERR_OK){
			goto AllocErr;
		}
	}else{
		goto AllocErr;
	}
	atbm_dev_kfree_skb(atbm_skb);
	return;
AllocErr:
	if(p){
		wifi_printk(WIFI_ALWAYS,"Rx Why Here !!!\n");
		pbuf_free(p);
	}
RcvErr:
	atbm_dev_kfree_skb(atbm_skb);
	atbm_skb=ATBM_NULL;
	p=ATBM_NULL;
	return;

}
atbm_void atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)   //not required here ,   lwip_tcp_opt.net_rx = ethernetif_input.
{

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

