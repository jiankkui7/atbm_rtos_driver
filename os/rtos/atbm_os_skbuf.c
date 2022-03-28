#include "atbm_os_skbuf.h"


//add by wp
//hal_mutex_t lwip_mutex;
int lwip_queue_enable = 0;
int lwip_enable = 0;

atbm_void atbm_lwip_init(struct net_device *dev)
{
	//hal_create_mutex(&lwip_mutex);
}

atbm_void atbm_lwip_enable(struct net_device *dev)
{
	lwip_queue_enable = 1;
	lwip_enable = 1;
	//FIXME add callback event here



}

atbm_void atbm_lwip_disable(struct net_device *dev)
{
	//lwip_queue_enable = 0;
	lwip_enable = 0;
	lwip_queue_enable = 0;
	//FIXME add callback event here

	netif_set_down(xNetIf);


}

atbm_void atbm_lwip_txdone(struct net_device *dev)
{
}

atbm_void atbm_lwip_wake_queue(struct net_device *dev,int num)
{
	if(!lwip_queue_enable && lwip_enable){
		lwip_queue_enable = 1;
	}
}

atbm_void atbm_lwip_stop_queue(struct net_device *dev,int num)
{
	if(lwip_queue_enable && lwip_enable){
		//hal_wait_for_mutex(&lwip_mutex,2000);
		lwip_queue_enable = 0;
	}
}

atbm_void atbm_lwip_task_event(struct net_device *dev)
{
}


struct net_device * atbm_alloc_netdev(atbm_int32 size)
{
	struct net_device *  netdev = atbm_kmalloc(size + sizeof(struct net_device),GFP_KERNEL);

	ATBM_ASSERT((netdev != ATBM_NULL));
	if(netdev)
		atbm_memset(netdev,0,(size + sizeof(struct net_device)));

	//netdev->nif = (struct netif *)((char *)netdev+ sizeof(struct net_device));
	return  netdev;
}

atbm_void * netdev_drv_priv(struct net_device *ndev)
{
	return &ndev->drv_priv[0];

}


atbm_void atbm_free_netdev(struct net_device * netdev)
{
	if(netdev != ATBM_NULL)
		free(netdev);
}


FLASH_FUNC int  atbm_register_netdevice(struct netif * netdev)
{
/*
	int ifindex = if_netdev2index(netdev);
	struct ip_addr netmask, gw, ip_addr;
	struct net_ip_info * ipinfo =  &g_wifi_ipinfo[ifindex];

	wifi_printk(WIFI_DBG_INIT,"atbm_register_netdevice %x\n",netdev);

	g_wifinetif[ifindex] = netdev;

	IP4_ADDR(&ip_addr,	ipinfo->ip_addr[0], ipinfo->ip_addr[1], ipinfo->ip_addr[2], ipinfo->ip_addr[3]);
	IP4_ADDR(&gw,		ipinfo->gw[0], ipinfo->gw[1], ipinfo->gw[2], ipinfo->gw[3]);
	IP4_ADDR(&netmask,	ipinfo->netmask[0], ipinfo->netmask[1], ipinfo->netmask[2], ipinfo->netmask[3]);

	if(netif_add(netdev, &ip_addr, &netmask, &gw, 0, ethernetif_init, tcpip_input) == NULL){????????
		DEBUG(1,1,"netif_add failed\n");
		return -1;
	}
	netif_set_default(netdev);
	//netif_set_up(netdev);
*/
	return 0;
}

FLASH_FUNC atbm_void unregister_netdevice(struct netif * netdev)
{
	/*
	int ifindex =  if_netdev2index(netdev);
	netif_set_down(netdev);
	netif_set_default(NULL);
	g_wifinetif[ifindex] = NULL;

	netif_remove(netdev);
	*/
	return ;
}







/****************************************************************************
* Function:   	atbm_wifi_tx_pkt
*
* Purpose:   	This function is used to send packet to wifi driver
*
* Parameters: point to buffer of packet
*
* Returns:	None.
******************************************************************************/
atbm_void atbm_wifi_tx_pkt(struct pbuf *p)
{
	struct atbmwifi_vif *priv;
	priv = g_vmac;
	if(priv == ATBM_NULL)
	{
		return;
	}

	struct pbuf *q = p;


	struct atbm_buff *pSkbuf = ATBM_NULL;


	pSkbuf = atbm_dev_alloc_skb(p->tot_len);
	if (!pSkbuf)
	{
		wifi_printk(WIFI_TX,"<ERROR> tx_pkt alloc skb \n");
		return;
	}

	while (q) {
		/* Copy the data from the pbuf to the interface buf, one pbuf at a
		   time. The size of the data in each pbuf is kept in the ->len
		   variable. */

		wifi_printk(WIFI_TX,"q->tot_len:%d,q->len:%d\n",q->tot_len,q->len);

		atbm_memcpy((atbm_void *)(&(pSkbuf->abuf[pSkbuf->dlen])), q->payload, q->len);
		atbm_skb_put(pSkbuf, q->len);

		/* Check if this is the last pbuf of the packet. If yes, then break */
		if (q->len == q->tot_len) {
			break;
		} else {
			q = q->next;
		}
	}

	pSkbuf->priority = 0;
	//atbmwifi_tx_start(pSkbuf, priv->ndev);
	if(priv->ndev && priv->ndev->netdev_ops){
		priv->ndev->netdev_ops->ndo_start_xmit(priv->ndev, pSkbuf);
	}
	return;
}


atbm_uint32 atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)   //not required here ,   lwip_tcp_opt.net_rx = ethernetif_input.
{

	wifi_printk(("passing to LWIP layer, packet len %d \n", ATBM_OS_SKB_LEN(at_skb)));
	struct pbuf *p, *q;
	atbm_uint16 len = 0;
	atbm_uint8 *frame_ptr;
	/* Receive the complete packet */
	frame_ptr = ATBM_OS_SKB_DATA(at_skb);
	/* Obtain the size of the packet and put it into the "len" variable. */
	len = ATBM_OS_SKB_LEN(at_skb);
	if (0 == len) {
		return 0;
	}
	/* We allocate a pbuf chain of pbufs from the pool. */
	p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);

	LWIP_DEBUGF(NETIF_DEBUG, ("processing pbufs\n"));
	/* We iterate over the pbuf chain until we have read the entire packet into the pbuf. */
	if (p != ATBM_NULL)
	{
		for (q = p; q != ATBM_NULL; q = q->next) {
			atbm_memcpy(q->payload, frame_ptr, q->len);
			frame_ptr += q->len;
		}
		/* full packet send to tcpip_thread to process */

		host_network_process_ethernet_data(p,netif);
		atbm_dev_kfree_skb(at_skb);

	} else
	{
		atbm_dev_kfree_skb(at_skb);
		LWIP_DEBUGF(NETIF_DEBUG, ("mem error\n"));
		return -1;
	}
	return 0;
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


