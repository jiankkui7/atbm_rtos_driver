#include "atbm_hal.h"
#include "atbm_os_skbuf.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/def.h"
#include "netif/etharp.h"

extern struct atbmwifi_vif *  g_vmac;

atbm_void atbm_lwip_enable(struct atbm_net_device *dev)
{
	wifi_printk(WIFI_ALWAYS,"%s\n", __func__);
}

atbm_void atbm_lwip_disable(struct atbm_net_device *dev)
{
	wifi_printk(WIFI_ALWAYS,"%s\n", __func__);
}

atbm_void atbm_lwip_txdone(struct atbm_net_device *dev)
{
}

atbm_void atbm_lwip_wake_queue(struct atbm_net_device *dev,int num)
{
	wifi_printk(WIFI_ALWAYS,"%s\n", __func__);
}

atbm_void atbm_lwip_stop_queue(struct atbm_net_device *dev,int num)
{
	wifi_printk(WIFI_ALWAYS,"%s\n", __func__);
}

atbm_void atbm_lwip_task_event(struct atbm_net_device *dev)
{
	wifi_printk(WIFI_ALWAYS,"%s\n", __func__);
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
	wifi_printk(WIFI_ALWAYS,"%s,netdev(%x),nif(%x)\r\n",__func__, netdev, netdev->nif);
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

	netdev = netdev;

	return 0;
}

err_t atbm_wifi_tx_pkt_netvif(struct netif *netif, struct pbuf *p)
{
	struct pbuf *q = p;
	struct atbm_buff *pSkbuf = ATBM_NULL;
	struct atbmwifi_vif *priv = (struct atbmwifi_vif *)(netif->state);
	if(priv == ATBM_NULL)
	{
		wifi_printk(WIFI_ALWAYS,"%s priv== ATBM_NULL\n", __func__);
		return -1;
	}

	wifi_printk(WIFI_TX,"%s tot_len %d \n", __func__, q->tot_len);

	{


		pSkbuf = atbm_dev_alloc_skb(q->tot_len);
		if (!pSkbuf)
		{
			wifi_printk(WIFI_TX,"<ERROR> tx_pkt alloc skb \r\n");
			return -1;
		}
		//mstar usb need ALIGN 32byte,else usb bus driver will copy data
		if(priv->config.privacy){
			atbm_skb_reserve(pSkbuf,26/*Qos header*/+6/*LLC header*/+8/*enc IV*/+2/*eth header type*/-14/*eth header */+sizeof(struct wsm_tx));
		}
		else {
			atbm_skb_reserve(pSkbuf,26+6+2-14+sizeof(struct wsm_tx));
		}

		while (q) {
			/* Copy the data from the pbuf to the interface buf, one pbuf at a
			   time. The size of the data in each pbuf is kept in the ->len
			   variable. */
			wifi_printk(WIFI_TX,"q->tot_len:%d,q->len:%d\r\n",q->tot_len,q->len);

			atbm_memcpy((atbm_void *)(&(pSkbuf->abuf[pSkbuf->dlen])), q->payload, q->len);
			atbm_skb_put(pSkbuf, q->len);

			/* Check if this is the last pbuf of the packet. If yes, then break */
			if (q->len == q->tot_len) {
				break;
			} else {
				q = q->next;
			}
		}
	}

	pSkbuf->priority = 0;

	if(priv->ndev && priv->ndev->netdev_ops){
		priv->ndev->netdev_ops->ndo_start_xmit(priv, pSkbuf);
	}
	return 0;
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
atbm_void atbm_wifi_tx_pkt(atbm_void *p)
{
	extern int gbWifiConnect;
	atbm_wifi_tx_pkt_netvif(g_vmac->ndev->nif,p);
	return;
}

//void  ethernetif_input(struct netif *netif, void *p_buf,int size);
static atbm_void __atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)
{
	struct pbuf *p, *q;
	atbm_uint16 len = 0;
	atbm_uint8 *frame_ptr;
	ATBM_NETIF *netif = dev->nif;

	frame_ptr = ATBM_OS_SKB_DATA(at_skb);
	/* Obtain the size of the packet and put it into the "len" variable. */
	len = ATBM_OS_SKB_LEN(at_skb);
	if (0 == len) {
		return;
	}

	/* We allocate a pbuf chain of pbufs from the pool. */
	p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);

	wifi_printk(WIFI_RX,"rx_pkt ref(%d)\r\n",p->ref);
	/* We iterate over the pbuf chain until we have read the entire packet into the pbuf. */
	if (p != ATBM_NULL){

		for (q = p; q != ATBM_NULL; q = q->next) {
			atbm_memcpy(q->payload, frame_ptr, q->len);
			frame_ptr += q->len;
		}
		/* full packet send to tcpip_thread to process */

		if(netif->input){
			if(netif->input(p,netif) != ERR_OK)
				pbuf_free(p);
		}
		else {
			pbuf_free(p);
			wifi_printk(WIFI_ALWAYS,"netif->input == NULL\r\n");
		}

	}
	else
	{
		wifi_printk(WIFI_ALWAYS,"%s mem error,len(%d)\r\n",__func__,len);

	}
	atbm_dev_kfree_skb(at_skb);
}
atbm_void atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)   //not required here ,   lwip_tcp_opt.net_rx = ethernetif_input.
{

	struct eth_hdr *ethhdr;
	uint32_t len = 0;
	uint8_t *frame_ptr;
	ethhdr = (struct eth_hdr *)ATBM_OS_SKB_DATA(at_skb);
	frame_ptr = ATBM_OS_SKB_DATA(at_skb);
	len = ATBM_OS_SKB_LEN(at_skb);
	switch (atbm_htons(ethhdr->type)) {
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
		//wifi_printk(WIFI_ALWAYS,"atbm_wifi_rx_pkt free ather pkg\r\n");
	    atbm_dev_kfree_skb(at_skb);
	    break;
	}
	/* Receive the complete packet */

}

atbm_void atbm_skbbuffer_init(void)
{

}

struct tcpip_opt lwip_tcp_opt ={
	.net_init = NULL,
	.net_enable = atbm_lwip_enable,//
	.net_disable = atbm_lwip_disable,//
	.net_rx = atbm_wifi_rx_pkt,
	.net_tx_done =	atbm_lwip_txdone,
	.net_start_queue =	atbm_lwip_wake_queue,
	.net_stop_queue =	atbm_lwip_stop_queue,
	.net_task_event =	atbm_lwip_task_event,//
};

