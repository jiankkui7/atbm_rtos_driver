#include "atbm_hal.h"

#include "pbuf.h"
#include "netif.h"
#include "inet.h"

#include "atbm_os_skbuf.h"

#define DEBUG_TEST_CODE 0
#if DEBUG_TEST_CODE
static atbm_uint32 recv_time;
static atbm_uint32 send_time;
#endif

//add by wp
//hal_mutex_t lwip_mutex;
int lwip_queue_enable = 0;
int lwip_enable = 0;
extern struct atbmwifi_vif *  g_vmac;


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
	struct netif * netdevif = (struct netif *)pNetIf;
	struct atbm_net_device *netdev = (struct atbm_net_device *)netdevif->state;
	struct atbmwifi_vif *priv = ATBM_NULL;
	struct atbmwifi_common	*hw_priv = ATBM_NULL;

	priv = (struct atbmwifi_vif *)netdev_drv_priv(netdev);
	hw_priv = priv->hw_priv;
	netdevif->hwaddr_len = 6;
	atbm_memcpy(netdevif->hwaddr,hw_priv->addresses[priv->if_id].addr,netdevif->hwaddr_len);
#ifdef ATBM_COMB_IF
	if(netdev->netdev_ops&&netdev->netdev_ops->ndo_open)
		netdev->netdev_ops->ndo_open(priv);	
#endif //#ifdef ATBM_COMB_IF
}
atbm_void atbm_lwip_init(struct atbm_net_device *dev)
{
	//hal_create_mutex(&lwip_mutex);
}

atbm_void atbm_lwip_enable(struct atbm_net_device *dev)
{
	lwip_queue_enable = 1;
	lwip_enable = 1;
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
atbm_void atbm_wifi_tx_pkt_netvif(struct netif *netif, struct pbuf *p)
{
	struct pbuf *q = p;
	struct atbm_buff *pSkbuf = ATBM_NULL;
	struct netif * netdevif = netif;
	struct atbm_net_device *netdev = (struct atbm_net_device *)netdevif->state;
	struct atbmwifi_vif *priv = ATBM_NULL;
	priv = (struct atbmwifi_vif *)netdev_drv_priv(netdev);
	if(priv == ATBM_NULL)
	{
		wifi_printk(WIFI_ALWAYS,"atbm_wifi_tx_pkt priv== ATBM_NULL\n");
		return;
	}


	wifi_printk(WIFI_TX,"atbm_wifi_tx_pkt packet len %d \n",q->tot_len);


	
#if defined (WLAN_ZERO_COPY1)	
	if (q->len == q->tot_len) {
		pSkbuf = atbm_dev_alloc_skbhdr();
		if (!pSkbuf)
		{
			wifi_printk(WIFI_TX,"<ERROR> tx_pkt alloc skb \n");
			return;
		}

		//iot_printf("atbm_wifi_tx_pkt_netvif %x payload %x\n", &q->aheadroom[WLAN_HEADROOM_SIZE], q->payload); 
		atbm_dev_decriptor_os_skb(pSkbuf,p);
	}
	else
#endif //WLAN_ZERO_COPY11
	{
		
		
		pSkbuf = atbm_dev_alloc_skb(q->tot_len);
		if (!pSkbuf)
		{
			wifi_printk(WIFI_TX,"<ERROR> tx_pkt alloc skb \n");
			return;
		}
		//mstar usb need ALIGN 32byte,else usb bus driver will copy data
		//if(priv->config.privacy){
		//	atbm_skb_reserve(pSkbuf,ATBM_MEM_ALIGN(26/*Qos header*/+6/*LLC header*/+8/*enc IV*/+2/*eth header type*/-14/*eth header */+sizeof(struct wsm_tx)));
		//}
		//else {
		//	atbm_skb_reserve(pSkbuf,ATBM_MEM_ALIGN(26+6+2-14+sizeof(struct wsm_tx)));
		//}
		
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
		pbuf_free(p);
	}
	
	//if(!lwip_queue_enable){
	//	atbm_SleepMs(10);
	//}
	pSkbuf->priority = 0;
#if DEBUG_TEST_CODE
	atbm_uint8 dhcpMagic[4] = {0x63,0x82,0x53,0x63};
	atbm_uint8 *pdata;
	atbm_uint16 data_len;
	atbm_uint32 interval;

	pdata = pSkbuf->abuf;
	data_len = pSkbuf->dlen;

	wifi_printk(WIFI_ALWAYS,"atbm: wifi TX, len=%d \n", data_len);
	
	//dump_mem(pdata, data_len);
	
	if((pdata[12] == 0x08) && (pdata[13] == 0x00) && (data_len > 282) &&
		(0 == atbm_memcmp(&pdata[278], dhcpMagic, 4))) 
		//(((pdata[34] == 0) && (pdata[35] == 68) && (pdata[36] == 0) && (pdata[37] == 67)) ||
		//((pdata[34] == 0) && (pdata[35] == 67) && (pdata[36] == 0) && (pdata[37] == 68))))
	{
		send_time = atbm_GetOsTimeMs();
		//send_time = atbm_GetOsTime();

		wifi_printk(WIFI_ALWAYS,"atbm: Send DHCP from %d.%d.%d.%d to %d.%d.%d.%d, opt %d\n",
			pdata[26],pdata[27],pdata[28],pdata[29],pdata[30],pdata[31],pdata[32],pdata[33],pdata[42]);
		wifi_printk(WIFI_ALWAYS,"atbm: Send DHCP from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x\n",
			pdata[6],pdata[7],pdata[8],pdata[9],pdata[10],pdata[11],
			pdata[0],pdata[1],pdata[2],pdata[3],pdata[4],pdata[5],pdata[284]);

		interval = send_time - recv_time;
		wifi_printk(WIFI_ALWAYS,"[%d] atbm: reply interval=%d ms\n", send_time, interval);

	}


	if((pdata[12] == 0x08) && (pdata[13] == 0x00) && (pdata[14] == 0x45) &&
		(pdata[23] == 0x01) && (pdata[35] == 0x00))
	{
		send_time = atbm_GetOsTimeMs();
		//send_time = atbm_GetOsTime();

		wifi_printk(WIFI_ALWAYS,"atbm: Send PING from %d.%d.%d.%d to %d.%d.%d.%d\n",
			pdata[26],pdata[27],pdata[28],pdata[29],pdata[30],pdata[31],pdata[32],pdata[33]);
		wifi_printk(WIFI_ALWAYS,"atbm: Send PING from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x\n",
			pdata[6],pdata[7],pdata[8],pdata[9],pdata[10],pdata[11],
			pdata[0],pdata[1],pdata[2],pdata[3],pdata[4],pdata[5]);

		interval = send_time - recv_time;
		wifi_printk(WIFI_ALWAYS,"[%d] atbm: reply interval=%d ms\n", send_time, interval);
	}
#endif

	//atbmwifi_tx_start(pSkbuf, priv->ndev);
	if(priv->ndev && priv->ndev->netdev_ops){
		priv->ndev->netdev_ops->ndo_start_xmit(priv, pSkbuf);
	}
	return;
}

atbm_void atbm_wifi_tx_pkt(atbm_void *p)
{
	extern int gbWifiConnect;
	atbm_wifi_tx_pkt_netvif(g_vmac->ndev->nif,p);
	return;
}


atbm_uint32 atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)   //not required here ,   lwip_tcp_opt.net_rx = ethernetif_input.
{

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
#if DEBUG_TEST_CODE	
	atbm_uint8 dhcpMagic[4] = {0x63,0x82,0x53,0x63};
	atbm_uint8 *pdata = at_skb->abuf;
	atbm_uint16 data_len = at_skb->dlen;

	if((pdata[12] == 0x08) && (pdata[13] == 0x00) && (data_len >= 282) &&
		(0 == atbm_memcmp(&pdata[278], dhcpMagic, 4)))
		//(((pdata[34] == 0) && (pdata[35] == 68) && /*src port = 0x0044*/
		//(pdata[36] == 0) && (pdata[37] == 67)) || /*dst port = 0x0043*/
		//((pdata[34] == 0) && (pdata[35] == 67) && /*src port = 0x0043*/
		//(pdata[36] == 0) && (pdata[37] == 68)))) /*dst port = 0x0044*/
	{
		recv_time = atbm_GetOsTimeMs();
		//recv_time = atbm_GetOsTime();
		wifi_printk(WIFI_ALWAYS,"atbm: Recv DHCP from %d.%d.%d.%d to %d.%d.%d.%d, MsgType: %d\n",
			pdata[26],pdata[27],pdata[28],pdata[29],pdata[30],pdata[31],pdata[32],pdata[33], pdata[42]);
		wifi_printk(WIFI_ALWAYS,"atbm: Recv DHCP from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x, opt %d\n",
			pdata[6],pdata[7],pdata[8],pdata[9],pdata[10],pdata[11],
			pdata[0],pdata[1],pdata[2],pdata[3],pdata[4],pdata[5],pdata[284]);
	}

	if((pdata[12] == 0x08) && (pdata[13] == 0x00) && /*type ipv4 = 0x0800*/
		(pdata[14] == 0x45) && /*version = 0x4, header = 0x5*/
		(pdata[23] == 0x01) && /*ICMP*/
		(pdata[35] == 0x00)) /*code = 0x0*/
	{
		recv_time = atbm_GetOsTimeMs();
		//recv_time = atbm_GetOsTime();
		wifi_printk(WIFI_ALWAYS,"atbm: Recv PING from %d.%d.%d.%d to %d.%d.%d.%d\n",
			pdata[26],pdata[27],pdata[28],pdata[29],pdata[30],pdata[31],pdata[32],pdata[33]);
		
		wifi_printk(WIFI_ALWAYS,"atbm: Recv PING from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x\n",
			pdata[6],pdata[7],pdata[8],pdata[9],pdata[10],pdata[11],
			pdata[0],pdata[1],pdata[2],pdata[3],pdata[4],pdata[5]);
	}


#endif

	//iot_printf("Up LWIP, len %d\n", len);
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

		host_network_process_ethernet_data(p,dev->nif);
		atbm_dev_kfree_skb(at_skb);

	} 
	else
	{
		atbm_dev_kfree_skb(at_skb);
		wifi_printk(WIFI_ALWAYS,"%s mem error\n",__func__);
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
atbm_void atbm_skbbuffer_init(void)
{
}

