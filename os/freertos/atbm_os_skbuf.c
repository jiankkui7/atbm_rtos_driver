

#include "atbm_hal.h"
//#include "uart_hi.h"
#include "target_usb.h"

#include "lwip\pbuf.h"
#include "lwip\netif.h"
#include "lwip\inet.h"

#define DEBUG_TEST_CODE 0
#if DEBUG_TEST_CODE
static atbm_uint32 recv_time;
static atbm_uint32 send_time;
#endif

int lwip_queue_enable = 0;
int lwip_enable = 0;
extern struct atbmwifi_vif *  g_vmac;
extern struct netif xNetIf;

#ifndef ATBM_COMB_IF
struct atbm_net_device * atbm_alloc_netdev(atbm_int32 size)
{
	struct atbm_net_device *  netdev = atbm_kmalloc(size + sizeof(struct atbm_net_device),GFP_KERNEL);

	ATBM_ASSERT((netdev != ATBM_NULL));
	if(netdev)
		atbm_memset(netdev,0,(size + sizeof(struct atbm_net_device)));

	netdev->nif = &xNetIf;
	return  netdev;
}
#else
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

#endif
atbm_void * netdev_drv_priv(struct atbm_net_device *ndev)
{
	return &ndev->drv_priv[0];

}


atbm_void atbm_free_netdev(struct atbm_net_device * netdev)
{
	if(netdev != ATBM_NULL)
		atbm_kfree(netdev);
}

#ifdef ATBM_COMB_IF

#define if_netdev2index(_s)	atbm_get_netdev_index(_s)

FLASH_FUNC int  atbm_get_netdev_index(struct netif * netdev)
{
	return netdev->num;
}

FLASH_FUNC int  atbm_register_netdevice(struct atbm_net_device *netdev)
{
	extern err_t ethernetif_init(struct netif *netif);
	extern err_t tcpip_input(struct pbuf *p, struct netif *inp);
	int ifindex = -1;
	struct ip_addr netmask, gw, ip_addr;

	wifi_printk(WIFI_DBG_INIT,"atbm_register_netdevice (%x),nif(%x)\n",netdev,netdev->nif);

	
	netmask.addr = 0;
	gw.addr = 0;
	ip_addr.addr = 0;
	if(netif_add(netdev->nif, &ip_addr, &netmask, &gw, (atbm_void*)netdev, ethernetif_init, tcpip_input) == ATBM_NULL){
		ATBM_DEBUG(1,1,"netif_add failed\n");
		return -1;
	}
	ifindex = if_netdev2index(netdev->nif);
//	g_wifinetif[ifindex] = netdev;
	netif_set_default(netdev->nif);

	return 0;
}

FLASH_FUNC atbm_void unregister_netdevice(struct netif * netdevif)
{
	
	int ifindex =  if_netdev2index(netdevif);
	netif_set_down(netdevif);
	netif_set_default(ATBM_NULL);
//	g_wifinetif[ifindex] = NULL;

	netif_remove(netdevif);
	
	return ;
}
FLASH_FUNC atbm_void atbm_register_netdevice_callback(atbm_void *call_data)
{
	struct netif * netdevif = (struct netif *)call_data;
	struct atbm_net_device *netdev = (struct atbm_net_device *)netdevif->state;
	struct atbmwifi_vif *priv = ATBM_NULL;
	struct atbmwifi_common	*hw_priv = ATBM_NULL;

	priv = (struct atbmwifi_vif *)netdev_drv_priv(netdev);
	hw_priv = priv->hw_priv;
	netdevif->hwaddr_len = 6;
	atbm_memcpy(netdevif->hwaddr,hw_priv->addresses[priv->if_id].addr,netdevif->hwaddr_len);
	if(netdev->netdev_ops&&netdev->netdev_ops->ndo_open)
		netdev->netdev_ops->ndo_open(priv);	
}
#else

FLASH_FUNC int  atbm_register_netdevice(struct atbm_net_device *netdev)
{
	struct netif * netdevif = (struct netif *)netdev->nif;
	struct atbmwifi_vif *priv = (struct atbmwifi_vif *)netdev->drv_priv;	
	atbm_memcpy(netdevif->hwaddr,priv->mac_addr ,6);
	//if(netdev->netdev_ops&&netdev->netdev_ops->ndo_open)
	//	netdev->netdev_ops->ndo_open(priv);	
}
#endif


atbm_void atbm_lwip_init(struct atbm_net_device *dev)
{
	//hal_create_mutex(&lwip_mutex);
}
extern err_t dhcp_start(struct netif *netif);

atbm_void atbm_lwip_enable(struct atbm_net_device *dev)
{	
	int ret =ERR_OK;	
	struct atbmwifi_vif *priv = ATBM_NULL;
	priv = (struct atbmwifi_vif *)netdev_drv_priv(dev);


	//FIXME add callback event here
	priv->net_enable = 1;
	priv->net_queue_enable = 1;
	if((priv->iftype == ATBM_NL80211_IFTYPE_STATION) || (priv->iftype == ATBM_NL80211_IFTYPE_P2P_CLIENT)){
		ret =dhcp_start(dev->nif);
		if(ret != ERR_OK)
			wifi_printk(WIFI_ALWAYS,"dhcp start error\n");
		else
			wifi_printk(WIFI_ALWAYS,"dhcp start success\n");
	}else {
		struct ip_addr netmask, gw, ip_addr;
		wifi_printk(WIFI_ALWAYS,"init_udhcpd\n");
		netif_set_up(dev->nif);
		ip_addr.addr = inet_addr("192.168.43.1");
		netif_set_ipaddr(dev->nif, &ip_addr);
		netmask.addr = inet_addr("255.255.0.0");
		netif_set_netmask(dev->nif, &netmask);
		gw.addr = inet_addr("192.168.43.1");
		netif_set_gw(dev->nif, &gw);
		init_udhcpd(dev->nif);
		enable_dhcp_server();
	}

	
}
atbm_void atbm_lwip_disable(struct atbm_net_device *dev)
{
	//FIXME add callback event here
	struct atbmwifi_vif *priv = ATBM_NULL;
	priv = (struct atbmwifi_vif *)netdev_drv_priv(dev);
	//FIXME add callback event here
	priv->net_enable = 0;
	priv->net_queue_enable = 0;
}

atbm_void atbm_lwip_txdone(struct atbm_net_device *dev)
{
}


atbm_void atbm_lwip_wake_queue(struct atbm_net_device *dev,int num)
{
	struct atbmwifi_vif *priv = ATBM_NULL;
	priv = (struct atbmwifi_vif *)netdev_drv_priv(dev);
	if(!priv->net_queue_enable&& priv->net_enable){
		priv->net_queue_enable = 1;
	}
}

atbm_void atbm_lwip_stop_queue(struct atbm_net_device *dev,int num)
{
	struct atbmwifi_vif *priv = ATBM_NULL;
	priv = (struct atbmwifi_vif *)netdev_drv_priv(dev);
	if(priv->net_queue_enable && priv->net_enable){
		//hal_wait_for_mutex(&lwip_mutex,2000);
		priv->net_queue_enable = 0;
	}
}




#ifndef ATBM_COMB_IF 

atbm_uint32 atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)   //not required here ,   lwip_tcp_opt.net_rx = ethernetif_input.
{
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
		wifi_printk(WIFI_ALWAYS,"atbm: Recv PING from %d.%d.%d.%d to %d.%d.%d.%d\n",
			pdata[26],pdata[27],pdata[28],pdata[29],pdata[30],pdata[31],pdata[32],pdata[33]);
		
		wifi_printk(WIFI_ALWAYS,"atbm: Recv PING from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x\n",
			pdata[6],pdata[7],pdata[8],pdata[9],pdata[10],pdata[11],
			pdata[0],pdata[1],pdata[2],pdata[3],pdata[4],pdata[5]);
	}

	recv_time = atbm_GetOsTimeMs();
	//recv_time = atbm_GetOsTime();
#endif

	wifi_printk(WIFI_RX,"passing to LWIP layer, packet len %d \n", ATBM_OS_SKB_LEN(at_skb));	

	prvEthernetInput(at_skb->abuf,at_skb->dlen);
	
	atbm_dev_kfree_skb(at_skb);
	

	return 0;
}
#else
atbm_uint32 atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)   //not required here ,   lwip_tcp_opt.net_rx = ethernetif_input.
{

	//wifi_printk(WIFI_RX,"passing to LWIP layer, packet len %d \n", OS_SKB_LEN(at_skb));
	prvEthernetInput(dev->nif,at_skb->abuf,at_skb->dlen);
	
	atbm_dev_kfree_skb(at_skb);
	

	return 0;
}


#endif
#if defined (WLAN_ZERO_COPY1)	
int atbm_os_skb_cnt =0;
int atbm_os_skb_free =0;
struct atbm_buff * atbm_dev_decriptor_os_skb(struct atbm_buff *atbm_buf , struct pbuf *p) 
{
	ATBM_OS_SKB_HEAD(atbm_buf) = p->aheadroom;
	ATBM_OS_SKB_DATA(atbm_buf) = p->payload;
	//atbm_buf->dlen = p->len;

	atbm_buf->ref = 1;
	atbm_buf->bufferLen = p->len+WLAN_HEADROOM_SIZE;
	
	atbm_buf->pOsBuffer = p;
	atbm_buf->is_os_buffer = 1;
	atbm_os_skb_cnt++;

	/*add for wifi*/
	ATBM_OS_SKB_LEN(atbm_buf) = p->len;
	atbm_buf->Tail = ATBM_OS_SKB_DATA(atbm_buf)+ATBM_OS_SKB_LEN(atbm_buf);
}


struct atbm_buff * atbm_dev_free_os_skb(struct atbm_buff * atbm_buf) 
{
	struct pbuf *p = atbm_buf->pOsBuffer;
	
	if(atbm_buf->is_os_buffer){
		atbm_os_skb_free++;
		__pbuf_free(p);
		atbm_buf->pOsBuffer = ATBM_NULL;
		atbm_buf->is_os_buffer = 0;
	}		
	
	//atbm_dev_kfree_skb(atbm_buf);
}
#endif  //#if defined (WLAN_ZERO_COPY11)	

/****************************************************************************
* Function:   	atbm_wifi_tx_pkt
*
* Purpose:   	This function is used to send packet to wifi driver
*
* Parameters: point to buffer of packet
*
* Returns:	None.
******************************************************************************/
#ifndef ATBM_COMB_IF 
atbm_void atbm_wifi_tx_pkt(struct pbuf *p)
{
	struct atbmwifi_vif *priv;
	struct pbuf *q = p;
	struct atbm_buff *pSkbuf = ATBM_NULL;

#if DEBUG_TEST_CODE
	atbm_uint8 dhcpMagic[4] = {0x63,0x82,0x53,0x63};
	atbm_uint8 *pdata;
	atbm_uint16 data_len;
	atbm_uint32 interval;
#endif
	
	priv = g_vmac;
	if(priv == ATBM_NULL)
	{
		return;
	}


#if defined (WLAN_ZERO_COPY1)	
	pbuf_ref(p);
	pSkbuf = atbm_dev_alloc_skbhdr();
	if (!pSkbuf)
	{
		wifi_printk(WIFI_TX,"<ERROR> tx_pkt alloc skb \n");
		return;
	}

		//iot_printf("atbm_wifi_tx_pkt_netvif %x payload %x\n", &q->aheadroom[WLAN_HEADROOM_SIZE], q->payload); 
	atbm_dev_decriptor_os_skb(pSkbuf,p);
			
#else	//WLAN_ZERO_COPY11

	pSkbuf = atbm_dev_alloc_skb(p->tot_len);
	if (!pSkbuf)
	{
		wifi_printk(WIFI_TX,"<ERROR> tx_pkt alloc skb \n");
		return;
	}
	//mstar usb need ALIGN 32byte
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
#endif //WLAN_ZERO_COPY11
	
	if(!lwip_queue_enable){
		atbm_mdelay(10);
	}

	pSkbuf->priority = 0;

#if DEBUG_TEST_CODE
	pdata = pSkbuf->abuf;
	data_len = pSkbuf->dlen;

	wifi_printk(WIFI_ALWAYS,"atbm: wifi TX, len=%d \n", data_len);
	
	//dump_mem(pdata, data_len);
	
	if((pdata[12] == 0x08) && (pdata[13] == 0x00) && (data_len > 282) &&
		(0 == atbm_memcmp(&pdata[278], dhcpMagic, 4))) 
		//(((pdata[34] == 0) && (pdata[35] == 68) && (pdata[36] == 0) && (pdata[37] == 67)) ||
		//((pdata[34] == 0) && (pdata[35] == 67) && (pdata[36] == 0) && (pdata[37] == 68))))
	{
		wifi_printk(WIFI_ALWAYS,"atbm: Send DHCP from %d.%d.%d.%d to %d.%d.%d.%d, opt %d\n",
			pdata[26],pdata[27],pdata[28],pdata[29],pdata[30],pdata[31],pdata[32],pdata[33],pdata[42]);
		wifi_printk(WIFI_ALWAYS,"atbm: Send DHCP from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x\n",
			pdata[6],pdata[7],pdata[8],pdata[9],pdata[10],pdata[11],
			pdata[0],pdata[1],pdata[2],pdata[3],pdata[4],pdata[5],pdata[284]);
	}


	if((pdata[12] == 0x08) && (pdata[13] == 0x00) && (pdata[14] == 0x45) &&
		(pdata[23] == 0x01) && (pdata[35] == 0x00))
	{
		wifi_printk(WIFI_ALWAYS,"atbm: Send PING from %d.%d.%d.%d to %d.%d.%d.%d\n",
			pdata[26],pdata[27],pdata[28],pdata[29],pdata[30],pdata[31],pdata[32],pdata[33]);
		wifi_printk(WIFI_ALWAYS,"atbm: Send PING from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x\n",
			pdata[6],pdata[7],pdata[8],pdata[9],pdata[10],pdata[11],
			pdata[0],pdata[1],pdata[2],pdata[3],pdata[4],pdata[5]);
	}
	
	send_time = atbm_GetOsTimeMs();
	//send_time = atbm_GetOsTime();
	interval = send_time - recv_time;
	wifi_printk(WIFI_ALWAYS,"[%d] atbm: reply interval=%d ms\n", send_time, interval);
#endif

	//atbmwifi_tx_start(pSkbuf, priv->ndev);
	if(priv->ndev && priv->ndev->netdev_ops){
		priv->ndev->netdev_ops->ndo_start_xmit(priv, pSkbuf);
	}
	return;
}
#else
atbm_void atbm_wifi_tx_pkt(struct netif *netif, struct pbuf *p)
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

	pSkbuf = atbm_dev_alloc_skb(p->tot_len);
	if (!pSkbuf)
	{
		wifi_printk(WIFI_ALWAYS,"<ERROR> tx_pkt alloc skb \n");
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
		priv->ndev->netdev_ops->ndo_start_xmit(priv, pSkbuf);
	}
	return;
}
#endif
atbm_void atbm_lwip_task_event(struct atbm_net_device *dev)
{
}
struct tcpip_opt lwip_tcp_opt;
atbm_void atbm_skbbuffer_init(void)
{
	lwip_tcp_opt.net_init = atbm_lwip_init;
	lwip_tcp_opt.net_enable = atbm_lwip_enable;//
	lwip_tcp_opt.net_disable = atbm_lwip_disable;//
	lwip_tcp_opt.net_rx = atbm_wifi_rx_pkt;
	lwip_tcp_opt.net_tx_done =	atbm_lwip_txdone;
	lwip_tcp_opt.net_start_queue =	atbm_lwip_wake_queue;
	lwip_tcp_opt.net_stop_queue =	atbm_lwip_stop_queue;
	lwip_tcp_opt.net_task_event =	atbm_lwip_task_event;//
}



