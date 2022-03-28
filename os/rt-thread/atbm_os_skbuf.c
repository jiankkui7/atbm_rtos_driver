#include "atbm_hal.h"
#include "atbm_skbuf.h"
#include "atbm_os_skbuf.h"
#include "lwip/opt.h"

#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include <lwip/stats.h>
#include <lwip/snmp.h>
#include <lwip/igmp.h>
#include "netif/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/prot/dhcp.h"
#include <lwip/tcpip.h>
#include <lwip/ip_addr.h>

int lwip_queue_enable = 0;
int lwip_enable = 0;
extern struct atbmwifi_vif *  g_vmac;
atbm_void atbm_lwip_init(struct atbm_net_device *dev)
{
}

atbm_void atbm_lwip_enable(struct atbm_net_device *dev)
{
	lwip_queue_enable = 1;
	lwip_enable = 1;
}

atbm_void atbm_lwip_disable(struct atbm_net_device *dev)
{
	lwip_enable = 0;
	lwip_queue_enable = 0;
}

atbm_void atbm_lwip_txdone(struct atbm_net_device *dev)
{
}

atbm_void atbm_lwip_wake_queue(struct atbm_net_device *dev,int num)
{
	if((!lwip_queue_enable) && lwip_enable){
		lwip_queue_enable = 1;
	}
}

atbm_void atbm_lwip_stop_queue(struct atbm_net_device *dev,int num)
{
	if(lwip_queue_enable && lwip_enable){
		lwip_queue_enable = 0;
	}
}

atbm_void atbm_lwip_task_event(struct atbm_net_device *dev)
{
}

atbm_void atbm_skbbuffer_init(void)
{
}
extern err_t atbm_wifi_tx_pkt_netvif(ATBM_NETIF *netif, struct pbuf *p);
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
atbm_uint32  atbm_register_netdevice(struct atbm_net_device *netdev)
{
	ip_addr_t ipaddr;
	ip_addr_t netmask;
	ip_addr_t gw;

	ATBM_NETIF *p_netif = ATBM_NULL;
	if(!netdev){
		wifi_printk(WIFI_ALWAYS,"NetDev is Null return \n");
		return 0;
	}	
		
	IP4_ADDR(&ipaddr.u_addr.ip4, IP_ADDR0, IP_ADDR1, IP_ADDR2, IP_ADDR3);
	IP4_ADDR(&netmask.u_addr.ip4, NETMASK_ADDR0, NETMASK_ADDR1 , NETMASK_ADDR2, NETMASK_ADDR3);
	IP4_ADDR(&gw.u_addr.ip4, GW_ADDR0, GW_ADDR1, GW_ADDR2, GW_ADDR3);

	p_netif = netdev->nif;

	if(p_netif == ATBM_NULL){
		wifi_printk(WIFI_DBG_ERROR," p_netif == ATBM_NULL\n");	
		return 0;
	}
	if (NULL == netif_add(p_netif, &ipaddr.u_addr.ip4, &netmask.u_addr.ip4, &gw.u_addr.ip4, (atbm_void*)g_vmac, atbm_lwip_netif_init, tcpip_input))
	{
		wifi_printk(WIFI_DBG_ERROR,"wifi_netif_init netif_add err\n");	
		return  - 1;
	}
	/*  Registers the default network interface. */
	netif_set_default(p_netif);
	/* set interface up */
	netif_set_up(p_netif);
	return 0;
}
atbm_void unregister_netdevice(struct atbm_net_device *netdev)
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
err_t atbm_wifi_tx_pkt_netvif(ATBM_NETIF *netif, struct pbuf *p)
{
	unsigned long flags;
	struct pbuf *temp_pbuf=ATBM_NULL;
	struct atbm_buff *AtbmBuf = ATBM_NULL;
	struct atbmwifi_vif *priv = (struct atbmwifi_vif *)netif->state;
	if(priv == ATBM_NULL ||p==ATBM_NULL)
	{
		ATBM_BUG_ON(1);
		wifi_printk(WIFI_ALWAYS,"atbm_wifi_tx_pkt priv== ATBM_NULL\n");
		return 0;
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
		return 0;
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

atbm_void __atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *atbm_skb) 
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
	//p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
	p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
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
atbm_void atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)
{
	struct eth_hdr *ethhdr;
	if(at_skb==ATBM_NULL || dev==ATBM_NULL){
		return ;
	}
	ethhdr = (struct eth_hdr *)ATBM_OS_SKB_DATA(at_skb);
	switch (htons(ethhdr->type)) {
	  case 0x0806://arp
	  case 0x0800://ip
	  //case 0x86dd://ip6
	    __atbm_wifi_rx_pkt(dev,at_skb);
	    break;
	  default:
	    atbm_dev_kfree_skb(at_skb);
	    break;
	}
}

struct atbm_net_device * atbm_alloc_netdev(atbm_int32 size)
{
	struct atbm_net_device *  netdev = atbm_kmalloc(size + sizeof(struct atbm_net_device),GFP_KERNEL);

	ATBM_ASSERT((netdev != ATBM_NULL));
	if(netdev)
		atbm_memset(netdev,0,(size + sizeof(struct atbm_net_device)));

	netdev->nif = atbm_kmalloc(sizeof(ATBM_NETIF),GFP_KERNEL);
	ATBM_ASSERT(netdev->nif != ATBM_NULL);
	if(netdev->nif)
		atbm_memset(netdev->nif,0,sizeof(ATBM_NETIF));
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
		atbm_kfree(netdev->nif);
		
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

