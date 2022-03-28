
#include <cyg/infra/diag.h>     /* For dial_printf */
#include <cyg/hal/hal_if.h>     /* For CYGACC_CALL_IF_DELAY_US */
//#include <cyg/hal/hal_cache.h>  /* For HAL_DCACHE_INVALIDATE */
#include <cyg/kernel/kapi.h>
#include <cyg/io/eth/netdev.h>  /* For struct eth_drv_sc */
#include <cyg/io/eth/eth_drv.h> /* For eth_drv_netdev */
#include <cyg/io/flash.h>       /* For SPI Flash */
#include <sys/mbuf.h>           /* Memory Pool */
#include <sys/param.h>          /* For tsleep */
#include <stdarg.h>
#include <sys/sockio.h>
#include <pkgconf/system.h>
#include <sys/bsdtypes.h>
#include "atbm_hal.h"
#include "atbm_os_skbuf.h"

int lwip_queue_enable = 0;
int lwip_enable = 0;
extern struct atbmwifi_vif *  g_vmac;


extern struct netif *pOsNetIf=ATBM_NULL;

atbm_void * netdev_drv_priv(struct atbm_net_device *ndev)
{
	return &ndev->drv_priv[0];

}

atbm_void atbm_set_netif(struct eth_drv_sc *pNetIf)
{
	wifi_printk(WIFI_ALWAYS,"%s %d\n",__func__,__LINE__);
	return;
}
atbm_void atbm_netdev_registed(struct eth_drv_sc *pNetIf)
{
	return;
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

#if 0//#ifndef ATBM_COMB_IF
struct atbm_net_device * atbm_alloc_netdev(atbm_int32 size)
{
	struct atbm_net_device *  netdev = atbm_kmalloc(size + sizeof(struct atbm_net_device),GFP_KERNEL);

	ATBM_ASSERT((netdev != ATBM_NULL));
	if(netdev)
		atbm_memset(netdev,0,(size + sizeof(struct atbm_net_device)));

	netdev->nif =pOsNetIf;
	if(pOsNetIf == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS,"\n<ERROR> atbmwifi pOsNetIf not set yet may ERROR!!!!!!\n\n\n");
	}
	return  netdev;
}
#else
extern struct eth_drv_sc *sc_wifi;
struct atbm_net_device * atbm_alloc_netdev(atbm_int32 size)
{
	struct atbm_net_device *  netdev = atbm_kmalloc(size + sizeof(struct atbm_net_device),GFP_KERNEL);

	ATBM_ASSERT((netdev != ATBM_NULL));
	if(netdev)
		atbm_memset(netdev,0,(size + sizeof(struct atbm_net_device)));

	netdev->nif = sc_wifi;
	ATBM_ASSERT(netdev->nif != ATBM_NULL);
	wifi_printk(WIFI_ALWAYS,"atbm_alloc_netdev,netdev(%x),nif(%x)\n",netdev,netdev->nif);
	return  netdev;
}
#endif

atbm_void atbm_free_netdev(struct atbm_net_device * netdev)
{
	if(netdev != ATBM_NULL)
		atbm_kfree(netdev);
}


FLASH_FUNC int  atbm_register_netdevice(struct atbm_net_device *netdev)
{
	struct atbmwifi_vif *priv;
	priv = (struct atbmwifi_vif *)netdev_drv_priv(netdev);
	atbm_memcpy (priv->ndev->nif->sc_arpcom.ac_enaddr, priv->mac_addr, 6);
	return 0;
}

FLASH_FUNC atbm_void atbm_unregister_netdevice(struct eth_drv_sc * netdev)
{
	return ;
}


/****************************************************************************
* Function:   	atbm_wifi_tx_pkt
*
* Purpose:   	This function is used to send packet to wifi driver
*
* Parameters: 
*	pdata: point to buffer of data
*	data_len: the data length
*
* Returns:	None.
******************************************************************************/
atbm_void atbm_wifi_tx_pkt(atbm_void *pbuf)
{

	struct atbmwifi_vif *priv;
	struct atbm_buff *pSkbuf = (struct atbm_buff *)pbuf;

	//wifi_printk(WIFI_ALWAYS,"atbm_wifi_tx_pkt()====>\n");
	priv = g_vmac;
	if(priv == ATBM_NULL)
	{
		wifi_printk(WIFI_ALWAYS, "atbm: error, wifi drv is not init!\n");
                atbm_dev_kfree_skb(pSkbuf);
		return;
	}
	
	//atbmwifi_tx_start(pSkbuf, priv->ndev);
	if(priv->ndev && priv->ndev->netdev_ops){
		priv->ndev->netdev_ops->ndo_start_xmit(priv, pSkbuf);
	}
        else
        {
              atbm_dev_kfree_skb(pSkbuf);
        }
	//wifi_printk(WIFI_ALWAYS,"atbm_wifi_tx_pkt()<====\n");
	return;
}


atbm_uint32 atbm_wifi_rx_pkt(struct atbm_net_device *dev, struct atbm_buff *at_skb)   //not required here ,   lwip_tcp_opt.net_rx = ethernetif_input.
{
	struct ifnet        *ifp = ATBM_NULL;
	struct mbuf         *pMBuf = ATBM_NULL;
	struct ether_header *eh = ATBM_NULL;

	atbm_uint16 len = 0;
	atbm_uint8 *frame_ptr;
	atbm_uint8 *pdata = ATBM_NULL;
	

	//wifi_printk(WIFI_ALWAYS,"atbm_wifi_rx_pkt()====>\n");
	
	/* Receive the complete packet */
	frame_ptr = ATBM_OS_SKB_DATA(at_skb);
	/* Obtain the size of the packet and put it into the "len" variable. */
	len = ATBM_OS_SKB_LEN(at_skb);

        //wifi_printk(WIFI_ALWAYS,"at_skb->dlen = %d\n",at_skb->dlen); 
        //dump_mem(at_skb->abuf, at_skb->dlen);

	if (0 == len) {
		wifi_printk(WIFI_ALWAYS,"atbm: error, data len = 0!\n");
		goto RX_FAILED;
	}
	
	/*allocate a mbuf*/
	MGETHDR(pMBuf, M_DONTWAIT, MT_DATA);						
	if (pMBuf== ATBM_NULL){
		wifi_printk(WIFI_ALWAYS,"atbm: errpr, mbuf failed!\n");
		goto RX_FAILED;
	}
	
	MCLGET(pMBuf, M_DONTWAIT);
	if ((pMBuf->m_flags & M_EXT) == 0)
	{
		wifi_printk(WIFI_ALWAYS,"atbm: error, mbuf flag failed!\n");
                m_freem(pMBuf);
		goto RX_FAILED;
	}
	
        pdata = (atbm_uint8 *)(mtod(pMBuf,atbm_uint8 *));

	/*copy data from skb buffer to the new memory-->pdata*/
	atbm_memcpy(pdata, at_skb->abuf, at_skb->dlen);
    
	ifp = &dev->nif->sc_arpcom.ac_if;
        //wifi_printk(WIFI_ALWAYS,"ifp->if_flags = 0x%x \n",ifp->if_flags);
        //wifi_printk(WIFI_ALWAYS,"ifp->if_name  = %s \n",ifp->if_name);
        ifp->if_ipackets++;
	pMBuf->m_pkthdr.rcvif = ifp;
	pMBuf->m_data = pdata;
	eh = (struct ether_hdr *) pMBuf->m_data;
	pMBuf->m_data += sizeof(struct ether_header);
	pMBuf->m_pkthdr.len = at_skb->dlen - sizeof(struct ether_header);
	pMBuf->m_len = pMBuf->m_pkthdr.len;
        
        //wifi_printk(WIFI_ALWAYS,"pMBuf->m_len = %d\n",pMBuf->m_len);
        //dump_mem(pMBuf->m_data, pMBuf->m_len);
	/* Push data into protocol stacks */
	ether_input(ifp, eh, pMBuf);
	atbm_dev_kfree_skb(at_skb);
	//wifi_printk(WIFI_ALWAYS,"atbm_wifi_rx_pkt()<====\n");
	return WIFI_OK;

RX_FAILED:
	atbm_dev_kfree_skb(at_skb);
	return WIFI_ERROR;

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

