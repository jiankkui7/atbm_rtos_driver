
#include <cyg/io/dev_regist.h>
#include <cyg/infra/diag.h>     /* For dial_printf */
#include <cyg/hal/hal_if.h>     /* For CYGACC_CALL_IF_DELAY_US */
//#include <cyg/hal/hal_cache.h>  /* For HAL_DCACHE_INVALIDATE */
#include <cyg/kernel/kapi.h>
#include <cyg/io/eth/netdev.h>  /* For struct eth_drv_sc */
#include <cyg/io/eth/eth_drv.h> /* For eth_drv_netdev */

#include <cyg/devs/eth/nbuf.h>
#include <cyg/devs/eth/ckcore_eth.h>
#include <cyg/devs/eth/ckcore_eth_private_data.h>

#include <cyg/io/flash.h>       /* For SPI Flash */
#include <sys/mbuf.h>           /* Memory Pool */
#include <sys/param.h>          /* For tsleep */
#include <stdarg.h>
#include <sys/sockio.h>
#include <pkgconf/system.h>
#include <sys/bsdtypes.h>
#include "atbm_hal.h"

atbm_void  TargetUsb_lmac_start(atbm_void)
{
	wifi_printk(WIFI_ALWAYS, "atbm: TargetUsb_lmac_start(), is not defined.\n");
	return;
}

int atbm_usb_register(struct atbm_usb_driver *driver)
{
	wifi_printk(WIFI_ALWAYS, "atbm: init --->\n");
	return usb_register(driver);
}

atbm_void atbm_usb_deregister(struct atbm_usb_driver *driver)
{
	wifi_printk(WIFI_ALWAYS, "atbm: deinit <---\n");
	usb_deregister(driver);
	return;
}
//extern struct atbmwifi_common g_hw_prv;

static int atbm_ecos_init(struct cyg_netdevtab_entry *tab)
{
 	wifi_printk(WIFI_ALWAYS, "===> atbm_ecos_init()\n");
 	struct eth_drv_sc* 	pNetDev = ATBM_NULL;
   
       // struct atbmwifi_common *hw_priv = &g_hw_prv;
	atbm_uint8		MacAddr[6] = {0x00,0x00,0x11,0x32,0x43,0x69};
        //atbm_get_mac_address(hw_priv);
        //atbm_memcpy(MacAddr,hw_priv->mac_addr,6);
        /**/
	pNetDev = (struct eth_drv_sc *)tab->device_instance;
        
        /*Initialize code*/    

	/* Initialize upper level driver */
	(pNetDev->funs->eth_drv->init)(pNetDev, MacAddr);
        
	wifi_printk(WIFI_ALWAYS, "<=== atbm_ecos_init()\n");
	
	return WIFI_OK;
}

/* Device name */ 
static const char atbm_device_name[] =  "ra0";

ETH_DRV_SC(devive_wireless_sc0,
           ATBM_NULL,  /* Driver specific data */
           "ra0",
           atbm_ecos_start,
           atbm_ecos_stop,
           atbm_ecos_control,
           atbm_ecos_can_send,
           atbm_ecos_send,
           atbm_ecos_recv,
           atbm_ecos_deliver,
           atbm_ecos_poll,
           atbm_ecos_int_vector
           );
struct eth_drv_sc *sc_wifi = &devive_wireless_sc0;

static cyg_netdevtab_entry_t atbm_wifi_netdev = {atbm_device_name, &atbm_ecos_init, &devive_wireless_sc0};

/* This function is called to  "start up"  the interface.   It may  be */
/* called multiple times, even  when the hardware  is already running.   It */
/* will be called whenever something "hardware oriented" changes and should */
/* leave the hardware ready to send/receive packets.                        */
static atbm_void atbm_ecos_start(struct eth_drv_sc *sc, unsigned char *enaddr, int flags)
{       
	return;
}
static atbm_void  atbm_ecos_stop(struct eth_drv_sc *sc)
{
	return;
}
static int atbm_ecos_control(struct eth_drv_sc *sc, unsigned long key, atbm_void *data, int data_length)
{
    return 0;
}
static int atbm_ecos_can_send(struct eth_drv_sc *sc)
{
    return 1;
}

static atbm_void atbm_drv_tx_done(struct eth_drv_sc *sc, CYG_ADDRESS key, int status)
{
       struct ifnet *ifp = &sc->sc_arpcom.ac_if;
       struct mbuf *m0 = (struct mbuf *)key;
       CYGARC_HAL_SAVE_GP();
    
      ifp->if_opackets++;
      
      if (m0) { 
      //        mbuf_key = m0;
        m_freem(m0);
      }
      // Start another if possible
      // eth_drv_send(ifp); 
      CYGARC_HAL_RESTORE_GP();
      //wifi_printk(WIFI_ALWAYS,"<==atbm_void atbm_drv_tx_done\n");
}

static atbm_void atbm_ecos_send(struct eth_drv_sc *sc,struct eth_drv_sg *sg_list,int sg_len,int total_len,unsigned long key)
{
	atbm_int32 i;
	atbm_uint8 *pdata;
	struct atbm_buff *pSkbuf = ATBM_NULL;

	//wifi_printk(WIFI_ALWAYS,"==>atbm_ecos_send()\n");

	pSkbuf = atbm_dev_alloc_skb(total_len);
	if (!pSkbuf){
		wifi_printk(WIFI_TX,"atbm: atbm_ecos_send(), error, skb alloc failed! len=%d\n", total_len);
                goto fail;
	}

	pdata = &(pSkbuf->abuf[0]);

	//copy data
	for(i=0; i<sg_len; i++){
		atbm_memcpy(pdata, (atbm_int8*)sg_list[i].buf, sg_list[i].len);
		pdata += sg_list[i].len;
        // wifi_printk(WIFI_ALWAYS,"sg_list[%d],len = %d\n",i,sg_list[i].len);
	}

	atbm_skb_put(pSkbuf, total_len);
	pSkbuf->priority = 0;
       // wifi_printk(WIFI_ALWAYS,"total_len = %d %d sg_len = %d\n",total_len,pSkbuf->dlen,sg_len);
       // dump_mem(pSkbuf->abuf,pSkbuf->dlen);
#ifndef ATBM_COMB_IF 
	atbm_wifi_tx_pkt((atbm_void*)pSkbuf);
#else
#error Error, "ATBM_COMB_IF" is defined at eCos;
#endif
 fail:
        atbm_drv_tx_done(sc,key, 0);
	//wifi_printk(WIFI_ALWAYS,"<==atbm_ecos_send()\n");
	return;

}

static atbm_void atbm_ecos_recv(struct eth_drv_sc *sc,struct eth_drv_sg *sg_list,int sg_len)
{
	wifi_printk(WIFI_ALWAYS,"==>atbm_ecos_recv(), not defined.\n");
	return;
}
static atbm_void atbm_ecos_deliver(struct eth_drv_sc *sc)
{
	wifi_printk(WIFI_ALWAYS,"==>atbm_ecos_deliver()\n");
   
        
        wifi_printk(WIFI_ALWAYS,"<==atbm_ecos_deliver()\n");
	return;
}

static atbm_void atbm_ecos_poll(struct eth_drv_sc *sc)
{
	wifi_printk(WIFI_ALWAYS,"==>atbm_ecos_poll(), not defined.\n");
	return;
}

static int atbm_ecos_int_vector(struct eth_drv_sc *sc)
{
	//usb doesn't has interrupt
	wifi_printk(WIFI_ALWAYS,"==>atbm_ecos_int_vector(), not defined.\n");
	return -1;
}

/*
Func:
Description:
	Register net interface into TCP/IP stack.

Return:
	OK:     WIFI_OK(0)
	Error:  WIFI_ERROR(-1)
*/
static int atbm_net_dev_register(cyg_netdevtab_entry_t *wifi_netdev)
{
	int ret;
	ret = net_dev_register(wifi_netdev);
	wifi_printk(WIFI_ALWAYS,"atbm: net_dev_register() ret = %d\n", ret);
	if(0 == ret)
		ret = WIFI_OK;
	else
		ret = WIFI_ERROR;
	
	return ret;
}

/*
Func:
Description:
	Unregister net interface from TCP/IP stack.

Return:
	OK:     WIFI_OK(0)
	Error:  WIFI_ERROR(-1)
*/
static int atbm_net_dev_unregister(atbm_uint8 *dev_name)
{
	int ret;
	
	if(0 == block_dev_unregister(dev_name))
		ret = WIFI_OK;
	else
		ret = WIFI_ERROR;
	
	return ret;
}

atbm_os_wait_queue_head_t usbwifi_detect_sem;

extern atbm_void atbm_usb_module_init(atbm_void);
extern atbm_void atbm_usb_module_exit(atbm_void);
extern atbm_void (*proc_wifi_init)(atbm_void);
extern atbm_void (*proc_wifi_exit)(atbm_void);
/*follow MTK func API's name.*/
atbm_void usbwifi_init(atbm_void)
{       
        wifi_printk(WIFI_ALWAYS, "atbm: wifi_net_register()\n");
	//the func pointer defined/called by usb-host when the usb-device is enumerated.
	proc_wifi_init = atbm_usb_module_init;
	proc_wifi_exit = atbm_usb_module_exit;
	atbm_os_init_waitevent(&usbwifi_detect_sem);
	if(atbm_net_dev_register(&atbm_wifi_netdev) < 0)
		wifi_printk(WIFI_ALWAYS, "atbm: error, wifi_net register net dev failed.\n");
	return;
}

extern int atbm_usb_register_init(atbm_void);
int usb_wifi_init(atbm_void)
{
	wifi_printk(WIFI_ALWAYS, "atbm: usb_register()--wifi_printk\n");
	//usbwifi_init();
	
	atbm_printk("atbm: usb_wifi_init()--atbm_printk\n");
	diag_printf("atbm: usb_register()--diag_printf\n");
	wifi_printk(WIFI_DBG_MSG, "atbm: usb_register()--wifi_printk\n");
	//return atbm_usb_register_init();
	atbm_usb_module_init();
       
	return WIFI_OK;
}



