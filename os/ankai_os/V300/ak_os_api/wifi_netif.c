/**
 * @file
 * Ethernet Interface Skeleton
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/*
 * This file is a skeleton for developing Ethernet network interface
 * drivers for lwIP. Add code to the low_level functions and do a
 * search-and-replace for the word "ethernetif" to replace it with
 * something that better describes your network interface.
 */
#include "drv_api.h"
#include "netif/etharp.h"
#include "lwip/tcpip.h"
#include "libc_mem.h"

#include "wifi.h"

typedef struct dhcp_info{
    enum dhcp_mode      dhcp_mode;
    struct ip_info      ip_info;
}dhcp_info_t;

dhcp_info_t dhcp_info = {
    DHCP_MODE_DYNAMIC_EVERY, 
};
dhcp_info_t *p_dhcp = &dhcp_info;


/*********************************************************
*
*
*********************************************************/
extern int atbm_akwifi_netif_init(void);
int wifi_netif_init(void)
{
	atbm_akwifi_netif_init();
	
	return 0;
}


/******************************************************************
 * @brief  wifistation_netif_init, init wifi netif dev for station mode
 *         it will start dhcp client
 * @param  : 
 * @retval  0 success, -1 fail
 *******************************************************************/
static int do_dhcp(void){
	int restart_cnt;
	struct netif *p_netif = (struct netif *)atbm_priv_get_netif();
	if(!p_netif)
		return;
	while(1)
	{
		if(!netif_is_up(p_netif))
			return -1;
		dhcp_stop(p_netif);
		dhcp_start(p_netif);
		restart_cnt++;
		if (p_netif->ip_addr.addr !=0)
		{
			u8_t *ip = (u8_t *)(&p_netif->ip_addr.addr);
			break;
		}else{
			ak_sleep_ms(1000+restart_cnt*2000);
		}
	}
}

extern int atbm_akwifistation_netif_init(void);
int wifistation_netif_init(void)
{
	atbm_akwifistation_netif_init();	
	return 0;
}

int wifistation_netif_set_dhcp(enum dhcp_mode mode,const char *ip_str)
{
    u32_t ip = 0;
    
    p_dhcp->dhcp_mode = mode;
    if(NULL != ip_str) {
         ip = inet_addr(ip_str);
    }
    if(DHCP_MODE_STATIC == p_dhcp->dhcp_mode && 0 != ip) {
        p_dhcp->ip_info.ipaddr.addr = ip;
        ip &= 0x00ffffff;
        p_dhcp->ip_info.gw.addr = ip|0x01000000;
    }
}

int wifistation_netif_deinit(void)
{
	return 0;
}

int wifistation_netif_get_ip(void)
{
    int ret;
    struct ip_info bk_ip_info;
	unsigned int tick;
	struct netif *p_netif = (struct netif *)atbm_priv_get_netif();
	
    // static ip
    if(DHCP_MODE_STATIC == p_dhcp->dhcp_mode) {
        printf("get IP with static IP\n");
        printf("ip=%u.%u.%u.%u,gw=%u.%u.%u.%u,mask=%u.%u.%u.%u \n"
                , p_dhcp->ip_info.ipaddr.addr & 0xff,(p_dhcp->ip_info.ipaddr.addr & 0xff00)>>8,(p_dhcp->ip_info.ipaddr.addr &0xff0000) >>16,p_dhcp->ip_info.ipaddr.addr>>24
                , p_dhcp->ip_info.gw.addr & 0xff,(p_dhcp->ip_info.gw.addr & 0xff00)>>8,(p_dhcp->ip_info.gw.addr &0xff0000) >>16,p_dhcp->ip_info.gw.addr>>24
                , p_dhcp->ip_info.netmask.addr & 0xff, (p_dhcp->ip_info.netmask.addr & 0xff00)>>8,(p_dhcp->ip_info.netmask.addr &0xff0000) >>16,p_dhcp->ip_info.netmask.addr>>24 );
            
        netif_set_addr(p_netif, &p_dhcp->ip_info.ipaddr, &p_dhcp->ip_info.netmask, &p_dhcp->ip_info.gw);
        ret = 0;
    }
    else if(DHCP_MODE_DYNAMIC_EVERY == p_dhcp->dhcp_mode) 
    {
		do_dhcp();
    }else{
         // get backup ip
        memset(&bk_ip_info, 0, sizeof(struct ip_info));
        wifi_restore_ip_info(&bk_ip_info);
        /*use back addr first  if no back addr get ip addr from dhcp*/
        if(bk_ip_info.ipaddr.addr != 0 && bk_ip_info.netmask.addr != 0 && bk_ip_info.gw.addr != 0)
        {
	        printf("get IP with back IP\n");
            printf("ip=%u.%u.%u.%u,gw=%u.%u.%u.%u,mask=%u.%u.%u.%u \n"
                        , bk_ip_info.ipaddr.addr & 0xff,(bk_ip_info.ipaddr.addr & 0xff00)>>8,(bk_ip_info.ipaddr.addr &0xff0000) >>16,bk_ip_info.ipaddr.addr>>24
                        , bk_ip_info.gw.addr & 0xff,(bk_ip_info.gw.addr & 0xff00)>>8,(bk_ip_info.gw.addr &0xff0000) >>16,bk_ip_info.gw.addr>>24
                        , bk_ip_info.netmask.addr & 0xff, (bk_ip_info.netmask.addr & 0xff00)>>8,(bk_ip_info.netmask.addr &0xff0000) >>16,bk_ip_info.netmask.addr>>24 );
        
            netif_set_addr(p_netif, &bk_ip_info.ipaddr, &bk_ip_info.netmask, &bk_ip_info.gw);
            return 0;
        } 
        else
        {
            do_dhcp();
     
            bk_ip_info.ipaddr.addr = p_netif->ip_addr.addr;
            bk_ip_info.netmask.addr = p_netif->netmask.addr;
            bk_ip_info.gw.addr = p_netif->gw.addr;
        
            printf("back ip=%u.%u.%u.%u,gw=%u.%u.%u.%u,mask=%u.%u.%u.%u \n"
                , bk_ip_info.ipaddr.addr & 0xff,(bk_ip_info.ipaddr.addr & 0xff00)>>8,(bk_ip_info.ipaddr.addr &0xff0000) >>16,bk_ip_info.ipaddr.addr>>24
                , bk_ip_info.gw.addr & 0xff,(bk_ip_info.gw.addr & 0xff00)>>8,(bk_ip_info.gw.addr &0xff0000) >>16,bk_ip_info.gw.addr>>24
                , bk_ip_info.netmask.addr & 0xff, (bk_ip_info.netmask.addr & 0xff00)>>8,(bk_ip_info.netmask.addr &0xff0000) >>16,bk_ip_info.netmask.addr>>24 );
            
            wifi_back_ip_info(&bk_ip_info);
        }      
    }
    return ret;
}


/**
 * @brief  wifi_netif_deinit, remove netif of wifi
 * @param  : 
 * @retval void
 */

void wifi_netif_deinit(void)
{
	struct netif *p_netif = NULL;
	
	if(!atbm_wifi_initialed()){
		printk("wifi_netif_deinit err\n");	
		return;
	}
	
	p_netif = (struct netif *)atbm_priv_get_netif();
	if(p_netif == NULL){
		printk("wifi_netif_deinit p_netif == ATBM_NULL\n");	
		return;
	}
	netif_remove(p_netif);
	netif_set_down(p_netif);

	if(atbm_get_wifimode() == WIFI_MODE_STA)
		dhcp_stop(p_netif);
	else if(atbm_get_wifimode() == WIFI_MODE_AP)
		dhcps_stop();
}


/*
*@brief get wifi netif addr
*/
extern void atbm_akwifi_get_netif_addr(struct ip_info *wifi_ip_info);

void wifi_get_netif_addr(struct ip_info *wifi_ip_info)
{
	atbm_akwifi_get_netif_addr(wifi_ip_info);
}

//TODO: set dhcp

//int dhcp_setup()





