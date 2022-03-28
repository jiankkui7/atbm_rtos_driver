#ifndef ATBM_OS_SKBUFF_H
#define ATBM_OS_SKBUFF_H
#include "lwip/netif.h"
#include "netif/etharp.h"
/* MAC ADDRESS*/
#define MAC_ADDR0   02
#define MAC_ADDR1   00
#define MAC_ADDR2   00
#define MAC_ADDR3   00
#define MAC_ADDR4   00
#define MAC_ADDR5   00

#define IP_ADDR0   192
#define IP_ADDR1   168
#define IP_ADDR2   1
#define IP_ADDR3   222
  
/*NETMASK*/
#define NETMASK_ADDR0   255
#define NETMASK_ADDR1   0
#define NETMASK_ADDR2   0
#define NETMASK_ADDR3   0

/*Gateway Address*/
#define GW_ADDR0   192
#define GW_ADDR1   168
#define GW_ADDR2   1
#define GW_ADDR3   1  

/*Static IP ADDRESS*/
#define AP_IP_ADDR0   192
#define AP_IP_ADDR1   168
#define AP_IP_ADDR2   43
#define AP_IP_ADDR3   188
   
/*NETMASK*/
#define AP_NETMASK_ADDR0   255
#define AP_NETMASK_ADDR1   0
#define AP_NETMASK_ADDR2   0
#define AP_NETMASK_ADDR3   0

/*Gateway Address*/
#define AP_GW_ADDR0   192
#define AP_GW_ADDR1   168
#define AP_GW_ADDR2   43
#define AP_GW_ADDR3   1  

typedef struct netif ATBM_NETIF;

struct atbm_net_device * atbm_alloc_netdev(atbm_int32 size);
atbm_void atbm_skbbuffer_init();
atbm_void * netdev_drv_priv(struct atbm_net_device *ndev);
atbm_uint32 atbm_register_netdevice(struct atbm_net_device *netdev);

#endif /* ATBM_OS_SKBUFF_H */

