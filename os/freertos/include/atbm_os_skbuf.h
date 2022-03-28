#ifndef ATBM_OS_SKBUFF_H
#define ATBM_OS_SKBUFF_H

typedef struct netif ATBM_NETIF;

struct atbm_net_device * atbm_alloc_netdev(atbm_int32 size);
atbm_void atbm_skbbuffer_init(void);

#endif /* ATBM_OS_SKBUFF_H */

