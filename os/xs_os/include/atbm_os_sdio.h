#ifndef ATBM_OS_SDIO_H
#define ATBM_OS_SDIO_H
#include "atbm_hal.h"
#include <xs/driver/sdio_api.h>

struct atbm_sdio_func{
	atbm_uint32 num;
	atbm_uint32 en;
	atbm_uint32 blocksize;
	void *priv;
	struct xs_mmc_card	*card;		/* the card this device belongs to */
};

struct atbm_sdio_device_id{
	char id[8];
};
struct atbm_sdio_driver{
	char name[16];
	struct atbm_sdio_device_id *match_id_table;
	int (*probe_func) (struct atbm_sdio_func *func,
		const struct atbm_sdio_device_id *id);
	int (*discon_func) (struct atbm_sdio_func *func);
};
int atbm_sdio_register(struct atbm_sdio_driver *sdio_driver);
void atbm_sdio_deregister(struct atbm_sdio_driver *sdio_driver);
void atbm_sdio_claim_host(struct atbm_sdio_func *func);
void atbm_sdio_release_host(struct atbm_sdio_func *func);
atbm_int32 atbm_sdio_enable_func(struct atbm_sdio_func *func);
void atbm_sdio_disable_func(struct atbm_sdio_func *func);
void atbm_sdio_set_drvdata(struct atbm_sdio_func *func,void *priv);
void *atbm_sdio_get_drvdata(struct atbm_sdio_func *func);
int atbm_sdio_claim_irq(struct atbm_sdio_func *func,void (*irq_handle)(struct atbm_sdio_func *func));
int atbm_sdio_release_irq(struct atbm_sdio_func *func);
int __atbm_sdio_memcpy_fromio(struct atbm_sdio_func *func,void *dst,unsigned int addr,int count);
int __atbm_sdio_memcpy_toio(struct atbm_sdio_func *func,unsigned int addr,void *src,int count);
unsigned char atbm_sdio_f0_readb(struct atbm_sdio_func *func,unsigned int addr,int *retval);
void atbm_sdio_f0_writeb(struct atbm_sdio_func *func,unsigned char regdata,unsigned int addr,int *retval);
int atbm_sdio_set_blocksize(struct atbm_sdio_func *func,int blocksize);
atbm_uint32 atbm_sdio_alignsize(struct atbm_sdio_func *func,atbm_uint32 size);


#endif/* ATBM_OS_SDIO_H */
