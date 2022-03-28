#ifndef ATBM_OS_SDIO_H
#define ATBM_OS_SDIO_H
/*include os platform*/
#include "moal_sdio.h"
#include "usr_cfg.h"
/*
 * SDIO function devices
 */
struct atbm_sdio_func {

	unsigned int		num;		/* function number */

	unsigned char		class;		/* standard interface class */
	unsigned short		vendor;		/* vendor id */
	unsigned short		device;		/* device id */

	unsigned		max_blksize;	/* maximum block size */
	unsigned		cur_blksize;	/* current block size */

	unsigned		enable_timeout;	/* max enable timeout in msec */

	unsigned int		state;		/* function state */
#define SDIO_STATE_PRESENT	(1<<0)		/* present in sysfs */

	unsigned char			tmpbuf[4];	/* DMA:able scratch buffer */

	unsigned		num_info;	/* number of info strings */
	const char		**info;		/* info strings */

	void *dev_data;
	ATBM_BOOL	sdio_int_pending;

};

extern int sdio_claim_irq(struct atbm_sdio_func *func, void *handler);
extern 	int sdio_release_irq(struct atbm_sdio_func *func);
extern int sdio_set_block_size(int fn,unsigned blksz);  
extern int sdio_enable_func(struct atbm_sdio_func *func);
extern int sdio_disable_func(struct atbm_sdio_func *func);
extern int sdio_release_host(struct atbm_sdio_func *func);
#define atbm_sdio_driver   sdio_driver
#define atbm_sdio_register    sdio_register
#define atbm_sdio_deregister  sdio_deregister
#define atbm_sdio_set_drvdata  sdio_set_drvdata
#define atbm_sdio_claim_host  sdio_claim_host
#define atbm_sdio_enable_func  sdio_enable_func
#define atbm_sdio_release_host  sdio_release_host
#define atbm_sdio_disable_func  sdio_disable_func
#define __atbm_sdio_memcpy_fromio(x,y,z,h)  sdio_readsb(y,z,h)
#define __atbm_sdio_memcpy_toio(x,y,z,h)  sdio_writesb(y,z,h)
#define __atbm_sdio_set_block_size(x,y)    sdio_set_block_size(x,y)
#define atbm_sdio_claim_irq(x,y)  sdio_claim_irq(x,y)
#define atbm_sdio_release_irq(x)  sdio_release_irq(x)
#define atbm_sdio_device_id  atbm_uint32//sdio_device_id
//#define atbm_sdio_func  sdio_func
#define atbm_sdio_get_drvdata  sdio_get_drvdata
#define atbm_sdio_f0_readb(x,y,z)  sdio_f0_readb(y,z)
#define atbm_sdio_f0_writeb(x,y,z,h)  sdio_f0_writeb(y,z,h)
atbm_uint32 __atbm_sdio_align_size(struct sbus_priv *self, atbm_uint32 size);

#endif/* ATBM_OS_SDIO_H */
