
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "atbm_hal.h"
#include <xs/driver/sdio_api.h>
/******** Functions below is Wlan API **********/
#include "atbm_os_sdio.h"
#include <stdint.h>
#include "lwip/netif.h"
#include "lwip/sockets.h"


#define AK_SIDO_DEBUG_LEVEL	WIFI_DBG_MSG
#define AK_SIDO_ERR_LEVEL	WIFI_DBG_ERROR

#define ATBM_BLKSZ	288
typedef void (*irq_handle)(struct atbm_sdio_func *func);
static struct atbm_sdio_func func0;
static struct atbm_sdio_func func1;
//static struct atbm_sdio_func *irq_func = ATBM_NULL;
static atbm_mutex sdio_lock;
//static irq_handle func_irqhanlde = ATBM_NULL;
static void (*prv_irq_handle)(uint32_t) ;
struct xs_sdio_func xs_dummy_f0;


//#define ATBM_CALL_IRQHANDLE() 					if(func_irqhanlde&&irq_func) func_irqhanlde(irq_func)
//#define ATBM_SET_IRQ(__func,__handle)			irq_func = __func;func_irqhanlde = __handle

#define SDIO_FUNC_SET_EN(__func,__en)			(__func)->en = __en
#define SDIO_FUNC_SET_NUM(__func,__num)			(__func)->num = __num
#define SDIO_FUNC_SET_PRIV(__func,__priv)		(__func)->priv = __priv
#define SDIO_FUNC_SET_BLKSIZE(__func,__blks)		(__func)->blocksize = __blks
#define SDIO_FUNC_GET_EN(__func)			((__func)->en)
#define SDIO_FUNC_GET_NUM(__func)			((__func)->num)
#define SDIO_FUNC_GET_PRIV(__func)			((__func)->priv)
#define SDIO_FUNC_GET_BLKSIZE(__func)			((__func)->blocksize)	
#define SDIO_FUNC_SET_CARD(__func,__card)		(__func)->card = __card
#define SDIO_FUNC_SET_IRQ_PARAM(__func,__card,__fn_num)	__card->sdio_func[__fn_num-1]->irq_param = (void*)(__func)

#define SDIO_FUNC0_INT(card)		SDIO_FUNC_SET_NUM(&func0,0) ;SDIO_FUNC_SET_EN(&func0,1); \
	SDIO_FUNC_SET_CARD(&func0,card); \
	SDIO_FUNC_SET_PRIV(&func0,ATBM_NULL); SDIO_FUNC_SET_BLKSIZE(&func0,ATBM_BLKSZ);
#define SDIO_FUNC1_INT(card)		SDIO_FUNC_SET_NUM(&func1,1) ;SDIO_FUNC_SET_EN(&func1,0); \
	SDIO_FUNC_SET_CARD(&func1,card); SDIO_FUNC_SET_IRQ_PARAM(&func1,card,1);\
	SDIO_FUNC_SET_PRIV(&func1,ATBM_NULL); SDIO_FUNC_SET_BLKSIZE(&func1,ATBM_BLKSZ);
#define SDIO_FUNC1()			func1
#define SDIO_FUNC0()			func0
#define SDIO_LOCK_INIT()		atbm_os_mutexLockInit(&sdio_lock)
#define SDIO_LOCK()			atbm_os_mutexLock(&sdio_lock,0)
#define SDIO_UNLOCK()			atbm_os_mutexUnLock(&sdio_lock)
#define __ATBM_SDIO_ALIGNSIZE(___blks,___size)	((___size)+(___blks)-((___size)%(___blks)))
#define ATBM_SDIO_ALIGNSIZE(_blks,_size)		(((_size)%(_blks)==0)?(_size):__ATBM_SDIO_ALIGNSIZE(_blks,_size))

#if 0
static T_hHisr atbm_sdio_handle;
static void *hisr_stack = ATBM_NULL;
static long isr_gpio = 0;
#define ATBM_HISR_STACK_SIZE	(2048)
#define ATBM_SET_HANLE(__hanle) atbm_sdio_handle = __hanle
#define ATBM_GET_HANEL()		atbm_sdio_handle
#endif

struct xs_mmc_card *atbm_card = NULL;


int atbm_sdio_register(struct atbm_sdio_driver *sdio_driver)
{
	struct xs_sdio_func *xs_func = NULL;
	struct atbm_sdio_func *func = NULL;

	/* init sdio driver */
	atbm_card = xs_sdio_init();
	/* success ? */
	if (atbm_card) {
		SDIO_FUNC0_INT(atbm_card);
		SDIO_FUNC1_INT(atbm_card);
		func = &(SDIO_FUNC1());
		xs_func = func->card->sdio_func[(func->num -1)];
		//rick debug wifi, set block size here?
		xs_sdio_set_block_size(xs_func,ATBM_BLKSZ);
		SDIO_LOCK_INIT();
		return sdio_driver->probe_func(&(SDIO_FUNC1()),sdio_driver->match_id_table);
	}
	wifi_printk(WIFI_DBG_ERROR, "%s, Init sdio driver faill.\r\n",__FUNCTION__);
	return -1;
} 
void atbm_sdio_deregister(struct atbm_sdio_driver *sdio_driver)
{
	//rick todo, de-init sdio driver
	sdio_driver->discon_func(&(SDIO_FUNC1()));
}
void atbm_sdio_claim_host(struct atbm_sdio_func *func)
{
	struct xs_sdio_func *xs_func = NULL;
	
	SDIO_LOCK();
	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		xs_sdio_claim_host(xs_func);
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
	
	
}
void atbm_sdio_release_host(struct atbm_sdio_func *func)
{
	struct xs_sdio_func *xs_func = NULL;

	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		xs_sdio_release_host(xs_func);
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
	SDIO_UNLOCK();
}

atbm_int32 atbm_sdio_enable_func(struct atbm_sdio_func *func)
{
	struct xs_sdio_func *xs_func = NULL;
	int err =0;

	SDIO_FUNC_SET_EN(func,1);
	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		err = xs_sdio_enable_func(xs_func);
		if (err) {
			wifi_printk(WIFI_DBG_ERROR, "%s, err %d.\r\n",
				__FUNCTION__,err);
		}
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
	return err;
}

void atbm_sdio_disable_func(struct atbm_sdio_func *func)
{
	struct xs_sdio_func *xs_func = NULL;
	int err =0;

	SDIO_FUNC_SET_EN(func,0);
	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		err = xs_sdio_disable_func(xs_func);
		if (err) {
			wifi_printk(WIFI_DBG_ERROR, "%s, err %d.\r\n",
				__FUNCTION__,err);
		}
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
}

void atbm_sdio_set_drvdata(struct atbm_sdio_func *func,void *priv)
{
	SDIO_FUNC_SET_PRIV(func,priv);
}

void *atbm_sdio_get_drvdata(struct atbm_sdio_func *func)
{
	return SDIO_FUNC_GET_PRIV(func);
}

int atbm_sdio_claim_irq(struct atbm_sdio_func *func,void (*irq_handle)(struct atbm_sdio_func *func))
{
	prv_irq_handle = (void *)irq_handle;
	struct xs_sdio_func *xs_func = NULL;
	int err =0;

	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		err = xs_sdio_claim_irq(xs_func, prv_irq_handle);
		if (err) {
			wifi_printk(WIFI_DBG_ERROR, "%s, err %d.\r\n",
				__FUNCTION__,err);
		}
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
	return err;
}

int atbm_sdio_release_irq(struct atbm_sdio_func *func)
{
	struct xs_sdio_func *xs_func = NULL;
	int err =0;

	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		err = xs_sdio_release_irq(xs_func);
		if (err) {
			wifi_printk(WIFI_DBG_ERROR, "%s, err %d.\r\n",
				__FUNCTION__,err);
		}
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
	return err;
}

int __atbm_sdio_memcpy_fromio(struct atbm_sdio_func *func,void *dst,unsigned int addr,int count)
{
	struct xs_sdio_func *xs_func = NULL;
	int err =0;

	if(func->en == 0){
		wifi_printk(WIFI_DBG_ERROR,"%s:func not en \r\n",__FUNCTION__);
		return -1;
	}

	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		err = xs_sdio_memcpy_fromio(xs_func,dst,addr,count);
		if (err) {
			wifi_printk(WIFI_DBG_ERROR, "%s, err %d.\r\n",
				__FUNCTION__,err);
		}
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
	return err;
}

int __atbm_sdio_memcpy_toio(struct atbm_sdio_func *func,unsigned int addr,void *src,int count)
{
	struct xs_sdio_func *xs_func = NULL;
	int err =0;

	if(func->en == 0){
		wifi_printk(WIFI_DBG_ERROR,"%s:func not en \r\n",__FUNCTION__);
		return -1;
	}

	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		err = xs_sdio_memcpy_toio(xs_func,addr,src,count);
		if (err) {
			wifi_printk(WIFI_DBG_ERROR, "%s, err %d.\r\n",
				__FUNCTION__,err);
		}
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
	return err;
}

unsigned char atbm_sdio_f0_readb(struct atbm_sdio_func *func,unsigned int addr,int *retval)
{
	struct xs_sdio_func *xs_func = &xs_dummy_f0;
 	unsigned char data = 0xff;

	if (func->num == 0) {
		data = xs_sdio_f0_readb(xs_func,addr,retval);
		if (*retval !=0) {
			wifi_printk(WIFI_DBG_ERROR, "%s, err_ret %d.\r\n",
				__FUNCTION__,*retval);
		}
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
	return data;
}

void atbm_sdio_f0_writeb(struct atbm_sdio_func *func,unsigned char regdata,unsigned int addr,int *retval)
{
	struct xs_sdio_func *xs_func = &xs_dummy_f0;

	if (func->num == 0) {
		xs_sdio_f0_writeb(xs_func,regdata,addr,retval);
		if (*retval) {
			wifi_printk(WIFI_DBG_ERROR, "%s, err_ret %d.\r\n",
				__FUNCTION__,*retval);
		}
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
}

int atbm_sdio_set_blocksize(struct atbm_sdio_func *func,int blocksize)
{
	struct xs_sdio_func *xs_func = NULL;
	int err =0;

	wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_set_blocksize(%d)(%d)\r\n",blocksize,func->blocksize);
	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		err = xs_sdio_set_block_size(xs_func,(unsigned int)blocksize);
		if (err) {
			wifi_printk(WIFI_DBG_ERROR, "%s, err %d.\r\n",
				__FUNCTION__,err);
		}
		SDIO_FUNC_SET_BLKSIZE(func,blocksize);
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}
	return err;
}

atbm_uint32 atbm_sdio_alignsize(struct atbm_sdio_func *func,atbm_uint32 size)
{
	struct xs_sdio_func *xs_func = NULL;
	atbm_uint32 block_size = SDIO_FUNC_GET_BLKSIZE(func);
	atbm_uint32 alignsize = size;
	if((block_size == 0)||(size == 0)){
		wifi_printk(WIFI_DBG_ERROR,"atbm_sdio_alignsize err\r\n");
		return alignsize;
	}

	if ((func->num >= 1 ) && (func->num <= SDIO_MAX_FUNCS)) {
		xs_func = func->card->sdio_func[(func->num -1)];
		alignsize = xs_sdio_align_size(xs_func,size);
	} else {
		wifi_printk(WIFI_DBG_ERROR, "%s, error fun num %d.\r\n",
			__FUNCTION__,func->num);
	}

	return alignsize;
}

static struct atbm_sdio_driver atmbwifi_driver;
extern int atbm_sdio_probe(struct atbm_sdio_func *func,const struct atbm_sdio_device_id *id);
extern int atbm_sdio_disconnect(struct atbm_sdio_func *func);
static struct atbm_sdio_device_id atbm_sdio_ids[] = {
	//{ SDIO_DEVICE(SDIO_ANY_ID, SDIO_ANY_ID) },
	{ /* end: all zeroes */			},
};
int atbm_sdio_register_init(void)
{
	int ret =0;
	atbm_memcpy(atmbwifi_driver.name, "atbm6021",sizeof("atbm6021"));;
	atmbwifi_driver.match_id_table	= atbm_sdio_ids;
	atmbwifi_driver.probe_func		= atbm_sdio_probe;
	atmbwifi_driver.discon_func		= atbm_sdio_disconnect;
	wifi_printk(WIFI_ALWAYS,"atbm_sdio_register_init\r\n");
	ret = atbm_sdio_register(&atmbwifi_driver);
	if (ret){
		wifi_printk(WIFI_DBG_ERROR,"atbmwifi driver register error\r\n");
		return ret;
	}
	return 0;
}
int atbm_sdio_register_deinit(void)
{
	atbm_sdio_deregister(&atmbwifi_driver);
	return 0;
}

