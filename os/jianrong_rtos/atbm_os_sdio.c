#include "atbm_hal.h"
/******** Functions below is Wlan API **********/
#include "atbm_os_sdio.h"
#include <stdint.h>
#include "lwip/netif.h"
#include "lwip/sockets.h"
#include "api.h"
#include "wifi.h"
#include "sdcard.h"
#if (PLATFORM==JIANRONG_RTOS_3268)

#include "sdio.h"
#endif

#define AK_SIDO_DEBUG_LEVEL	WIFI_DBG_MSG
#define AK_SIDO_ERR_LEVEL	WIFI_DBG_ERROR
typedef void (*irq_handle)(struct atbm_sdio_func *func);
static struct atbm_sdio_func func0;
static struct atbm_sdio_func func1;
static struct atbm_sdio_func *irq_func = ATBM_NULL;
static atbm_mutex sdio_lock;
static irq_handle func_irqhanlde = ATBM_NULL;

#define ATBM_CALL_IRQHANDLE() 					if(func_irqhanlde&&irq_func) func_irqhanlde(irq_func)
#define ATBM_SET_IRQ(__func,__handle)			irq_func = __func;func_irqhanlde = __handle

#define SDIO_FUNC_SET_EN(__func,__en)			(__func)->en = __en
#define SDIO_FUNC_SET_NUM(__func,__num)			(__func)->func = __num
#define SDIO_FUNC_SET_PRIV(__func,__priv)		(__func)->priv = __priv
#define SDIO_FUNC_SET_BLKSIZE(__func,__blks)	(__func)->blocksize = __blks
#define SDIO_FUNC_GET_EN(__func)				((__func)->en)
#define SDIO_FUNC_GET_NUM(__func)				((__func)->func)
#define SDIO_FUNC_GET_PRIV(__func)				((__func)->priv)
#define SDIO_FUNC_GET_BLKSIZE(__func)			((__func)->blocksize)	

#define SDIO_FUNC0_INT()						SDIO_FUNC_SET_NUM(&func0,0) ;SDIO_FUNC_SET_EN(&func0,1);	\
												SDIO_FUNC_SET_PRIV(&func0,ATBM_NULL);SDIO_FUNC_SET_BLKSIZE(&func0,288)
#define SDIO_FUNC1_INT()						SDIO_FUNC_SET_NUM(&func1,1) ;SDIO_FUNC_SET_EN(&func1,0);	\
												SDIO_FUNC_SET_PRIV(&func1,ATBM_NULL);SDIO_FUNC_SET_BLKSIZE(&func1,288)
#define SDIO_FUNC1()							func1
#define SDIO_FUNC0()							func0
#define SDIO_LOCK_INIT()						atbm_os_mutexLockInit(&sdio_lock)
#define SDIO_LOCK()								atbm_os_mutexLock(&sdio_lock,0)
#define SDIO_UNLOCK()							atbm_os_mutexUnLock(&sdio_lock)
#define __ATBM_SDIO_ALIGNSIZE(___blks,___size)	((___size)+(___blks)-((___size)%(___blks)))
#define ATBM_SDIO_ALIGNSIZE(_blks,_size)		(((_size)%(_blks)==0)?(_size):__ATBM_SDIO_ALIGNSIZE(_blks,_size))
#define SDIO_FBR_BASE(f)	((f) * 0x100) /* base of function f's FBRs */

//static T_hHisr atbm_sdio_handle;
static void *hisr_stack = ATBM_NULL;
static long isr_gpio = 0;
#define ATBM_HISR_STACK_SIZE	(2048)
//#define ATBM_SET_HANLE(__hanle) atbm_sdio_handle = __hanle
//#define ATBM_GET_HANEL()		atbm_sdio_handle

#if (PLATFORM==JIANRONG_RTOS_3268)
int sdio_enable_func(struct sdio_func *func)
{
	int ret;
	unsigned char reg;
	printf("enable func for sdio\n");
	ret = mmc_io_rw_direct(0, 0, SDIO_CCCR_IOEx, 0, &reg);
	printf("enable func for sdio  0--->%x %x\n",ret,func);
	if (ret  != SD_OK)
		goto err;

	reg |= 1 << func->num;
	printf("enable func for sdio  1\n");

	ret = mmc_io_rw_direct(1, 0, SDIO_CCCR_IOEx, reg, NULL);
	if (ret  != SD_OK)
		goto err;

	printf("enable func for sdio  2\n");

	while (1) {
		ret = mmc_io_rw_direct(0, 0, SDIO_CCCR_IORx, 0, &reg);
		if (ret  != SD_OK)
			goto err;
		if (reg & (1 << func->num))
			break;
	}
	printf("enable func for sdio  3\n");

	p_dbg("SDIO: Enabled func %d\n", reg);

	return 0;

err:
	p_err("SDIO: Failed to enable device\n");
	return ret;
}



void atbm_sdio_isr_enable(atbm_uint8 enable)
{
	if (enable){
		EXT_INT_ENABLE(EXT_INT2);
	}else{
		EXT_INT_DISABLE(EXT_INT2);
	}
}

static void atbm_sdio_gpio_handle(unsigned long pin, unsigned char polarity)
{
	atbm_sdio_isr_enable(1);
//	wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_gpio_handle\n");

//	AK_Activate_HISR(ATBM_GET_HANEL());
}
int atbm_sdio_register(struct atbm_sdio_driver *sdio_driver)
{
	SDIO_FUNC0_INT();
	//atbm_printk("atbm 1\r\n");
	SDIO_FUNC1_INT();
	//atbm_printk("atbm 2\r\n");
	SDIO_LOCK_INIT();
	//atbm_printk("atbm 3\r\n");
	return sdio_driver->probe_func(&SDIO_FUNC1(),sdio_driver->match_id_table);
	
} 
void atbm_sdio_deregister(struct atbm_sdio_driver *sdio_driver)
{
	sdio_driver->discon_func(&SDIO_FUNC1());
}
void atbm_sdio_claim_host(struct atbm_sdio_func *func)
{
	func = func;
	SDIO_LOCK();
}
void atbm_sdio_release_host(struct atbm_sdio_func *func)
{
	func = func;
	SDIO_UNLOCK();

}

atbm_int32 atbm_sdio_enable_func(struct atbm_sdio_func *func)
{
	//printf("func enable 0\n");
	SDIO_FUNC_SET_EN(func,1);
	//printf("func enable 1:%x  %x\n",func,func->func);
	sdio_enable_func(func);
	//printf("func enable 2\n");
}

void atbm_sdio_disable_func(struct atbm_sdio_func *func)
{
	SDIO_FUNC_SET_EN(func,0);
}

void atbm_sdio_set_drvdata(struct atbm_sdio_func *func,void *priv)
{
	SDIO_FUNC_SET_PRIV(func,priv);
}

void *atbm_sdio_get_drvdata(struct atbm_sdio_func *func)
{
	return SDIO_FUNC_GET_PRIV(func);
}

static int atbm_sdio_hisr_handle(void)
{
	wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_hisr_handle\n");
	ATBM_CALL_IRQHANDLE();
}
static void atbm_sdio_init_irq_gpio(int gpio_isr)
{
#if 0
	#define ATBM_AK_GPIO_INPUT			(0)
	#define ATBM_AK_GPIO_INTR_LOW		(0)
	#define ATBM_AK_INT_EN				(1)
	gpio_set_pin_as_gpio(gpio_isr);
	gpio_set_pin_dir(gpio_isr,ATBM_AK_GPIO_INPUT);
	gpio_set_int_p(gpio_isr,ATBM_AK_GPIO_INTR_LOW);
	gpio_int_control(gpio_isr,ATBM_AK_INT_EN);
	isr_gpio = gpio_isr;
#endif	
}

static int atbm_sdio_setup_gpio_irq(int gpio_isr)
{
#if 0
	T_hHisr atbm_hanlde = 0;
	
	atbm_sdio_init_irq_gpio(gpio_isr);
	hisr_stack = atbm_kmalloc(ATBM_HISR_STACK_SIZE,GFP_KERNEL);

	if(hisr_stack==NULL){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_hisr_handle,stack err\n");
		return -1;
	}

	atbm_hanlde = AK_Create_HISR(atbm_sdio_hisr_handle,"atbm",0,hisr_stack,ATBM_HISR_STACK_SIZE);


	ATBM_SET_HANLE(atbm_hanlde);

	gpio_intr_enable(gpio_isr,1,1,atbm_sdio_gpio_handle);
	gpio_int_control(gpio_isr,1);
	return 0;
#endif
}

void atbm_sdio_gpioirq_en(struct atbm_sdio_func *func,atbm_uint8 en)
{
	ATBM_BUG_ON(func == NULL);
	atbm_sdio_isr_enable(en);
}
int atbm_sdio_claim_irq(struct atbm_sdio_func *func,void (*irq_handle)(struct atbm_sdio_func *func))
{


		bool ret;
		atbm_uint8 reg = 0;
		int fd	=0;
		
		ATBM_SET_IRQ(func,irq_handle);
		
		ret = mmc_io_rw_direct(0,0,ATBM_SDIO_CCCR_IENx,0,&reg);
		printf("ATBM_SDIO_CCCR_IENx:%x\n",ret);
		if(ret){
			wifi_printk(AK_SIDO_DEBUG_LEVEL,"read ATBM_SDIO_CCCR_IENx err\n");
			goto __fail;
		}
	
		/* Master interrupt enable ... */
		reg |= BIT(0);
	
		/* ... for our function */
		reg |= BIT(1);
		
		//ret = sdio_write_byte(0,ATBM_SDIO_CCCR_IENx,reg);
		ret = mmc_io_rw_direct(1, 0, ATBM_SDIO_CCCR_IENx, reg, NULL);
		printf("ATBM_SDIO_CCCR_IENx:%x %x\n",ret,reg);		
		if(ret){
			//wifi_printk(AK_SIDO_DEBUG_LEVEL,"write ATBM_SDIO_CCCR_IENx err\n");
			goto __fail;
		}
//		ret = atbm_sdio_setup_gpio_irq(wifi->gpio_int.nb);
		BSP_IntVecReg(IO_INT, 0, irq_handle, func);

		enable_sdio_int(irq_handle);

		//if(ret == 0){
		//	dev_close(fd);
			return 0;
		//}
	__fail: 
		//dev_close(fd);
		//wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_claim_irq fail \n");
		return -1;

}

int atbm_sdio_release_irq(struct atbm_sdio_func *func)
{
	ATBM_SET_IRQ(ATBM_NULL,ATBM_NULL);
	//AK_Delete_HISR(ATBM_GET_HANEL());
	atbm_kfree(hisr_stack);
	return 0;

}

static int sdio_io_rw_ext_helper(struct sdio_func *func, int write,
	unsigned addr, int incr_addr, atbm_uint8 *buf, unsigned size)
{
	unsigned remainder = size;
	unsigned max_blocks;
	int ret;
    printf("func:%x\n",func);
	printf("func:%x\n",func->card);
	printf("func:%x\n",func->card->cccr);
	printf("func:%x\n",func->card->cccr.multi_block);
	
	if (func->card->cccr.multi_block) {
		max_blocks = 512;


		while (remainder > func->cur_blksize) {
			unsigned blocks;

			
			blocks = remainder / func->cur_blksize;
			
			if (blocks > max_blocks)
				blocks = max_blocks;
			size = blocks * func->cur_blksize;

			ret = mmc_io_rw_extended(write,
				func->num, addr, incr_addr, buf,
				blocks, func->cur_blksize);
			if (ret == 0xff)
				return ret;

			remainder -= size;
			buf += size;
			if (incr_addr)
				addr += size;
		}
	}
	/* Write the remainder using byte mode. */
	while (remainder > 0) {

		size = min(remainder, 512);

		ret = mmc_io_rw_extended(write, func->num, addr,
			 incr_addr, buf, 0, size);
		if (ret == 0xff)
			return ret;

		remainder -= size;
		buf += size;
		if (incr_addr)
			addr += size;
	}
	return 0;
}

extern atbm_uint8 atbm_down_finish;
int __atbm_sdio_memcpy_fromio(struct atbm_sdio_func *func,void *dst,unsigned int addr,int count)
{
	int blocks;
	int ret;
	int fn_bsize = SDIO_FUNC_GET_BLKSIZE(func);
	//printf("count:%d,fn:%d\n",count,func->func);
	if (count >= fn_bsize) {
		blocks = count / fn_bsize;
		
		//ret = sdio_read_multi(func_num, addr, blocks*fn_bsize, 1, dst);
		ret = mmc_io_rw_extended(0, func->func,
		addr, 1, dst, blocks, fn_bsize);
		if (ret !=0 ) {
			printf("atbm_sdio_memcpy_fromio: failed.ret=%d.\n", ret);
			return -1;
		}		
		count = count - blocks*fn_bsize;
		addr += blocks*fn_bsize;
		dst += blocks*fn_bsize;				
	}
   // printf("cou2:%d %d\n",atbm_down_finish,count);
	if (count) {		
		//ret = sdio_read_multi(func_num, addr, count, 1, dst);
		//if(atbm_down_finish == 0){
		//	ret = mmc_io_rw_extended(0, func->func,
		//	addr, 1, dst, 1, count);
		//}else
		{
			ret = mmc_io_rw_extended(0, func->func,
			addr, 1, dst, 1, count);
		}

		if (ret !=0 ) {
			printf("atbm_sdio_memcpy_fromio: failed.ret=%d.\n", ret);
			return -1;
		}	
	}
	
	return 0;	
}

int __atbm_sdio_memcpy_toio(struct atbm_sdio_func *func,unsigned int addr,void *dst,int count)
{
	int blocks;
	int ret;

	int fn_bsize = SDIO_FUNC_GET_BLKSIZE(func);
	//printf("count:%d,fn_bsize:%d\n",count,fn_bsize);

	if (count >= fn_bsize) {
		blocks = count / fn_bsize;
		
		//ret = sdio_read_multi(func_num, addr, blocks*fn_bsize, 1, dst);
		ret = mmc_io_rw_extended(1, func->func,
		addr, 1, dst, blocks, fn_bsize);
		if (ret !=0 ) {
			printf("xr_sdio_memcpy_fromio: failed.ret=%d.\n", ret);
			return -1;
		}	
		count = count - blocks*fn_bsize;
		addr += blocks*fn_bsize;
		dst += blocks*fn_bsize; 	
		
	}
    //printf("cou2:%d %d\n",atbm_down_finish,count);
	if (count) {
		//ret = sdio_read_multi(func_num, addr, count, 1, dst);
		//if(atbm_down_finish == 0){
		//	ret = mmc_io_rw_extended(1, func->func,
		//	addr, 1, dst, 1, count);
		//}
		//else
		{
			ret = mmc_io_rw_extended(1, func->func,
			addr, 1, dst, 1, count);
		}

		if (ret !=0 ) {
			printf("xr_sdio_memcpy_fromio: failed.ret=%d.\n", ret);
			return -1;
		}	
	}
	
	return 0;
}

unsigned char atbm_sdio_f0_readb(struct atbm_sdio_func *func,unsigned int addr,int *retval)
{
		int ret;
		unsigned char val;
	
		if (retval)
			*retval = 0;
	
		ret = mmc_io_rw_direct(0, 0, addr, 0, &val);
		if (ret) {
			if (retval)
				*retval = ret;
			return 0xFF;
		}
	
		return val;

}

void atbm_sdio_f0_writeb(struct atbm_sdio_func *func,unsigned char regdata,unsigned int addr,int *retval)
{
	int ret;

	if ((addr < 0xF0 || addr > 0xFF) /*&& (!mmc_card_lenient_fn0(func->card))*/) {
		if (retval)
			*retval = -EINVAL;
		return;
	}

	ret = mmc_io_rw_direct(1, 0, addr, regdata, NULL);
	if (retval)
		*retval = ret;

}

int sdio_set_block_size(int fn,unsigned blksz)
{
	int ret = 0;
	ret = mmc_io_rw_direct(1, 0,
		SDIO_FBR_BASE(fn) + 0x10,
		blksz & 0xff, NULL);
	if (ret)
		goto end;
	ret = mmc_io_rw_direct(1, 0,
		SDIO_FBR_BASE(fn) + 0x11,
		(blksz >> 8) & 0xff, NULL);


	if (ret)
		goto end;
end:
	return ret;
}


int  atbm_sdio_set_blocksize(struct atbm_sdio_func *func,int blocksize)
{
	//sdio_set_block_len(func->func,blocksize);
	sdio_set_block_size(func->func,blocksize);
	SDIO_FUNC_SET_BLKSIZE(func,blocksize);
	//wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_set_blocksize(%d)(%d)\n",blocksize,func->blocksize);
	return 0;

}

atbm_uint32 atbm_sdio_alignsize(struct atbm_sdio_func *func,atbm_uint32 size)
{
	atbm_uint32 block_size = SDIO_FUNC_GET_BLKSIZE(func);
	atbm_uint32 alignsize = size;
	if((block_size == 0)||(size == 0)){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_alignsize err\n");
		return alignsize;
	}

	alignsize = ATBM_SDIO_ALIGNSIZE(block_size,size);
	return alignsize;

}
#else

extern struct mmc_host bw_mmc_host;
struct sdio_func *wifi_sdio_func;

struct sdio_func rtw_func = {
  .num = 1,
  .enable_timeout = 100,
};

struct mmc_card rtw_card =  {
  .host = &bw_mmc_host,
  .func = &rtw_func,
};

struct mmc_host bw_mmc_host = {
  .card = &rtw_card,
};


bool gpio_isr_enable(bool enable)
{
	struct mmc_host *sd_host;
    sd_host = &bw_mmc_host;
	if (enable)
	{
		sdc_ext_int_enable(sd_host, sd_host->controller,1);
	}
	else
	{
		sdc_ext_int_enable(sd_host, sd_host->controller,0);
	}

}



int sdio_enable_func_atbm(struct sdio_func *func)
{
	int ret;
	unsigned char reg;
	printf("enable func for sdio\n");
	struct mmc_host *sd_host;
    sd_host = &bw_mmc_host;
	printf("sdio_enable_func_atbm init bw_mmc_host:%X\r\n",&bw_mmc_host);
	ret = mmc_io_rw_direct(sd_host->card,0, 0, SDIO_CCCR_IOEx, 0, &reg);
	printf("enable func for sdio  0--->%x %x\n",ret,func);
	if (ret  != SD_OK)
		goto err;

	reg |= 1 << func->num;
	printf("enable func for sdio  1\n");

	ret = mmc_io_rw_direct(sd_host->card,1, 0, SDIO_CCCR_IOEx, reg, NULL);
	if (ret  != SD_OK)
		goto err;

	printf("enable func for sdio  2\n");

	while (1) {
		ret = mmc_io_rw_direct(sd_host->card,0, 0, SDIO_CCCR_IORx, 0, &reg);
		if (ret  != SD_OK)
			goto err;
		if (reg & (1 << func->num))
			break;
	}
	printf("enable func for sdio  3\n");

	p_dbg("SDIO: Enabled func %d\n", reg);

	return 0;

err:
	p_err("SDIO: Failed to enable device\n");
	return ret;
}



void atbm_sdio_isr_enable(atbm_uint8 enable)
{
	if (enable){
		gpio_isr_enable(enable);
	}else{
	gpio_isr_enable(enable);
	}
}

static void atbm_sdio_gpio_handle(unsigned long pin, unsigned char polarity)
{
	atbm_sdio_isr_enable(1);
//	wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_gpio_handle\n");

//	AK_Activate_HISR(ATBM_GET_HANEL());
}
int atbm_sdio_register(struct atbm_sdio_driver *sdio_driver)
{
	SDIO_FUNC0_INT();
	SDIO_FUNC1_INT();
	SDIO_LOCK_INIT();
	return sdio_driver->probe_func(&SDIO_FUNC1(),sdio_driver->match_id_table);
} 
void atbm_sdio_deregister(struct atbm_sdio_driver *sdio_driver)
{
	sdio_driver->discon_func(&SDIO_FUNC1());
}
void atbm_sdio_claim_host(struct atbm_sdio_func *func)
{
	func = func;
	SDIO_LOCK();
}
void atbm_sdio_release_host(struct atbm_sdio_func *func)
{
	func = func;
	SDIO_UNLOCK();

}

atbm_int32 atbm_sdio_enable_func(struct atbm_sdio_func *func)
{
	//printf("func enable 0\n");
	SDIO_FUNC_SET_EN(func,1);
	//printf("func enable 1:%x  %x\n",func,func->func);
	sdio_enable_func_atbm(func);
	//printf("func enable 2\n");
}

void atbm_sdio_disable_func(struct atbm_sdio_func *func)
{
	SDIO_FUNC_SET_EN(func,0);
}

void atbm_sdio_set_drvdata(struct atbm_sdio_func *func,void *priv)
{
	SDIO_FUNC_SET_PRIV(func,priv);
}

void *atbm_sdio_get_drvdata(struct atbm_sdio_func *func)
{
	return SDIO_FUNC_GET_PRIV(func);
}

static int atbm_sdio_hisr_handle(void)
{
	wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_hisr_handle\n");
	ATBM_CALL_IRQHANDLE();
}
static void atbm_sdio_init_irq_gpio(int gpio_isr)
{
#if 0
	#define ATBM_AK_GPIO_INPUT			(0)
	#define ATBM_AK_GPIO_INTR_LOW		(0)
	#define ATBM_AK_INT_EN				(1)
	gpio_set_pin_as_gpio(gpio_isr);
	gpio_set_pin_dir(gpio_isr,ATBM_AK_GPIO_INPUT);
	gpio_set_int_p(gpio_isr,ATBM_AK_GPIO_INTR_LOW);
	gpio_int_control(gpio_isr,ATBM_AK_INT_EN);
	isr_gpio = gpio_isr;
#endif	
}

static int atbm_sdio_setup_gpio_irq(int gpio_isr)
{
#if 0
	T_hHisr atbm_hanlde = 0;
	
	atbm_sdio_init_irq_gpio(gpio_isr);
	hisr_stack = atbm_kmalloc(ATBM_HISR_STACK_SIZE,GFP_KERNEL);

	if(hisr_stack==NULL){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_hisr_handle,stack err\n");
		return -1;
	}

	atbm_hanlde = AK_Create_HISR(atbm_sdio_hisr_handle,"atbm",0,hisr_stack,ATBM_HISR_STACK_SIZE);


	ATBM_SET_HANLE(atbm_hanlde);

	gpio_intr_enable(gpio_isr,1,1,atbm_sdio_gpio_handle);
	gpio_int_control(gpio_isr,1);
	return 0;
#endif
}

void atbm_sdio_gpioirq_en(struct atbm_sdio_func *func,atbm_uint8 en)
{
	ATBM_BUG_ON(func == NULL);
	atbm_sdio_isr_enable(en);
}
int atbm_sdio_claim_irq(struct atbm_sdio_func *func,void (*irq_handle)(struct atbm_sdio_func *func))
{
		bool ret;
		atbm_uint8 reg = 0;
		int fd	=0;
		struct mmc_host *sd_host;
	    sd_host = &bw_mmc_host;
		
		ATBM_SET_IRQ(func,irq_handle);
		
		ret = mmc_io_rw_direct(sd_host->card,0,0,ATBM_SDIO_CCCR_IENx,0,&reg);
		printf("ATBM_SDIO_CCCR_IENx:%x\n",ret);
		if(ret){
			wifi_printk(AK_SIDO_DEBUG_LEVEL,"read ATBM_SDIO_CCCR_IENx err\n");
			goto __fail;
		}
	
		/* Master interrupt enable ... */
		reg |= BIT(0);
	
		/* ... for our function */
		reg |= BIT(1);
		ret = mmc_io_rw_direct(sd_host->card,1, 0, ATBM_SDIO_CCCR_IENx, reg, NULL);
		printf("ATBM_SDIO_CCCR_IENx:%x %x\n",ret,reg);		
		if(ret){
			goto __fail;
		}
//		ret = atbm_sdio_setup_gpio_irq(wifi->gpio_int.nb);
		printf("atbm_sdio_claim_irq:%X\r\n",func);
		irq_register(7, 0, irq_handle, func);

			return 0;
		//}
	__fail: 
		//dev_close(fd);
		//wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_claim_irq fail \n");
		return -1;

}

int atbm_sdio_release_irq(struct atbm_sdio_func *func)
{
	ATBM_SET_IRQ(ATBM_NULL,ATBM_NULL);
	atbm_kfree(hisr_stack);
	return 0;
}
static int sdio_io_rw_ext_helper(struct sdio_func *func, int write,
	unsigned addr, int incr_addr, atbm_uint8 *buf, unsigned size)
{
	unsigned remainder = size;
	unsigned max_blocks;
	int ret;
	struct mmc_host *sd_host;
    sd_host = &bw_mmc_host;
    printf("func:%x\n",func);
	printf("func:%x\n",func->card);
	printf("func:%x\n",func->card->cccr);
	printf("func:%x\n",func->card->cccr.multi_block);
	
	if (func->card->cccr.multi_block) {
		max_blocks = 512;


		while (remainder > func->cur_blksize) {
			unsigned blocks;

			
			blocks = remainder / func->cur_blksize;
			
			if (blocks > max_blocks)
				blocks = max_blocks;
			size = blocks * func->cur_blksize;

			ret = mmc_io_rw_extended(sd_host->card,write,
				func->num, addr, incr_addr, buf,
				blocks, func->cur_blksize);
			if (ret == 0xff)
				return ret;

			remainder -= size;
			buf += size;
			if (incr_addr)
				addr += size;
		}
	}
	/* Write the remainder using byte mode. */
	while (remainder > 0) {

		size = min(remainder, 512);

		ret = mmc_io_rw_extended(sd_host->card,write, func->num, addr,
			 incr_addr, buf, 0, size);
		if (ret == 0xff)
			return ret;

		remainder -= size;
		buf += size;
		if (incr_addr)
			addr += size;
	}
	return 0;
}

extern atbm_uint8 atbm_down_finish;
int __atbm_sdio_memcpy_fromio(struct atbm_sdio_func *func,void *dst,unsigned int addr,int count)
{
	int blocks;
	int ret;
	int fn_bsize = SDIO_FUNC_GET_BLKSIZE(func);
	struct mmc_host *sd_host;
    sd_host = &bw_mmc_host;
	//printf("count:%d,fn:%d\n",count,func->func);
	if (count >= fn_bsize) {
		blocks = count / fn_bsize;
		
		//ret = sdio_read_multi(func_num, addr, blocks*fn_bsize, 1, dst);
		ret = mmc_io_rw_extended(sd_host->card,0, func->func,
		addr, 1, dst, blocks, fn_bsize);
		if (ret !=0 ) {
			printf("atbm_sdio_memcpy_fromio: failed.ret=%d.\n", ret);
			return -1;
		}		
		count = count - blocks*fn_bsize;
		addr += blocks*fn_bsize;
		dst += blocks*fn_bsize;				
	}
   // printf("cou2:%d %d\n",atbm_down_finish,count);
	if (count) {		
		//ret = sdio_read_multi(func_num, addr, count, 1, dst);
		//if(atbm_down_finish == 0){
		//	ret = mmc_io_rw_extended(0, func->func,
		//	addr, 1, dst, 1, count);
		//}else
		{
			ret = mmc_io_rw_extended(sd_host->card,0, func->func,
			addr, 1, dst, 1, count);
		}

		if (ret !=0 ) {
			printf("atbm_sdio_memcpy_fromio: failed.ret=%d.\n", ret);
			return -1;
		}	
	}
	
	return 0;	
}

int __atbm_sdio_memcpy_toio(struct atbm_sdio_func *func,unsigned int addr,void *dst,int count)
{
	int blocks;
	int ret;
	struct mmc_host *sd_host;
    sd_host = &bw_mmc_host;
	int fn_bsize = SDIO_FUNC_GET_BLKSIZE(func);
	//printf("count:%d,fn_bsize:%d\n",count,fn_bsize);

	if (count >= fn_bsize) {
		blocks = count / fn_bsize;
		
		//ret = sdio_read_multi(func_num, addr, blocks*fn_bsize, 1, dst);
		ret = mmc_io_rw_extended(sd_host->card,1, func->func,
		addr, 1, dst, blocks, fn_bsize);
		if (ret !=0 ) {
			printf("xr_sdio_memcpy_fromio: failed.ret=%d.\n", ret);
			return -1;
		}	
		count = count - blocks*fn_bsize;
		addr += blocks*fn_bsize;
		dst += blocks*fn_bsize; 	
		
	}
    //printf("cou2:%d %d\n",atbm_down_finish,count);
	if (count) {
		//ret = sdio_read_multi(func_num, addr, count, 1, dst);
		//if(atbm_down_finish == 0){
		//	ret = mmc_io_rw_extended(1, func->func,
		//	addr, 1, dst, 1, count);
		//}
		//else
		{
			ret = mmc_io_rw_extended(sd_host->card,1, func->func,
			addr, 1, dst, 1, count);
		}

		if (ret !=0 ) {
			printf("xr_sdio_memcpy_fromio: failed.ret=%d.\n", ret);
			return -1;
		}	
	}
	
	return 0;
}

unsigned char atbm_sdio_f0_readb(struct atbm_sdio_func *func,unsigned int addr,int *retval)
{
		int ret;
		unsigned char val;
	struct mmc_host *sd_host;
    sd_host = &bw_mmc_host;
	
		if (retval)
			*retval = 0;
	
		ret = mmc_io_rw_direct(sd_host->card,0, 0, addr, 0, &val);
		if (ret) {
			if (retval)
				*retval = ret;
			return 0xFF;
		}
	
		return val;

}

void atbm_sdio_f0_writeb(struct atbm_sdio_func *func,unsigned char regdata,unsigned int addr,int *retval)
{
	int ret;
	struct mmc_host *sd_host;
    sd_host = &bw_mmc_host;

	if ((addr < 0xF0 || addr > 0xFF) /*&& (!mmc_card_lenient_fn0(func->card))*/) {
		if (retval)
			*retval = -EINVAL;
		return;
	}

	ret = mmc_io_rw_direct(sd_host->card,1, 0, addr, regdata, NULL);
	if (retval)
		*retval = ret;

}

int sdio_set_block_size_atbm(int fn,unsigned blksz)
{
	int ret = 0;
	struct mmc_host *sd_host;
    sd_host = &bw_mmc_host;
	ret = mmc_io_rw_direct(sd_host->card,1, 0,
		SDIO_FBR_BASE(fn) + 0x10,
		blksz & 0xff, NULL);
	if (ret)
		goto end;
	ret = mmc_io_rw_direct(sd_host->card,1, 0,
		SDIO_FBR_BASE(fn) + 0x11,
		(blksz >> 8) & 0xff, NULL);


	if (ret)
		goto end;
end:
	return ret;
}


int  atbm_sdio_set_blocksize(struct atbm_sdio_func *func,int blocksize)
{
	//sdio_set_block_len(func->func,blocksize);
	sdio_set_block_size_atbm(func->func,blocksize);
	SDIO_FUNC_SET_BLKSIZE(func,blocksize);
	//wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_set_blocksize(%d)(%d)\n",blocksize,func->blocksize);
	return 0;

}

atbm_uint32 atbm_sdio_alignsize(struct atbm_sdio_func *func,atbm_uint32 size)
{
	atbm_uint32 block_size = SDIO_FUNC_GET_BLKSIZE(func);
	atbm_uint32 alignsize = size;
	if((block_size == 0)||(size == 0)){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_alignsize err\n");
		return alignsize;
	}

	alignsize = ATBM_SDIO_ALIGNSIZE(block_size,size);
	return alignsize;

}
#endif
