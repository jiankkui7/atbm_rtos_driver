#include "atbm_hal.h"
/******** Functions below is Wlan API **********/
#include "atbm_os_sdio.h"
#include <stdint.h>
//#include "lwip/netif.h"
//#include "lwip/sockets.h"
//#include "lwip/capture.h"
#include "akos_api.h"
//#include "drv_api.h"
//#include "platform_devices.h"
//#include "dev_drv.h"
#include "drv_gpio.h"
//#include "wifi.h"
#include "drv_module.h"

#define AK_SIDO_DEBUG_LEVEL	WIFI_DBG_MSG
#define AK_SIDO_ERR_LEVEL	WIFI_DBG_ERROR
typedef void (*irq_handle)(struct atbm_sdio_func *func);
static struct atbm_sdio_func func0;
static struct atbm_sdio_func func1;
struct atbm_sdio_cccr cccr;
static struct atbm_sdio_func *irq_func = ATBM_NULL;
static atbm_mutex sdio_lock;
static irq_handle func_irqhanlde = ATBM_NULL;
static int mmc_bus_interface_control(int enable);
static int mmc_sdio_switch_hs(int enable);
static int atbm_sdio_read_cccr(void);

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
#define ATBM_SDIO_ENABLE_HS(X) mmc_sdio_switch_hs(X)
#define ATBM_SET_BUS() mmc_bus_interface_control()
#define ATBM_READ_CCCR() atbm_sdio_read_cccr()
#define SDIO_FBR_BASE(f)	((f) * 0x100) /* base of function f's FBRs */

static T_hHisr atbm_sdio_handle;
static void *hisr_stack = ATBM_NULL;
static long isr_gpio = 0;
#define ATBM_HISR_STACK_SIZE	(2048)
#define ATBM_SET_HANLE(__hanle) atbm_sdio_handle = __hanle
#define ATBM_GET_HANEL()		atbm_sdio_handle

int g_get_sdio_which_mci = 0;
/**                                             
* @brief atbm_get_sdio_which_mci  function
* @author charlie
* @date 2019-12-19
* @param [in] sdio_irq_vector
* @return int
* @retval 0 operation failed
* @retval 1 operation successful 
*/ 
int atbm_get_sdio_which_mci(void)
{
	int i=0;
	unsigned char sdio_irq_vector = 0;
	int bus_width = 0, frequency = 0;
	T_eCARD_INTERFACE cif;
	
	for(i = 0; i < 3; i++)
	{
		if(sdio_init_info(i, &bus_width, &frequency))
		{
			break;
		}
	}
	
	if(i == 0){
		cif = INTERFACE_SDMMC4;
		sdio_irq_vector =INT_VECTOR_MMC0;
	}else if(i == 1){
		cif = INTERFACE_SDIO;
		sdio_irq_vector =INT_VECTOR_MMC1;
	}
	else if(i == 2){
		cif = INTERFACE_SDIO2;
		sdio_irq_vector =INT_VECTOR_MMC2;
	}
	else{
		wifi_printk(WIFI_ERROR,"find sdio index in dtb fail\n");
		return -1;
	}
	wifi_printk(WIFI_ALWAYS,"fixed sdio interface =%d,sdio_irq_vector=%d\n",cif,sdio_irq_vector);
	g_get_sdio_which_mci = sdio_irq_vector;
	return 0;
}

int mmc_io_rw_direct(atbm_uint32 write, unsigned fn, unsigned addr, atbm_uint8 in, atbm_uint8 *out)
{
	int ret;

	if(write){
		ret =  sdio_write_byte(fn, addr, in);
	}else{
		ret =  sdio_read_byte(fn, addr, out);
	}
	if(ret == 0)
		return 0;

	return -1;
}
int mmc_bus_interface_control(int enable)
{
	int ret;
	unsigned char data;
	ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_IF, 0, &data);
	if (ret != 0)
		goto out;

	data |= 0X20;
	ret = mmc_io_rw_direct(1, 0, ATBM_SDIO_CCCR_IF, data, &data);
	if (ret != 0)
		goto out;
out:
	if (ret != 0)
	wifi_printk(WIFI_ALWAYS,"sdio_read_cccr err\n");
	return ret;

}
int mmc_sdio_switch_hs(int enable)
{
	int ret;
	atbm_uint8 speed;

	ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_SPEED, 0, &speed);
	if (ret != 0)
	{
		wifi_printk(WIFI_SDIO,"mmc_sdio_switch_hs err:%d\n", ret);
		return ret;
	}
	if (enable)
		speed |= ATBM_SDIO_SPEED_EHS;
	else
		speed &= ~ATBM_SDIO_SPEED_EHS;

	ret = mmc_io_rw_direct(1, 0, ATBM_SDIO_CCCR_SPEED, speed, NULL);
	if (ret != 0)
		wifi_printk(WIFI_SDIO,"mmc_sdio_switch_hs err1:%d\n", ret);
	else
		wifi_printk(WIFI_SDIO,"mmc_sdio_switch_hs ok\n");

	return ret;
}

static int atbm_sdio_read_cccr(void)
{
	int ret;
	int cccr_vsn;
	unsigned char data;

	atbm_memset(&cccr, 0, sizeof(struct atbm_sdio_cccr));

	ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_CCCR, 0, &data);
	if (ret != 0)
		goto out;

	cccr_vsn = data & 0x0f;
	wifi_printk(WIFI_SDIO,"SDIO_CCCR_CCCR:%x\n", cccr_vsn);

	if (cccr_vsn > SDIO_CCCR_REV_1_20)
	{
		wifi_printk(WIFI_SDIO,"unrecognised CCCR structure version %d\n", cccr_vsn);
		return -1;
	}

	cccr.sdio_vsn = (data & 0xf0) >> 4;

	ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_CAPS, 0, &data);
	if (ret != 0)
		goto out;

	wifi_printk(WIFI_SDIO,"SDIO_CCCR_CAPS:%x\n", data);
	if (data & SDIO_CCCR_CAP_SMB)
		cccr.multi_block = 1;
	if (data & SDIO_CCCR_CAP_LSC)
		cccr.low_speed = 1;
	if (data & SDIO_CCCR_CAP_4BLS)
		cccr.wide_bus = 1;

	if (cccr_vsn >= SDIO_CCCR_REV_1_10)
	{
		ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_POWER, 0, &data);

		wifi_printk(WIFI_SDIO,"SDIO_CCCR_POWER:%x\n", data);
		if (ret != 0)
			goto out;

		if (data & SDIO_POWER_SMPC)
			cccr.high_power = 1;
	}

	if (cccr_vsn >= SDIO_CCCR_REV_1_20)
	{
		ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_SPEED, 0, &data);

		wifi_printk(WIFI_SDIO,"SDIO_CCCR_SPEED:%x\n", data);
		if (ret != 0)
			goto out;

		if (data & ATBM_SDIO_SPEED_SHS)
			cccr.high_speed = 1;
	}

	ret = mmc_io_rw_direct(0, 0, 7, 0, &data);
	if (ret != 0)
		goto out;

	data |= 0X20;
	ret = mmc_io_rw_direct(1, 0, 7, data, &data);
	if (ret != 0)
		goto out;
	
out:
	if (ret != 0)
		wifi_printk(WIFI_SDIO,"sdio_read_cccr err\n");
	return ret;
}

int __atbm_sdio_enable_func(int num)
{
	int ret;
	unsigned char reg;
	wifi_printk(WIFI_SDIO,"enable func for sdio\n");
	ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_IOEx, 0, &reg);
	wifi_printk(WIFI_SDIO,"enable func for sdio  0--->%x %x\n",ret,num);
	if (ret  != 0)
		goto err;

	reg |= 1 <<num;
	wifi_printk(WIFI_SDIO,"enable func for sdio  1\n");

	ret = mmc_io_rw_direct(1, 0, ATBM_SDIO_CCCR_IOEx, reg, NULL);
	if (ret  != 0)
		goto err;

	wifi_printk(WIFI_SDIO,"enable func for sdio  2\n");

	while (1) {
		ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_IOEx, 0, &reg);
		if (ret  != 0)
			goto err;
		if (reg & (1 <<num))
			break;
	}
	wifi_printk(WIFI_SDIO,"enable func for sdio  3\n");

	wifi_printk(WIFI_SDIO,"SDIO: Enabled func %d\n", reg);

	return 0;

err:
	wifi_printk(WIFI_SDIO,"SDIO: Failed to enable device\n");
	return ret;
}

void atbm_sdio_isr_enable(atbm_uint8 enable);

static void atbm_sdio_gpio_handle(unsigned long *pin, unsigned long polarity)
{
//	atbm_sdio_isr_enable(0);
	//wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_gpio_handle\n");

	AK_Activate_HISR(ATBM_GET_HANEL());
}
int atbm_sdio_register(struct atbm_sdio_driver *sdio_driver)
{
	wifi_printk(WIFI_SDIO,"atbm_sdio_register\n");
	ATBM_SDIO_ENABLE_HS(1);
	ATBM_READ_CCCR();
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
	wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_enable_func(%d)\n",func->func);
	SDIO_FUNC_SET_EN(func,1);
	sdio_enable_func(func->func);
	return 0;
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
#ifdef AK_GPIO
void atbm_sdio_isr_enable(atbm_uint8 enable)
{
	gpio_int_control(isr_gpio,enable);
}
void atbm_sdio_hisr_handle(void)
{
	//wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_hisr_handle\n");
	ATBM_CALL_IRQHANDLE();
}
static void atbm_sdio_init_irq_gpio(int gpio_isr)
{
	#define ATBM_AK_GPIO_INPUT			(0)
	#define ATBM_AK_GPIO_INTR_LOW		(0)
	#define ATBM_AK_INT_EN				(1)
	gpio_set_pin_as_gpio(gpio_isr);
	gpio_set_pin_dir(gpio_isr,ATBM_AK_GPIO_INPUT);
	gpio_set_int_p(gpio_isr,ATBM_AK_GPIO_INTR_LOW);
	gpio_int_control(gpio_isr,ATBM_AK_INT_EN);
	isr_gpio = gpio_isr;
}
static int atbm_sdio_setup_gpio_irq(int gpio_isr)
{
	T_hHisr atbm_hanlde = 0;

	wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_setup_gpio_irq(%d)\n",gpio_isr);
	atbm_sdio_init_irq_gpio(gpio_isr);
	hisr_stack = atbm_kmalloc(ATBM_HISR_STACK_SIZE,GFP_KERNEL);

	if(hisr_stack==NULL){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_hisr_handle,stack err\n");
		return -1;
	}

	atbm_hanlde = AK_Create_HISR(atbm_sdio_hisr_handle,"atbm",0,hisr_stack,ATBM_HISR_STACK_SIZE);

	if(AK_IS_INVALIDHANDLE(atbm_hanlde)){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_hisr_handle,atbm_hanlde err\n");

		return -1;
	}

	ATBM_SET_HANLE(atbm_hanlde);

//	gpio_register_int_callback(gpio_isr,0,0,atbm_sdio_gpio_handle);
	gpio_intr_enable(gpio_isr,1,1,atbm_sdio_gpio_handle);
	gpio_int_control(gpio_isr,1);
	return 0;
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
	int fd  =0;
	T_WIFI_INFO  *wifi =  ATBM_NULL; //(T_WIFI_INFO *)wifi_dev.dev_data;
	
	fd = dev_open(DEV_WIFI);
    if(fd < 0)
    {
       wifi_printk(AK_SIDO_DEBUG_LEVEL,"open wifi faile\r\n");
        return -1;
    }
	dev_read(fd,  &wifi, sizeof(unsigned int *));

	
	ATBM_SET_IRQ(func,irq_handle);
	ret = sdio_read_byte(0,ATBM_SDIO_CCCR_IENx,&reg);
	if(ret == false){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"read ATBM_SDIO_CCCR_IENx err\n");
		goto __fail;
	}

	/* Master interrupt enable ... */
	reg |= BIT(0);

	/* ... for our function */
	reg |= BIT(1);
	
	ret = sdio_write_byte(0,ATBM_SDIO_CCCR_IENx,reg);
	if(ret == false){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"write ATBM_SDIO_CCCR_IENx err\n");
		goto __fail;
	}
	ret = atbm_sdio_setup_gpio_irq(wifi->gpio_int.nb);
	
	if(ret == 0){
		dev_close(fd);
		return 0;
	}
__fail:	
	dev_close(fd);
	wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_claim_irq fail \n");
	return -1;
}

int atbm_sdio_release_irq(struct atbm_sdio_func *func)
{
	ATBM_SET_IRQ(ATBM_NULL,ATBM_NULL);
	AK_Delete_HISR(ATBM_GET_HANEL());
	atbm_kfree(hisr_stack);
	return 0;
}
#else //AK_SDIO
#define SDIO_MESSAGE 1
OS_TIMER  bh_wake;
extern struct atbmwifi_common g_hw_prv;
atbm_void atbmwifi_bh_wake(TIMER_1ST_PARAM atbm_void *arg)
{
	if (atbm_atomic_add_return(1, &g_hw_prv.bh_rx) == 1){
		atbm_os_wakeup_event(&g_hw_prv.bh_wq);
		atbm_StartTimer(&bh_wake,5*HZ);
	}
}
static ATBM_BOOL atbm_sdio_interrupt_int_callback( atbm_void)
{
	wifi_printk(WIFI_SDIO,"atbm_sdio_interrupt_int_callback \n");
	ATBM_CALL_IRQHANDLE();
	return true;
}
static ATBM_BOOL sdio_interrupt_int_callback( unsigned long gpionum, unsigned char level)
{
	wifi_printk(WIFI_SDIO,"sdio_interrupt_int_callback \n");
	sdio_enable_irq(g_get_sdio_which_mci , 0);
	DrvModule_Send_Message(DRV_MODULE_SDIO2, SDIO_MESSAGE, NULL);
	return true;
}

static int atbm_sdio_data1_irq(void)
{
	
	wifi_printk(WIFI_SDIO,"sdio_interrupt_int_callback \n");
    //create drv module sdio task
    if(!DrvModule_Create_Task(DRV_MODULE_SDIO2))
    {
       DrvModule_UnProtect(DRV_MODULE_SDIO2); 
       return -1;
    }
	//wifi_printk(WIFI_ALWAYS,"atbm_sdio_data1_irq check .....[1]\n");
	DrvModule_Protect(DRV_MODULE_SDIO2); 
    //set massage and handler
    DrvModule_Map_Message(DRV_MODULE_SDIO2, SDIO_MESSAGE, atbm_sdio_interrupt_int_callback);
	int_register_irq(g_get_sdio_which_mci , sdio_interrupt_int_callback);
	sdio_enable_irq(g_get_sdio_which_mci , 1);
	
	//wifi_printk(WIFI_ALWAYS,"\nWifilib =============0x2010,8000:0x%x\n", *(volatile int *)(0x20108000));
	//wifi_printk(WIFI_ALWAYS,"\nWifilib =============0x2010,8038:0x%x\n", *(volatile int *)(0x20108038));
	//wifi_printk(WIFI_ALWAYS,"\nWifilib =============0x0800,0024:0x%x\n", *(volatile int *)(0x08000024));
	DrvModule_UnProtect(DRV_MODULE_SDIO2); 
	return 0;

}
int atbm_sdio_claim_irq(struct atbm_sdio_func *func,void (*irq_handle)(struct atbm_sdio_func *func))
{
	pAtbm_thread_t bh_thread;
	struct atbmwifi_common *hw_priv=&g_hw_prv;
	bool ret;
	atbm_uint8 reg = 0;
	wifi_printk(WIFI_SDIO,"atbm_sdio_claim_irq  %d\n",func->func);

	ATBM_SET_IRQ(func,irq_handle);
	ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_IENx, 0, &reg);
	if(ret == false){
		wifi_printk(WIFI_SDIO,"read ATBM_SDIO_CCCR_IENx err\n");
		goto __fail;
	}
	/* Master interrupt enable ... */
	reg |= BIT(0);
	/* ... for our function */
	reg |= BIT(func->func);
	
	wifi_printk(WIFI_SDIO,"write ATBM_SDIO_CCCR_IENx %x\n",reg);
	ret = mmc_io_rw_direct(1, 0, ATBM_SDIO_CCCR_IENx, reg, NULL);
	if(ret == false){
		wifi_printk(WIFI_SDIO,"write ATBM_SDIO_CCCR_IENx err\n");
		goto __fail;
	}
	ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_IENx, 0, &reg);
	
	wifi_printk(WIFI_SDIO,"atbm_sdio_claim_irq  %x\n",reg);
	ret = atbm_get_sdio_which_mci();
	if(ret != 0)
	{
		wifi_printk(WIFI_ERROR,"sdio get irq vector fail\n");
	}
	/*Init sdio Interrupt,after the sdio Initial*/
	//interrupt_init();
	ret = atbm_sdio_data1_irq();
	if(ret != 0)
	{
		wifi_printk(WIFI_SDIO,"sdio register irq err1\n");
	}
	return 0;
__fail:	
	return -1;
}
int atbm_sdio_release_irq(struct atbm_sdio_func *func)
{
	int ret;
	unsigned char reg;
	ret = mmc_io_rw_direct(0, 0, ATBM_SDIO_CCCR_IENx, 0, &reg);
	if (ret)
		return ret;

	reg &= ~(1 << func->func);

	/* Disable master interrupt with the last function interrupt */
	if (!(reg & 0xFE))
		reg = 0;

	ret = mmc_io_rw_direct(1, 0, ATBM_SDIO_CCCR_IENx, reg, NULL);
	if (ret)
		return ret;
	
	ATBM_SET_IRQ(ATBM_NULL,ATBM_NULL);
	
	sdio_enable_irq(g_get_sdio_which_mci , 0);
	return 0;
}
#endif

int __atbm_sdio_memcpy_fromio(struct atbm_sdio_func *func,void *dst,unsigned int addr,int count)
{
	bool ret;
	if(func->en == 0){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"%s:%d func not en \n",__func__,func->func);
		return -1;
	}
	if((((unsigned int)dst) &3)||(count &3)){
		wifi_printk(WIFI_ALWAYS,"Read Data & Len must be 4 align,dst=0x%08x,count=%d",(unsigned int )dst,count);
	}
#if (PLATFORM==AK_RTOS_37D)
	atbm_local_irq_save();
#endif
	ret=sdio_read_multi(func->func,addr,count,1,(unsigned char*)dst);
#if (PLATFORM==AK_RTOS_37D)
	atbm_local_irq_restore(0);
#endif
	if(ret==false){
		wifi_printk(WIFI_ALWAYS," __atbm_sdio_memcpy_fromio ret =%d\n",ret);
	}

	return 0;
}

int __atbm_sdio_memcpy_toio(struct atbm_sdio_func *func,unsigned int addr,void *dst,int count)
{
	bool ret;
	if(func->en == 0){
		wifi_printk(AK_SIDO_DEBUG_LEVEL,"%s:%d func not en \n",__func__,func->func);
		return -1;
	}
	if((((unsigned int)dst) &3)||(count &3)){
		wifi_printk(WIFI_ALWAYS,"Write Data & Len must be 4 align,dst=0x%08x,count=%d",(unsigned int )dst,count);
	}


	ret=sdio_write_multi(func->func,addr,count,1,(unsigned char*)dst);
	
	if(ret==false){
		wifi_printk(WIFI_ALWAYS," __atbm_sdio_memcpy_toio ret =%d\n",ret);
	}

	return 0;
}

unsigned char atbm_sdio_f0_readb(struct atbm_sdio_func *func,unsigned int addr,int *retval)
{
	unsigned char date = 0;
	bool ret;
	
	ret = sdio_read_byte(0,addr,&date);
	*retval = 0;
	if(ret == false)
		*retval = -1;
_return:
	return date;
}

void atbm_sdio_f0_writeb(struct atbm_sdio_func *func,unsigned char regdata,unsigned int addr,int *retval)
{
	bool ret;

	ret = sdio_write_byte(0,addr,regdata);
	
	*retval = 0;
	
	if(ret == false)
		*retval = -1;
_return:
	return;
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

int __atbm_sdio_set_blocksize(struct atbm_sdio_func *func,int blksz)
{
	wifi_printk(WIFI_SDIO,"atbm_sdio_set_blocksize func->func =%d :%d\n",func->func,blksz);
	int ret = 0;
	ret = mmc_io_rw_direct(1, 0,
		SDIO_FBR_BASE(func->func) + ATBM_SDIO_FBR_BLKSIZE,
		blksz & 0xff, NULL);
	if (ret)
		goto end;
	ret = mmc_io_rw_direct(1, 0,
		SDIO_FBR_BASE(func->func) + ATBM_SDIO_FBR_BLKSIZE + 1,
		(blksz >> 8) & 0xff, NULL);

	if (ret)
		goto end;
end:
	return ret;
}
int  atbm_sdio_set_blocksize(struct atbm_sdio_func *func,int blocksize)
{
	int ret;
	ret=sdio_set_block_len(func->func,blocksize);
	SDIO_FUNC_SET_BLKSIZE(func,blocksize);
	wifi_printk(AK_SIDO_DEBUG_LEVEL,"atbm_sdio_set_blocksize(%d)(%d) ret =%d\n",blocksize,func->blocksize,ret);
	return 0;
}

