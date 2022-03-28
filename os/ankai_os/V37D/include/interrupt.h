/**
 * @file interrupt.h
 * @brief: This file describe how to control the AK3223M interrupt issues.
 * 
 * Copyright (C) 2006 Anyka (GuangZhou) Software Technology Co., Ltd.
 * @author Miaobaoli
 * @date 2005-07-13
 * @version 1.0
 */
#ifndef __INTERRUPT_H__
#define __INTERRUPT_H__


/** @defgroup Interrupt  
 *  @ingroup M3PLATFORM
 */
/*@{*/

/** @{@name Interrupt Operator Define
 *  Define the macros to operate interrupt register, to enable/disable interrupt
 */
 /**IRQ mode*/
#define INTR_ENABLE(int_bits)   \
    do{ \
        irq_mask(); \
        *(volatile unsigned long *)IRQINT_MASK_REG |= (int_bits); \
        irq_unmask(); \
    }while(0)
#define INTR_DISABLE(int_bits) \
    do{ \
        irq_mask(); \
        *(volatile unsigned long *)IRQINT_MASK_REG &= ~(int_bits); \
        irq_unmask(); \
    }while(0)

 /**IRQ Level2 mode*/
#define INTR_ENABLE_L2(int_bits) \
    do{ \
        irq_mask(); \
        *(volatile unsigned long *)INT_SYS_MODULE_REG |= (int_bits); \
        irq_unmask(); \
    }while(0)


#define INTR_DISABLE_L2(int_bits) \
    do{ \
        irq_mask(); \
        *(volatile unsigned long *)INT_SYS_MODULE_REG &= ~(int_bits); \
        irq_unmask(); \
    }while(0)


/** FIQ mode*/
#define FIQ_INTR_ENABLE(int_bits)   \
    do{ \
        irq_mask(); \
        *(volatile unsigned long *)FRQINT_MASK_REG |= (int_bits); \
        irq_unmask(); \
    }while(0)

#define FIQ_INTR_DISABLE(int_bits)  \
    do{ \
        irq_mask(); \
        *(volatile unsigned long *)FRQINT_MASK_REG &= ~(int_bits); \
        irq_unmask(); \
    }while(0)

typedef bool (*T_INTR_HANDLER)(void);
    
    typedef enum {
        INT_VECTOR_MIN = 100,
    
        INT_VECTOR_MEM,
        INT_VECTOR_ISP,
        INT_VECTOR_VENC,
        //INT_VECTOR_SYS_CTRL,
        INT_VECTOR_MMC0,
        INT_VECTOR_MMC1,
        INT_VECTOR_ADC,
        INT_VECTOR_DAC,
        INT_VECTOR_SPI0,
        INT_VECTOR_SPI1,
    
        INT_VECTOR_UART0,
        INT_VECTOR_UART1,
        INT_VECTOR_L2,
        INT_VECTOR_TWI0,
        INT_VECTOR_IRDA,
        INT_VECTOR_GPIO,
        INT_VECTOR_MAC,
        INT_VECTOR_ENCRYPT,
        INT_VECTOR_USB,
        INT_VECTOR_USB_DMA,
    
        INT_VECTOR_TWI1,
        INT_VECTOR_UART2,
        INT_VECTOR_UART3,
        INT_VECTOR_VDEC,
        INT_VECTOR_GUI,
        INT_VECTOR_LCD,
        INT_VECTOR_RSVD0,
        INT_VECTOR_MMC2,
        INT_VECTOR_SD_PLUG_INOFF,
        INT_VECTOR_TWI2,
    
        INT_VECTOR_TWI3,
        INT_VECTOR_RSVD1,
    
        /*TOP_INT_VECTOR_SYSTEM*/
        INT_VECTOR_SAR_ADC,
        INT_VECTOR_TIMER4,
        INT_VECTOR_TIMER3,
        INT_VECTOR_TIMER2,
        INT_VECTOR_TIMER1,
        INT_VECTOR_TIMER0,
        INT_VECTOR_WAKEUP_TRIGGER,
        INT_VECTOR_RTC_RDY,
        INT_VECTOR_RTC_ALARM,
        INT_VECTOR_RTC_TIMER,
    
        INT_VECTOR_RTC_WDT,
        INT_VECTOR_GPI0_AO,
        INT_VECTOR_GPI1_AO,
        INT_VECTOR_GPI2_AO,
        INT_VECTOR_GPI3_AO,
        INT_VECTOR_GPI4_AO,
        INT_VECTOR_BVD_LP,
        INT_VECTOR_PMU_RDY,
        INT_VECTOR_TIMER6,
        INT_VECTOR_TIMER5,
    
        INT_VECTOR_MAX
    } INT_VECTOR;
    
    typedef enum e_int_en_cfg {
        INT_EN_CFG_MEM = 0,
        INT_EN_CFG_ISP,
        INT_EN_CFG_VENC,
        INT_EN_CFG_SYS_CTRL,
        INT_EN_CFG_MMC0,
        INT_EN_CFG_MMC1,
        INT_EN_CFG_ADC,
        INT_EN_CFG_DAC,
        INT_EN_CFG_SPI0,
        INT_EN_CFG_SPI1,
    
        INT_EN_CFG_UART0,
        INT_EN_CFG_UART1,
        INT_EN_CFG_L2,
        INT_EN_CFG_TWI0,
        INT_EN_CFG_IRDA,
        INT_EN_CFG_GPIO,
        INT_EN_CFG_MAC,
        INT_EN_CFG_ENCRYPT,
        INT_EN_CFG_USB,
        INT_EN_CFG_USB_DMA,
    
        INT_EN_CFG_TWI1,
        INT_EN_CFG_UART2,
        INT_EN_CFG_UART3,
        INT_EN_CFG_VDEC,
        INT_EN_CFG_GUI,
        INT_EN_CFG_LCD,
        INT_EN_CFG_RSVD0, //reserved
        INT_EN_CFG_MMC2,
        INT_EN_CFG_SD_INOFF,
        INT_EN_CFG_TWI2,
        
        INT_EN_CFG_TWI3,
        INT_EN_CFG_RSVD1, //reserved
    } E_INT_EN_CFG; 
    
    typedef enum e_top_int_en_cfg {
        TOP_INT_EN_CFG_SAR_ADC = 32,
        TOP_INT_EN_CFG_TIMER4,
        TOP_INT_EN_CFG_TIMER3,
        TOP_INT_EN_CFG_TIMER2,
        TOP_INT_EN_CFG_TIMER1,
        TOP_INT_EN_CFG_TIMER0,
        TOP_INT_EN_CFG_WAKEUP_TRIG,
        TOP_INT_EN_CFG_RTC_RDY,
        TOP_INT_EN_CFG_RTC_ALARM,
        TOP_INT_EN_CFG_RTC_TIMER,
    
        TOP_INT_EN_CFG_RTC_WDT,
        TOP_INT_EN_CFG_GPI0_AO,
        TOP_INT_EN_CFG_GPI1_AO,
        TOP_INT_EN_CFG_GPI2_AO,
        TOP_INT_EN_CFG_GPI3_AO,
        TOP_INT_EN_CFG_GPI4_AO,
        TOP_INT_EN_CFG_BVD_LP,
        TOP_INT_EN_CFG_PMU_RDY,
        TOP_INT_EN_CFG_TIMER6,
        TOP_INT_EN_CFG_TIMER5,
    
        TOP_INT_EN_CFG_RSVD0,
        TOP_INT_EN_CFG_RSVD1,
        TOP_INT_EN_CFG_RSVD2,
        TOP_INT_EN_CFG_RSVD3,
        TOP_INT_EN_CFG_RSVD4,
        TOP_INT_EN_CFG_RSVD5,
        TOP_INT_EN_CFG_RSVD6,
        TOP_INT_EN_CFG_RSVD7,
        TOP_INT_EN_CFG_RSVD8,
        TOP_INT_EN_CFG_RSVD9,
    
        TOP_INT_EN_CFG_RSVD10,
        TOP_INT_EN_CFG_RSVD11,
    } E_TOP_INT_EN_CFG;

/**
 * @brief: interrupt init, called before int_register_irq()
 */
void interrupt_init(void);

/**
 * @brief: register irq interrupt
 */
bool int_register_irq(INT_VECTOR v, T_INTR_HANDLER handler);

#endif

