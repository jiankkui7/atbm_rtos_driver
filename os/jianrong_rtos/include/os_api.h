//#include "print.h"
//#include "drv_api.h"
#if (PLATFORM==JIANRONG_RTOS_3268)
#include "usr_cfg.h"
#endif
#include "string.h"


#define __INLINE inline
#define iot_printf printk
#define  atbm_random()   rand()

#define  rcu_read_lock()
#define  rcu_read_unlock()
#define  TargetUsb_lmac_start()

atbm_uint32 atbm_os_random();
#define ZEROSIZE 0
//#ifndef PACK_STRUCT_BEGIN
//#define PACK_STRUCT_BEGIN
//#endif /* PACK_STRUCT_BEGIN */
  
//#ifndef PACK_STRUCT_END
//#define PACK_STRUCT_END
//#endif /* PACK_STRUCT_END */

