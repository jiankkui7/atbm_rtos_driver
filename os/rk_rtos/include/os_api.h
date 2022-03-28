#include "sys_MsWrapper_cus_os_util.h"
#include "sys_MsWrapper_cus_os_type.h"
#include "sys_MsWrapper_cus_os_mem.h"

#include <ahc_os.h>
#include <drvUSBHost.h>
#include <drvAPIWrapper.h>

#define __INLINE inline
#define iot_printf printc
#define  atbm_random   sys_Random32

#define  rcu_read_lock()
#define  rcu_read_unlock()
#define  TargetUsb_lmac_start()

atbm_uint32 atbm_os_random();

#ifndef PACK_STRUCT_BEGIN
#define PACK_STRUCT_BEGIN
#endif /* PACK_STRUCT_BEGIN */
  
#ifndef PACK_STRUCT_END
#define PACK_STRUCT_END
#endif /* PACK_STRUCT_END */

