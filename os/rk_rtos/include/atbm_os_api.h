/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/


#ifndef ATBM_OS_API_H
#define ATBM_OS_API_H

#include <drvUSBHost.h>
#include <drvAPIWrapper.h>
//#include <drvErrno.h>
#include "atbm_type.h"
#include "atbm_os_sdio.h"
#include "atbm_os_usb.h"
#define HZ  1000
#define ZEROSIZE 0
#define __INLINE inline

#ifndef atbm_packed
#define atbm_packed __attribute__ ((packed))
#endif //__packed
int atbmwifi_event_OsCallback(atbm_void *prv,int eventid,atbm_void *param);
int atbm_usb_register_init();
int atbm_usb_register_deinit();
#endif //ATBM_OS_API_H
