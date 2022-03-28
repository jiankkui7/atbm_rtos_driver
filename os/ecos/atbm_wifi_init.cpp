/**************************************************************************************************************
 * altobeam RTOS wifi hmac source code 
 *
 * Copyright (c) 2018, altobeam.inc   All rights reserved.
 *
 *  The source code contains proprietary information of AltoBeam, and shall not be distributed, 
 *  copied, reproduced, or disclosed in whole or in part without prior written permission of AltoBeam.
*****************************************************************************************************************/

#if 0
#include <gxos/gxcore_os_bsp.h>
#else
extern "C" void usbwifi_init(void);
extern "C" int usb_wifi_init(void);
extern int (*proc_usb_wifi_init)(void); 
class cyg_gxwifidev_init_class{
public:
	cyg_gxwifidev_init_class(void){
		usbwifi_init();
		proc_usb_wifi_init = usb_wifi_init;
	}

};

//class cyg_gxwifidev_init_class testatbm;
#endif
