#include "atbm_os_mailbox.h"
int atbm_createMailBox(atbm_void *data){
    RT_DEBUG_NOT_IN_INTERRUPT;
    rt_mb_init(&MailBox, "atbmail", &g_usb_pool[0], sizeof(g_usb_pool)/4, RT_IPC_FLAG_FIFO);
	atbm_maibox_bh=atbm_createThread(atbm_release_tx_buffer,data,MAIL_BOX_BH_PRIO);
	return 0;
}
atbm_urb_s *atbm_mailBox_recv(rt_int32_t timeout){
    RT_DEBUG_NOT_IN_INTERRUPT;
    atbm_urb_s *urb = ATBM_NULL;
	if(rt_mb_recv(&MailBox, (rt_int32_t *)&urb,timeout) == RT_EOK) {	
		return urb;
	}else{
		return ATBM_NULL;
	}
}
int atbm_mailBox_send(atbm_urb_s *urb){
	
   // RT_DEBUG_NOT_IN_INTERRUPT;
	if(rt_mb_send(&MailBox, (rt_int32_t)urb)==RT_EOK){
		return 0;
	}
	return -1;
}
atbm_mailBox_delete(){

	RT_DEBUG_NOT_IN_INTERRUPT;

	rt_mb_delete(&MailBox);

	return;

}

