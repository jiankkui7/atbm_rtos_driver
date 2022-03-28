

#include "atbm_hal.h"

extern struct atbmwifi_common g_hw_prv;
atbm_uint8 *TargetUsb_RecvUrbGet(atbm_void *pTargetHifHandle, int * BytesRead);
int TargetUsb_RecvUrbEmpty(atbm_void *pTargetHifHandle);
int TargetUsb_RecvUrbPut(HI_CONN_INFO_USB_USB *pTargetUsb, atbm_void * urb, atbm_uint8 len);
int TargetUsb_RecvMsgEmpty(atbm_void *pTargetHifHandle);
int TargetUsb_SendUrbMsg(atbm_void *pTargetHifHandle, struct usb_wsm_hdr_tx *pMsg,int len);

int atbm_usb_reg_write(HI_CONN_INFO_USB_USB *pTargetUsb, atbm_uint32 addr, atbm_void *buf, atbm_uint32 buf_len);
atbm_uint8 *  TargetUsb_RecvMsgGet(atbm_void *pTargetHifHandle, int * BytesRead);
int atbm_usb_reg_read(HI_CONN_INFO_USB_USB *pTargetUsb, atbm_uint32 addr, atbm_void *buf, atbm_uint32 buf_len);
HI_CONN_INFO_USB_USB *  TargetUsb_Init(atbm_void *pTargetHifHandle, int chip_version, int usbport, TARGET_CB_ADAP_RECV Receiver);
atbm_void  TargetUsb_lmac_start();


 struct atbm_usb_interface Usb_intf;
 HI_CONN_INFO_USB_USB *  Usb_Dev;
 int  TargetHandle=0;
 CRITICAL_SECTION	 UsbUrbCallBack_lock;
 pAtbm_thread_t hif_usb_work = 0;
 atbm_os_wait_queue_head_t hif_usb_work_wq;	 
 CRITICAL_SECTION	 TestEvent_lock;
int atbm_usb_hif_bh_wakeup = 0;



 atbm_void atbm_usb_hif_bh(atbm_void *arg)
 {
	 struct atbmwifi_common *hw_priv = arg;

	do{	
		atbm_os_wait_event_timeout(&hif_usb_work_wq,50);	 	

		 if (hw_priv->bh_error){
			 wifi_printk(WIFI_DBG_ERROR,"%s  break %d\n",__FUNCTION__,hw_priv->bh_error);
			 break;
		 }
		 atbm_usb_rx_callback();
		 atbm_usb_hif_bh_wakeup=0;
		 
	}while(1);
	
	return 1;
 }
 #ifdef ATBM_USB_RX_ISR
 int atbm_usb_hif_wake_up_task_isr(atbm_void)
 {
 	if(hif_usb_work_wq != ATBM_NULL)
		atbm_os_wakeup_event_isr(&hif_usb_work_wq);
 }
 #endif
 int atbm_usb_hif_idle_task(){
 	#ifndef ATBM_USB_RX_ISR
 	if(atbm_usb_hif_bh_wakeup==1) {
		atbm_os_wakeup_event(&hif_usb_work_wq);
		atbm_usb_hif_bh_wakeup = 2;
		//return 1;
 	}
	#endif
	return 0;
 }

 atbm_void hif_usb_work_init(){
 	
	 struct atbmwifi_common *hw_priv = &g_hw_prv;
	 
	 if(hif_usb_work ==0){
		 atbm_os_init_waitevent(&hif_usb_work_wq);
		 
		 hif_usb_work=atbm_createThread(atbm_usb_hif_bh,(atbm_void*)hw_priv,BH_TASK_PRIO);
		  if (!hif_usb_work){
			  wifi_printk(WIFI_DBG_ERROR,"hif_usb_work_init Failed\n");
			  return -1;
		  }
	 }
 }


 int usb_control_msg( struct atbm_usb_device *dev, unsigned int pipe, atbm_uint8 request, atbm_uint8 requesttype, atbm_uint16 value,
	 atbm_uint16 index, atbm_void *data, atbm_uint16 size, int timeout)
 {
	int ret;
	atbm_uint32 addr = value|(index<<16);
	
	hif_usb_work_init();

	if(requesttype == ATBM_USB_VENQT_WRITE){
		ret= atbm_usb_reg_write(dev,addr,data,size);
	}
	else {
		ret= atbm_usb_reg_read(dev,addr,data,size);
	}
 
	if(ret>=0)
		ret = size;
	
	 return ret;
 }


atbm_void usb_kill_urb( atbm_urb_s *urb)
{
}
atbm_void usb_free_urb( atbm_urb_s *urb)
{
	if(urb)
		atbm_kfree(urb);

}


struct atbm_urb * usb_alloc_urb(int id)
{
	return (struct atbm_urb *)atbm_kmalloc(sizeof(struct atbm_urb),GFP_KERNEL);
}



atbm_void atbm_usb_fill_bulk_urb(struct atbm_urb *urb, struct atbm_usb_device *dev, unsigned int
    pipe, atbm_void *transfer_buffer, int buffer_length, atbm_void *complete_fn, atbm_void
    *context)
{
    urb->dev = dev;
    urb->pipe = pipe;
    urb->transfer_buffer = transfer_buffer;
    urb->transfer_buffer_length = buffer_length;
    urb->complete = complete_fn;
    urb->context = context;
 }


typedef atbm_void (*call_usb_complete)(struct atbm_urb *atbm_urb);
atbm_void atbm_usb_tx_callback( struct atbm_urb *urb)
{	urb->status =0;
	((call_usb_complete )urb->complete)(urb);
}

atbm_void atbm_usb_rx_callback_work()
{
	#ifndef ATBM_USB_RX_ISR
	if(atbm_usb_hif_bh_wakeup==0){
		atbm_usb_hif_bh_wakeup=1;
	}
	#else
	atbm_os_wakeup_event(&hif_usb_work_wq);
	#endif
}
atbm_void atbm_usb_rx_callback()
{
    struct atbm_urb **purb;
    struct atbm_urb *urb;
	int BytesRead;
	atbm_uint8 * pMsg;
	EnterCriticalSection(&UsbUrbCallBack_lock);
	while(1){
		if(TargetUsb_RecvUrbEmpty(Usb_Dev) || TargetUsb_RecvMsgEmpty(Usb_Dev) ){
//			LeaveCriticalSection(&UsbUrbCallBack_lock);
			break;
		}
		
		purb = TargetUsb_RecvUrbGet(Usb_Dev,&BytesRead);
		urb = *purb;
		free(purb);
		pMsg = TargetUsb_RecvMsgGet(Usb_Dev,&BytesRead);

		if(pMsg ==0){
			wifi_printk(WIFI_ALWAYS,"atbm_usb_rx_callback: rx msg is ATBM_NULL\n");
			urb->status =-1;
		}
		else {
		//	iot_printf("atbm_usb_rx_callback %x %d\n",pMsg,BytesRead);
			urb->status =0;
			memcpy( urb->transfer_buffer,pMsg,BytesRead);
			urb->actual_length = BytesRead;
			free(pMsg);
		}
		((call_usb_complete )urb->complete)(urb);
	}
	LeaveCriticalSection(&UsbUrbCallBack_lock);
}
int usb_submit_urb(struct atbm_urb *urb)
{
	int status =0;
	
	if(urb->pipe == ATBM_USB_VENQT_WRITE){
		TargetUsb_SendUrbMsg(Usb_Dev,urb->transfer_buffer, urb->transfer_buffer_length);
		atbm_usb_tx_callback(urb);
	}
	else {

		TargetUsb_RecvUrbPut(Usb_Dev,&urb, sizeof(struct atbm_urb **));
		atbm_usb_rx_callback();
	}

	return status;
}



int atbm_usb_register( struct atbm_usb_driver *driver)
{

	Usb_intf.udev = Usb_Dev;
	driver->probe_func(&Usb_intf,ATBM_NULL);
}

atbm_void usb_main()
{
	InitializeCriticalSection(&UsbUrbCallBack_lock);
	while (1){
		Usb_Dev= TargetUsb_Init(&TargetHandle,0,0,ATBM_NULL);
		if(Usb_Dev)
			break;
		atbm_SleepMs(1000);
	}
	TargetUsb_GetChipVersion(0);

	atbm_usb_module_init();
}

