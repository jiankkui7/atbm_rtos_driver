#include "atbm_hal.h"
#include "akos_api.h"
#include "atbm_os_msgQ.h"


#define ATBM_URB_TX_MSGQ_NUM 8
static atbm_os_msgq atbm_urb_tx_msgQ;
static atbm_urb_s atbm_urb_tx_msqQbuf[ATBM_URB_TX_MSGQ_NUM+1];

#define ATBM_URB_RX_MSGQ_NUM 8
static atbm_os_msgq atbm_urb_rx_msgQ ;
static atbm_urb_s atbm_urb_rx_msqQbuf[ATBM_URB_RX_MSGQ_NUM+1];

pAtbm_thread_t atbm_urb_tx_thread;
pAtbm_thread_t atbm_urb_rx_thread;

#define ATBM_URB_TX_THREAD_PRIORITY		14
#define ATBM_URB_RX_THREAD_PRIORITY		14
#define ATBM_URB_TX_THREAD_STACKSIZE		4096
#define ATBM_URB_RX_THREAD_STACKSIZE		4096


static atbm_int32 atbm_urb_msgQ_init_state = 0;

//extern bool usb_bus_reg_class(T_pUSB_BUS_HANDLER bus_handler);

int usb_host_device_open(){
	rt_device_t uhc;
	if((uhc = rt_device_find("uhc")) != ATBM_NULL){
		if(rt_device_open(uhc, RT_DEVICE_OFLAG_RDWR) == RT_EOK){
			wifi_printk(WIFI_ALWAYS, "uhc  found open \n");
			rt_device_close(uhc);
		}
	}
	return 0;
}

int  atbm_usb_register (ucd_t drv)
{
	return rt_usbh_class_driver_register(drv);
}

int atbm_usb_deregister(ucd_t drv)	
{
	return rt_usbh_class_driver_unregister(drv);
}

atbm_uint32 atbm_usb_rcvbulkpipe(struct atbm_usb_device *udev, atbm_int32 pipe)
{
	pipe = pipe; /*No used*/
	return (atbm_uint32)udev->pipe_in;
}

atbm_uint32 atbm_usb_sndbulkpipe(struct atbm_usb_device *udev, atbm_int32 pipe)
{
	pipe = pipe; /*No used*/
	return (atbm_uint32)udev->pipe_out;
}

atbm_uint32 atbm_usb_sndctrlpipe(struct atbm_usb_device *udev, atbm_uint32 pipe)
{
	udev = udev; /*No used*/
	pipe = pipe; /*No used*/
	return (atbm_uint32)ATBM_DRV_CONTROL_PIPE;
}
atbm_uint32 atbm_usb_rcvctrlpipe(struct atbm_usb_device *udev, atbm_uint32 pipe)
{
	udev = udev; /*No used*/
	pipe = pipe; /*No used*/
	return (atbm_uint32)ATBM_DRV_CONTROL_PIPE;
}
atbm_int32 atbm_usb_control_msg(struct atbm_usb_device *udev, unsigned int pipe, unsigned char request, unsigned char requestType,
					unsigned short value, unsigned short index, unsigned char *reqdata, unsigned short len, unsigned short timeout)
{
	T_UsbDevReq dev_req;
	unsigned long ReadLen=0;
	dev_req.request_type = requestType;
	dev_req.bRequest =request;
	dev_req.wValue = value;
	dev_req.wIndex = index;
	dev_req.wLength = len;


	if(rt_usb_hcd_setup_xfer(udev->ins->hcd, udev->ins->pipe_ep0_out, &dev_req, timeout) != 8){
		wifi_printk(WIFI_ALWAYS, "set up err\n");
		return -1;
	}

	if(len == 0){
		rt_usb_hcd_pipe_xfer(udev->ins->hcd, udev->ins->pipe_ep0_in, ATBM_NULL, 0, timeout);
		return 0;
	}

	if(requestType == ATBM_USB_VENQT_READ){
		if((ReadLen = rt_usb_hcd_pipe_xfer(udev->ins->hcd, udev->ins->pipe_ep0_in, reqdata, len, timeout)) <= 0 ){
			wifi_printk(WIFI_ALWAYS, "data in err\n");
			return -1;
		}
		rt_usb_hcd_pipe_xfer(udev->ins->hcd, udev->ins->pipe_ep0_out, ATBM_NULL, 0, timeout);
	}else{
		if((ReadLen = rt_usb_hcd_pipe_xfer(udev->ins->hcd, udev->ins->pipe_ep0_out, reqdata, len, timeout)) <= 0 ){
			wifi_printk(WIFI_ALWAYS, "data out err\n");
			return -1;
		}
		rt_usb_hcd_pipe_xfer(udev->ins->hcd, udev->ins->pipe_ep0_in, ATBM_NULL, 0, timeout);
	}
	if (ReadLen<0) {
		return -1;
	}
	return ReadLen;
}

atbm_void  atbm_usb_fill_bulk_urb(atbm_urb_s *purb,
                     struct atbm_usb_device *dev,
                     unsigned int pipe,
                     void *transfer_buffer,
                     int buffer_length,
                     usb_complete_t complete_fn,
                     void *context)
{
	purb->pipe =pipe;
	purb->data = transfer_buffer;
	purb->data_len = buffer_length;
	purb->timeout = 0xffffffff;
	purb->actual_length=buffer_length;
	purb->complete_fn=complete_fn;
	purb->context = (atbm_void *)context;
	purb->udev = dev;
}

atbm_int32 atbm_usb_submit_urb(atbm_urb_s *purb, int param)
{
	atbm_int32 ret = 0;
	atbm_uint32 status;
	atbm_uint32 pdata;

	param = param; /*No used*/
	pdata = (atbm_uint32)purb;

	if(purb->pipe == (atbm_uint32)purb->udev->pipe_in){
		//wifi_printk(WIFI_ALWAYS, "Send in pipe pdata 0x%x\n", pdata);
		status = atbm_os_MsgQ_Send(&atbm_urb_rx_msgQ, &pdata,sizeof(atbm_uint32*));
		if (0 != status){
			wifi_printk(WIFI_ALWAYS, "atbm_urb_rx_msgQ send failed 0x%x\n", status);
			ret = -1;
		}
	}else{
		//wifi_printk(WIFI_ALWAYS, "Send Out pipe pdata 0x%x\n", pdata);
		status = atbm_os_MsgQ_Send(&atbm_urb_tx_msgQ, &pdata,sizeof(atbm_uint32*));
		if (0 != status){
			wifi_printk(WIFI_ALWAYS, "atbm_urb_tx_msgQ send failed 0x%x\n", status);
			ret = -1;
		}
	}
	
	return ret;
}

atbm_urb_s *atbm_usb_alloc_urb(atbm_int32 iso_packets, atbm_int32 mem_flags)
{
	atbm_urb_s *purb;

	iso_packets = iso_packets;/*No used*/
	mem_flags = mem_flags;    /*No used*/
	
	purb = (atbm_urb_s*) atbm_kzalloc(sizeof(atbm_urb_s),GFP_KERNEL);
	if (purb == ATBM_NULL) {
		wifi_printk(WIFI_ALWAYS ,"atbm_usb_alloc_urb fail \n");
		return ATBM_NULL;
	}

	return purb;	
}

atbm_void atbm_usb_free_urb(atbm_urb_s *purb)
{
	if(purb == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS ,"atbm_usb_free_urb fail \n");
		return;
	}

	atbm_kfree(purb);
	
	return;
}

atbm_void atbm_usb_kill_urb(atbm_urb_s *purb)
{
	if(purb == ATBM_NULL){
		wifi_printk(WIFI_ALWAYS ,"atbm_usb_kill_urb fail \n");
		return;
	}

	atbm_kfree(purb);
	
	return;
}
//#define atbm_usb_device_id      usb_device_id
struct atbm_usb_device *atbm_usb_get_dev(struct atbm_usb_device *udev)
{
	return udev;
}
struct atbm_usb_interface *atbm_usb_get_intf(struct atbm_usb_interface *intf)
{
	return intf;
}
struct atbm_usb_device *atbm_interface_to_usbdev(struct atbm_usb_interface *intf)
{
	return intf->device;
}

atbm_void atbm_usb_set_intfdata(struct atbm_usb_interface *usb_intf, struct dvobj_priv *pdvobjpriv)
{
	usb_intf->pdvobjpriv = pdvobjpriv;
	return;
}

struct dvobj_priv *atbm_usb_get_intfdata(struct atbm_usb_interface *intf)
{
	return intf->pdvobjpriv;
}
//#define atbm_usb_endpoint_is_bulk_in(a) usb_endpoint_is_bulk_in(a)
//#define atbm_usb_endpoint_num(a) usb_endpoint_num(a)
//#define atbm_usb_endpoint_is_bulk_out(a) usb_endpoint_is_bulk_out(a)
atbm_void atbm_usb_put_dev(struct atbm_usb_device *udev)
{
	udev = udev; /*No used*/
	return;

}

atbm_void atbm_urb_tx_queue_task(void *unused)
{
	atbm_uint32 status;
	atbm_urb_s *purb;
	atbm_uint32 actual_size;
	atbm_uint32 pdata;

	while(1){
		status=atbm_os_MsgQ_Recv(&atbm_urb_tx_msgQ,&pdata,sizeof(atbm_uint32*));
		if(status != 0){
			wifi_printk(WIFI_ALWAYS, "atbm_urb_tx_msgQ recv failed 0x%x\n", status);
			continue;
		}

		//wifi_printk(WIFI_ALWAYS, "Receive out pipe pdata 0x%x\n", pdata);
		purb = (atbm_urb_s *)pdata;
		if(purb->pipe != (atbm_uint32)purb->udev->pipe_out){
			wifi_printk(WIFI_ALWAYS, "urb commit err!!\n");
			continue;
		}

		actual_size = rt_usb_hcd_pipe_xfer(purb->udev->ins->hcd, (upipe_t)purb->pipe, purb->data, purb->data_len, purb->timeout);
		if(actual_size != purb->data_len){
			wifi_printk(WIFI_ALWAYS, "urb commit err %d-%d!!\n", purb->data_len, actual_size);
			continue;
		}

		/*Tx Urb complete*/
		purb->complete_fn(purb);
	}
}

atbm_void atbm_urb_rx_queue_task(void *unused)
{
	atbm_uint32 status,actual_size;
	atbm_urb_s *purb;
	atbm_uint32 pdata;

	//wifi_printk(WIFI_ALWAYS, "%s, running...\n", __func__);
	
	while(1){
		status=atbm_os_MsgQ_Recv(&atbm_urb_rx_msgQ,&pdata,sizeof(atbm_uint32*));
		if(status != 0){
			wifi_printk(WIFI_ALWAYS, "atbm_urb_rx_msgQ recv failed 0x%x\n", status);
		}

		//wifi_printk(WIFI_ALWAYS, "Receive out pipe pdata 0x%x\n", pdata);
		purb = (atbm_urb_s *)pdata;
		if(purb->pipe != (atbm_uint32)purb->udev->pipe_in){
			wifi_printk(WIFI_ALWAYS, "urb commit err!!\n");
			continue;
		}

		actual_size = rt_usb_hcd_pipe_xfer(purb->udev->ins->hcd, (upipe_t)purb->pipe, purb->data, purb->data_len, purb->timeout);
		if(actual_size <= 0){
			wifi_printk(WIFI_ALWAYS, "urb commit err %d-%d!!\n", purb->data_len, actual_size);
			continue;
		}
		purb->actual_length = actual_size;

		/*Tx Urb complete*/
		purb->complete_fn(purb);
	}
}

atbm_void atbm_urb_queue_init(atbm_void)
{
	atbm_uint32 status;

	wifi_printk(WIFI_ALWAYS, "atbm_urb_queue_init ==>\n");
	
	if(atbm_urb_msgQ_init_state == 1){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_queue_init error!!!\n");
		return;
	}
	// Init TX MessageQ
	
	status=atbm_os_MsgQ_Create(&atbm_urb_tx_msgQ,(atbm_uint32 *)&atbm_urb_tx_msqQbuf[0],ATBM_URB_TX_MSGQ_NUM*sizeof(atbm_uint32));
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_tx_msgQ create failed 0x%x\n", status);
		return;
	}

	// Init RX MessageQ
	status = atbm_os_MsgQ_Create(&atbm_urb_rx_msgQ,(atbm_uint32 *)&atbm_urb_rx_msqQbuf,ATBM_URB_RX_MSGQ_NUM*sizeof(atbm_uint32*));
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_rx_msgQ create failed 0x%x\n", status);
		return;
	}
	//Init TX Task
	atbm_urb_tx_thread=atbm_createThread(atbm_urb_tx_queue_task,ATBM_NULL,TXURB_TASK_PRIO);
	if (!atbm_urb_tx_thread){
		wifi_printk(WIFI_DBG_ERROR,"bh_thread Failed\n");
		return;
	}

	//Init RX Task
	atbm_urb_rx_thread=atbm_createThread(atbm_urb_rx_queue_task,ATBM_NULL,RXURB_TASK_PRIO);
	if (!atbm_urb_rx_thread){
		wifi_printk(WIFI_DBG_ERROR,"bh_thread Failed\n");
		return;
	}

	//Urb Init Ready
	atbm_urb_msgQ_init_state = 1;
	
	wifi_printk(WIFI_ALWAYS, "atbm_urb_queue_init <==\n");
	return ;
}
atbm_void atbm_urb_queue_exit(atbm_void)
{
	atbm_uint32 status;
	
	wifi_printk(WIFI_ALWAYS, "atbm_urb_queue_exit ==>\n");

	if(atbm_urb_msgQ_init_state == 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_queue_exit error!!!\n");
		return;
	}

	//Delete TX MessageQ
	status = atbm_os_MsgQ_Delete(&atbm_urb_tx_msgQ);
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_tx_msgQ delete failed 0x%x\n", status);
	}

	//Delete RX MessageQ
	status = atbm_os_MsgQ_Delete(&atbm_urb_rx_msgQ);
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_rx_msgQ delete failed 0x%x\n", status);
	}

	//Delete TX Task
	status = atbm_stopThread(atbm_urb_tx_thread);
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_tx_thread delete failed 0x%x\n", status);
	}

	//Delete RX Task
	status = atbm_stopThread(atbm_urb_rx_thread);
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_rx_thread delete failed 0x%x\n", status);
	}

	//Urb Init Flag Clear
	atbm_urb_msgQ_init_state = 0;
	
	wifi_printk(WIFI_ALWAYS, "atbm_urb_queue_exit <==\n");
	return;
}

