#include "atbm_hal.h"
#include "akos_api.h"
#include "atbm_os_msgQ.h"

#define ATBM_URB_TX_MSGQ_NUM 4
static atbm_os_msgq atbm_urb_tx_msgQ;
static atbm_urb_s atbm_urb_tx_msqQbuf[ATBM_URB_TX_MSGQ_NUM+1];

#define ATBM_URB_RX_MSGQ_NUM 4
static atbm_os_msgq atbm_urb_rx_msgQ ;
static atbm_urb_s atbm_urb_rx_msqQbuf[ATBM_URB_RX_MSGQ_NUM+1];

pAtbm_thread_t atbm_urb_tx_thread;
pAtbm_thread_t atbm_urb_rx_thread;

#define ATBM_URB_TX_THREAD_PRIORITY		14
#define ATBM_URB_RX_THREAD_PRIORITY		14
#define ATBM_URB_TX_THREAD_STACKSIZE		4096
#define ATBM_URB_RX_THREAD_STACKSIZE		4096

static atbm_uint8 atbm_urb_tx_thread_stack[ATBM_URB_TX_THREAD_STACKSIZE];
static atbm_uint8 atbm_urb_rx_thread_stack[ATBM_URB_RX_THREAD_STACKSIZE];


static atbm_int32 atbm_urb_msgQ_init_state = 0;

extern bool usb_bus_reg_class(T_pUSB_BUS_HANDLER bus_handler);

int  atbm_usb_register (T_pUSB_BUS_HANDLER tBusHandle)
{
	if (!usb_bus_reg_class(tBusHandle)) {
		return -1;
	}
	return 0;
}
int atbm_usb_deregister(T_pUSB_BUS_HANDLER tBusHandle)	
{
	if(tBusHandle->discon_callback){
		tBusHandle->discon_callback;
	}
	return 0;
}
atbm_uint32 atbm_usb_rcvbulkpipe(struct atbm_usb_device *udev, atbm_int32 pipe)
{
	udev = udev; /*No used*/
	pipe = pipe; /*No used*/
	return (atbm_uint32)ATBM_DRV_DATA_IN_PIPE;
}

atbm_uint32 atbm_usb_sndbulkpipe(struct atbm_usb_device *udev, atbm_int32 pipe)
{
	udev = udev; /*No used*/
	pipe = pipe; /*No used*/
	return (atbm_uint32)ATBM_DRV_DATA_OUT_PIPE;
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
	T_URB_HANDLE hURB = NULL;
	T_UsbDevReq dev_req;
	T_URB urb;
	unsigned long ReadLen=0;
	dev_req.bmRequestType = requestType;
	dev_req.bRequest =request;
	dev_req.wValue = value;
	dev_req.wIndex = index;
	dev_req.wLength = len;

	memcpy(&urb.dev_req, &dev_req, sizeof(T_UsbDevReq));
	urb.trans_type = TRANS_CTRL;
	
	if(requestType==ATBM_USB_VENQT_WRITE){
		urb.trans_dir =TRANS_DATA_OUT;
	}else{
		urb.trans_dir =TRANS_DATA_IN;

	}
	urb.data = reqdata;
	urb.buffer_len = len;
	urb.data_len = len;
	urb.timeout = timeout;
	urb.callback=ATBM_NULL;
	// submit
	if(urb.data==ATBM_NULL){
		
		wifi_printk(WIFI_ALWAYS," urb.dat NULL \n");
	}
	hURB = usb_bus_commit_urb(&urb);
	if (NULL == hURB) {
		return false;
	}
	// waiting for urb completion
	ReadLen=usb_bus_wait_completion(hURB);
	if (ReadLen<0) {
		return -1;
	}
	return ReadLen;
}
atbm_void atbm_urb_callback(T_URB *urb){
	wifi_printk(WIFI_ALWAYS,"%s %d\n",__func__,__LINE__);
	atbm_urb_s *atbmUrb =atbm_container_of(urb,atbm_urb_s,urb);
	atbmUrb->status=urb->result;
	atbmUrb->actual_length=urb->trans_len;
	atbmUrb->complete_fn(atbmUrb->context);
}
atbm_void  atbm_usb_fill_bulk_urb(atbm_urb_s *purb,
                     struct atbm_usb_device *dev,
                     unsigned int pipe,
                     void *transfer_buffer,
                     int buffer_length,
                     usb_complete_t complete_fn,
                     struct sbus_urb *context)
{
	purb->urb.trans_type = TRANS_BULK;
	if(pipe==ATBM_DRV_DATA_IN_PIPE){
		purb->urb.trans_dir =TRANS_DATA_IN;
		purb->urb.callback=ATBM_NULL;
	}else{
		purb->urb.trans_dir =TRANS_DATA_OUT;
		purb->urb.callback=ATBM_NULL;;
	}
	purb->pipe =pipe;
	purb->urb.data = transfer_buffer;
	purb->urb.buffer_len = buffer_length;
	purb->urb.data_len = buffer_length;
	purb->urb.timeout = 0xffffffff;
	purb->actual_length=buffer_length;
	purb->complete_fn=complete_fn;
	purb->context = (atbm_void *)context;
}
#if 0
atbm_int32 atbm_usb_submit_urb(atbm_urb_s *purb, int param)
{
	atbm_int32 retry_count = 0;
	atbm_int32 retval = 0;
	T_URB_HANDLE hURB = ATBM_NULL;
	hURB=usb_bus_commit_urb(&purb->urb);
	if (ATBM_NULL == hURB) {
		return -1;
	}
	switch(purb->pipe){
		case ATBM_DRV_DATA_IN_PIPE:
			// waiting for urb completion
			purb->status=usb_bus_wait_completion(hURB);
			if(purb->status>0){
				purb->actual_length=purb->status;
				purb->status=0;
			}
			/*Rx Urb complete*/
			purb->complete_fn(purb);
			wifi_printk(WIFI_ALWAYS,"Rx Use CallBack \n");
			break;
		case ATBM_DRV_DATA_OUT_PIPE:
			// waiting for urb completion
			purb->status=usb_bus_wait_completion(hURB);		
			if(purb->status>0){
				purb->status=0;
			}
			/*Tx Urb complete*/
			purb->complete_fn(purb);
			break;
		default:
			wifi_printk(WIFI_ALWAYS,"Error TransType\n");
			break;
	}
	return purb->status;
	
}
#endif
atbm_int32 atbm_usb_submit_urb(atbm_urb_s *purb, int param)
{
	atbm_int32 ret = 0;
	atbm_uint32 status;

	param = param; /*No used*/
	
	atbm_uint32 pdata;
	
	pdata = (atbm_uint32)purb;
	switch(purb->pipe){

		case ATBM_DRV_DATA_IN_PIPE:
			//wifi_printk(WIFI_ALWAYS, "Send In pipe pdata 0x%x\n", pdata);
			status = atbm_os_MsgQ_Send(&atbm_urb_rx_msgQ, &pdata,sizeof(atbm_uint32*));
			if (0 != status){
				wifi_printk(WIFI_ALWAYS, "atbm_urb_rx_msgQ send failed 0x%x\n", status);
				ret = -1;
			}
			break;
		case ATBM_DRV_DATA_OUT_PIPE:
			//wifi_printk(WIFI_ALWAYS, "Send Out pipe pdata 0x%x\n", pdata);
			status = atbm_os_MsgQ_Send(&atbm_urb_tx_msgQ, &pdata,sizeof(atbm_uint32*));
			if (0 != status){
				wifi_printk(WIFI_ALWAYS, "atbm_urb_tx_msgQ send failed 0x%x\n", status);
				ret = -1;
			}
			break;
		default:
			wifi_printk(WIFI_ALWAYS, "atbm_usb_submit_urb pipe error %d\n", purb->pipe);
			ret = -1;
			break;
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
	udev = udev; /*No used*/
	return ATBM_NULL;
}
struct atbm_usb_interface *atbm_usb_get_intf(struct atbm_usb_interface *intf)
{
	intf = intf; /*No used*/
	return ATBM_NULL;
}
struct atbm_usb_device *atbm_interface_to_usbdev(struct atbm_usb_interface *intf)
{
	intf = intf; /*No used*/
	return ATBM_NULL;
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
atbm_int32 atbm_urb_tx_queue_task(void *unused)
{
	atbm_int32 ret;
	atbm_uint32 status;
	atbm_urb_s urb_tx;
	atbm_urb_s *purb = &urb_tx;
	atbm_uint32 actual_size;
	T_URB_HANDLE hURB = ATBM_NULL;
	atbm_uint32 pdata;

	//wifi_printk(WIFI_ALWAYS, "%s, running...\n", __func__);

	while(1){

		status=atbm_os_MsgQ_Recv(&atbm_urb_tx_msgQ,&pdata,sizeof(atbm_uint32*));
		if(status != 0){
			wifi_printk(WIFI_ALWAYS, "atbm_urb_tx_msgQ recv failed 0x%x\n", status);
		}
		//wifi_printk(WIFI_ALWAYS, "Receive out pipe pdata 0x%x\n", pdata);
		purb = (struct atbm_urb_s *)pdata;
		hURB=usb_bus_commit_urb(&purb->urb);
		if (ATBM_NULL == hURB) {
			return -1;
		}
		purb->status=usb_bus_wait_txcompletion(hURB); 	
		if(purb->status>0){
			purb->status=0;
		}
		/*Tx Urb complete*/
		purb->complete_fn(purb);
	}
	return 0;
}


atbm_int32 atbm_urb_rx_queue_task(void *unused)
{
	atbm_int32 ret;
	atbm_uint32 status,actual_size;
	atbm_urb_s urb_rx;	
	atbm_urb_s *purb = &urb_rx;
	atbm_uint32 pdata;
	T_URB_HANDLE hURB = ATBM_NULL;
	//wifi_printk(WIFI_ALWAYS, "%s, running...\n", __func__);
	
	while(1){
		status=atbm_os_MsgQ_Recv(&atbm_urb_rx_msgQ,&pdata,sizeof(atbm_uint32*));
		if(status != 0){
			wifi_printk(WIFI_ALWAYS, "atbm_urb_rx_msgQ recv failed 0x%x\n", status);
		}
		//wifi_printk(WIFI_ALWAYS, "Receive In pipe pdata 0x%x\n", pdata);
		purb = (struct atbm_urb_s *)pdata;
		hURB=usb_bus_commit_urb(&purb->urb);
		if (ATBM_NULL == hURB) {
			return -1;
		}
		purb->status=usb_bus_wait_rxcompletion(hURB);
		if(purb->status>0){
			purb->actual_length=purb->status;
			purb->status=0;
		}
		/*Rx Urb complete*/
		purb->complete_fn(purb);
	}
	return 0;
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
	
	status=atbm_os_MsgQ_Create(&atbm_urb_tx_msgQ,&atbm_urb_tx_msqQbuf[0],ATBM_URB_TX_MSGQ_NUM*sizeof(atbm_uint32));
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_tx_msgQ create failed 0x%x\n", status);
		return;
	}

	// Init RX MessageQ
	status = atbm_os_MsgQ_Create(&atbm_urb_rx_msgQ,&atbm_urb_rx_msqQbuf,ATBM_URB_RX_MSGQ_NUM*sizeof(atbm_uint32*));
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_rx_msgQ create failed 0x%x\n", status);
		return;
	}
	//Init TX Task
	atbm_urb_tx_thread=atbm_createThread(atbm_urb_tx_queue_task,ATBM_NULL,TXURB_TASK_PRIO);
	if (!atbm_urb_tx_thread){
		wifi_printk(WIFI_DBG_ERROR,"bh_thread Failed\n");
		return -1;
	}

	//Init RX Task
	atbm_urb_rx_thread=atbm_createThread(atbm_urb_rx_queue_task,ATBM_NULL,RXURB_TASK_PRIO);
	if (!atbm_urb_rx_thread){
		wifi_printk(WIFI_DBG_ERROR,"bh_thread Failed\n");
		return -1;
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
	status = atbm_stopThread(&atbm_urb_tx_thread);
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_tx_thread delete failed 0x%x\n", status);
	}

	//Delete RX Task
	status = atbm_stopThread(&atbm_urb_rx_thread);
	if(status != 0){
		wifi_printk(WIFI_ALWAYS, "atbm_urb_rx_thread delete failed 0x%x\n", status);
	}

	//Urb Init Flag Clear
	atbm_urb_msgQ_init_state = 0;
	
	wifi_printk(WIFI_ALWAYS, "atbm_urb_queue_exit <==\n");
	return;
}

