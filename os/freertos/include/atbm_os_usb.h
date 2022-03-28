#ifndef ATBM_OS_USB_H
#define ATBM_OS_USB_H
//#include <drvUSBHost.h>
#include "atbm_type.h"

#include "target_usb.h"

struct atbm_usb_endpoint_descriptor
{
	atbm_uint8 bLength;
	atbm_uint8 bDescriptorType;

	atbm_uint8 bEndpointAddress;
	atbm_uint8 bmAttributes;
	atbm_uint16 wMaxPacketSize;
	atbm_uint8 bInterval;

	/* NOTE:  these two are _only_ in audio endpoints. */
	/* use USB_DT_ENDPOINT*_SIZE in bLength, not sizeof. */
	atbm_uint8 bRefresh;
	atbm_uint8 bSynchAddress;
} atbm_packed;


typedef struct _InterfaceDescriptor
{
	atbm_uint8 bLength;
	atbm_uint8 bDescriptorType;
	atbm_uint8 bInterfaceNumber;
	atbm_uint8 bAlternateSetting; /* Value used to select alternative setting
		*/
	atbm_uint8 bNumEndpoints; /* Number of Endpoints used for this interface */
	atbm_uint8 bInterfaceClass; /* Class Code (Assigned by USB Org) */
	atbm_uint8 bInterfaceSubClass; /* Subclass Code (Assigned by USB Org) */
	atbm_uint8 bInterfaceProtocol; /* Protocol Code */
	atbm_uint8 iInterface; /* Index of String Descriptor Describing this
		interface */

} USBH_InterfaceDesc_TypeDef;

struct atbm_usb_interface_descriptor
{
	atbm_uint8 bLength;
	atbm_uint8 bDescriptorType;

	atbm_uint8 bInterfaceNumber;
	atbm_uint8 bAlternateSetting;
	atbm_uint8 bNumEndpoints;
	atbm_uint8 bInterfaceClass;
	atbm_uint8 bInterfaceSubClass;
	atbm_uint8 bInterfaceProtocol;
	atbm_uint8 iInterface;
} atbm_packed;

struct atbm_usb_host_interface
{
	struct atbm_usb_interface_descriptor *desc;

	struct atbm_usb_host_endpoint *endpoint;
};



#define  atbm_usb_device HI_CONN_INFO_USB_USB

    struct atbm_usb_host_endpoint
    {
        int id;
		struct atbm_usb_endpoint_descriptor desc;

    };
    struct atbm_usb_interface
    {
       struct atbm_usb_device *udev;
	   struct dvobj_priv *pdvobjpriv;
	   struct  atbm_usb_host_interface  altsetting[1];
    };

 typedef   struct atbm_urb
    {
        /* private: usb core and host controller only fields in the urb */
        //	struct kref kref;		/* reference count of the URB */
        //	void *hcpriv;			/* private data for host controller */
        //	atbm_atomic_t use_count;		/* concurrent submissions counter */
        //	atbm_atomic_t reject;		/* submissions will fail */
        //	int unlinked;			/* unlink error code */

        /* public: documented fields in the urb that can be used by drivers */
        //	struct atbm_list_head urb_list;	/* list head for use by the urb's
        //					 * current owner */
        //	struct atbm_list_head anchor_list;	/* the URB may be anchored */
        //	struct usb_anchor *anchor;
        struct atbm_usb_device *dev; /* (in) pointer to associated device */
    //    struct atbm_usb_host_endpoint *ep; /* (internal) pointer to endpoint */
        unsigned int pipe; /* (in) pipe information */
     //   unsigned int stream_id; /* (in) stream ID */
        int status; /* (return) non-ISO status */
      //  unsigned int transfer_flags; /* (in) URB_SHORT_NOT_OK | ...*/
        atbm_void *transfer_buffer; /* (in) associated data buffer */
       // dma_addr_t transfer_dma; /* (in) dma addr for transfer_buffer */
        //	struct scatterlist *sg;		/* (in) scatter gather buffer list */
        //	int num_sgs;			/* (in) number of entries in the sg list */
        unsigned int transfer_buffer_length; /* (in) data buffer length */
        unsigned int actual_length; /* (return) actual transfer length */
        //	unsigned char *setup_packet;	/* (in) setup packet (control only) */
        //	dma_addr_t setup_dma;		/* (in) dma addr for setup_packet */
       // int start_frame; /* (modify) start frame (ISO) */
       // int number_of_packets; /* (in) number of ISO packets */
       // int interval; /* (modify) transfer interval
         /* (INT/ISO) */
        //int error_count; /* (return) number of ISO errors */
        atbm_void *context; /* (in) context for completion */
        atbm_void *complete; /* (in) completion routine */

        //	struct usb_iso_packet_descriptor iso_frame_desc[0];
        /* (in) ISO ONLY */
    }atbm_urb_s;
	struct atbm_usb_device_id {
	atbm_uint16    match_id_flags;

	atbm_uint16    idVendor;
	atbm_uint16    idProduct;
};
	
	struct atbm_usb_driver {
		char name[16];
	
		int (*probe_func) (struct atbm_usb_interface *intf,
			const struct atbm_usb_device_id *id);
	
		atbm_void (*discon_func) (struct atbm_usb_interface *intf);
	
		const struct atbm_usb_device_id *match_id_table;
	
		//struct device_driver driver;
	
	};
#define USB_DEVICE(a,b)  .idVendor = (a),.idProduct = (b)
/*USB Sturct */
//#define atbm_usb_driver usb_driver
//#define atbm_usb_interface usb_interface
//#define atbm_usb_device_id int
#define atbm_usb_device_descriptor //usb_device_descriptor
#define atbm_usb_host_config //usb_host_config
#define atbm_usb_config_descriptor //usb_config_descriptor
//#define atbm_usb_host_interface	usb_host_interface
//#define atbm_usb_interface_descriptor	usb_interface_descriptor
//#define atbm_usb_host_endpoint usb_host_endpoint
//#define atbm_usb_endpoint_descriptor usb_endpoint_descriptor
//#define atbm_usb_device	usb_device
/*USB Interface*/
//#define atbm_usb_register(a) ms_usb_register(a)	
#define atbm_usb_deregister(a)	//ms_usb_deregister(a)
#define atbm_usb_alloc_urb(a, b)  usb_alloc_urb(a)//((a) == 0 ? ms_usb_alloc_urb(b) : ms_usb_alloc_isoc_urb(a, b))
#define atbm_usb_free_urb(a)  usb_free_urb(a)
#define atbm_usb_rcvbulkpipe(udev,a)	ATBM_USB_VENQT_READ
#define atbm_usb_sndbulkpipe(udev,a)	ATBM_USB_VENQT_WRITE
#define atbm_usb_sndctrlpipe(udev,a) (a)
#define atbm_usb_rcvctrlpipe(udev,a) (a)
#define atbm_usb_control_msg  usb_control_msg 
//#define atbm_usb_fill_bulk_urb usb_fill_bulk_urb	
#define atbm_usb_submit_urb(a,b) usb_submit_urb(a)
#define atbm_usb_kill_urb(a) usb_kill_urb(a)
#define atbm_interface_to_usbdev(a) (struct HI_CONN_INFO_USB_USB *)(((struct atbm_usb_interface *)(a))->udev)
#define atbm_usb_set_intfdata(a,b) {(a)->pdvobjpriv = (b);}
#define atbm_usb_get_intfdata(a) (a)->pdvobjpriv
#define atbm_usb_endpoint_is_bulk_in(a) //endpoint_is_bulk_in(a)
#define atbm_usb_endpoint_num(a) //usb_endpoint_num(a)
#define atbm_usb_endpoint_is_bulk_out(a) //endpoint_is_bulk_out(a)
//#define atbm_usb_get_dev(a) //ms_usb_get_dev(a)
#define atbm_usb_put_dev(a)// ms_usb_put_dev(a)
#define atbm_usb_reset_device(a) //ms_usb_reset_device(a)


//#define atbm_usb_device  usb_device

//#define atbm_interface_to_usbdev(intf)  (intf)
#define atbm_usb_get_dev(udev)  (udev)
#define atbm_usb_get_intf(intf)  (intf)




struct atbm_urb *usb_alloc_urb(int id);
atbm_void atbm_usb_rx_callback();
/////////////////////////////////////////////////////////////////////
#endif /* ATBM_OS_USB_H */

