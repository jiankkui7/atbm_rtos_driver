#ifndef ATBM_OS_USB_H
#define ATBM_OS_USB_H
//#include <drvUSBHost.h>
#include "atbm_type.h"
//#include <usb/mod_devicetable.h>
#include <usb/usb.h>

#if 0
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
#endif

typedef struct urb atbm_urb_s;
#if 0
struct atbm_usb_driver {
	char *name;
	int (*probe) (struct atbm_usb_interface *intf,const struct atbm_usb_device_id *id);
	atbm_void (*discon) (struct atbm_usb_interface *intf);
	int (*ioctl) (struct atbm_usb_interface *intf, unsigned int code, atbm_void *buf);
	int (*suspend) (struct atbm_usb_interface *intf);
	int (*resume) (struct atbm_usb_interface *intf);
	int (*pre_reset) (struct atbm_usb_interface *intf);
	int (*post_reset) (struct atbm_usb_interface *intf);
	const struct atbm_usb_device_id *id_table;
	struct usb_dynids dynids;
	struct usbdrv_wrap drvwrap;
	unsigned int no_dynamic_id:1;
	unsigned int supports_autosuspend:1;
};
#else
typedef struct usb_driver atbm_usb_driver;
#endif

struct atbm_usb_device_id{

	atbm_uint16 match_flags;
	atbm_uint16 idVendor;
	atbm_uint16 idProduct;
	atbm_uint16 bcdDevice_lo;
	atbm_uint16 bcdDevice_hi;
	atbm_uint8 bDeviceClass;
	atbm_uint8 bDeviceSubClass;
	atbm_uint8 bDeviceProtocol;
	atbm_uint8 bInterfaceClass;
	atbm_uint8 bInterfaceSubClass;
	atbm_uint8 bInterfaceProtocol;
	atbm_uint32 driver_info;
};

#define atbm_usb_init_urb(a)        usb_init_urb(a)
#define atbm_usb_alloc_urb(a, b)    usb_alloc_urb(a)//((a) == 0 ? ms_usb_alloc_urb(b) : ms_usb_alloc_isoc_urb(a, b))
#define atbm_usb_free_urb(a)        usb_free_urb(a)
#define atbm_usb_get_urb(a)         usb_get_urb(a)
#define atbm_usb_submit_urb(a,b)    usb_submit_urb(a)
#define atbm_usb_unlink_urb(a)      usb_unlink_urb(a)
#define atbm_usb_kill_urb(a)        usb_kill_urb(a)

#define atbm_usb_control_msg        usb_control_msg 
#define atbm_usb_fill_bulk_urb      usb_fill_bulk_urb	

/*
#define atbm_usb_rcvbulkpipe(udev,a)	ATBM_USB_VENQT_READ
#define atbm_usb_sndbulkpipe(udev,a)	ATBM_USB_VENQT_WRITE
#define atbm_usb_sndctrlpipe(udev,a) (a)
#define atbm_usb_rcvctrlpipe(udev,a) (a)
*/
#define atbm_usb_rcvbulkpipe(udev,a)	usb_rcvbulkpipe(udev,a)
#define atbm_usb_sndbulkpipe(udev,a)	usb_sndbulkpipe(udev,a)
#define atbm_usb_sndctrlpipe(udev,a)	usb_sndctrlpipe(udev,a)
#define atbm_usb_rcvctrlpipe(udev,a)	usb_rcvctrlpipe(udev,a)

#define atbm_usb_device         usb_device
#define atbm_usb_interface      usb_interface
//#define atbm_usb_device_id      usb_device_id
#define atbm_usb_get_dev(udev)  usb_get_dev(udev)
#define atbm_usb_get_intf(intf) usb_get_intf(intf)
#define atbm_interface_to_usbdev(a) interface_to_usbdev(a)

#define atbm_usb_set_intfdata(a,b) usb_set_intfdata(a, b)
#define atbm_usb_get_intfdata(a) usb_get_intfdata(a)
#define atbm_usb_endpoint_is_bulk_in(a) usb_endpoint_is_bulk_in(a)
#define atbm_usb_endpoint_num(a) usb_endpoint_num(a)
#define atbm_usb_endpoint_is_bulk_out(a) usb_endpoint_is_bulk_out(a)
#define atbm_usb_put_dev(a) usb_put_dev(a)
#define atbm_usb_reset_device(a) usb_reset_device(a)

//struct atbm_urb *usb_alloc_urb(int id);
/////////////////////////////////////////////////////////////////////
#endif /* ATBM_OS_USB_H */

