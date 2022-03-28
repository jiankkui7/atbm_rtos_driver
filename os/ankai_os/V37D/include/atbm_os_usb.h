#ifndef ATBM_OS_USB_H
#define ATBM_OS_USB_H
#include "atbm_type.h"
#include "usb_bus_drv.h"
struct urb;
typedef void (*usb_complete_t)(struct urb *);
#pragma pack (4) 
typedef struct urb {
	T_URB  urb;
	atbm_uint32 pipe;				/* (in) pipe information */
	usb_complete_t complete_fn;
	atbm_uint32 actual_length;				/* (return) actual transfer length */
	atbm_int32 status; 					/* (return) non-ISO status */
	atbm_void *context;					/* (in) context for completion */
}atbm_urb_s;
#pragma pack() 

typedef enum
{
    ATBM_DRV_CONTROL_PIPE = 0,
    ATBM_DRV_DATA_IN_PIPE,
    ATBM_DRV_DATA_OUT_PIPE,
    ATBM_DRV_MAX_PIPES
} atbm_drv_pipe;

struct atbm_usb_device
{
	atbm_int8 *pfake;/*No used*/
};

struct atbm_usb_interface
{
	struct dvobj_priv *pdvobjpriv;
};

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

atbm_int32 atbm_usb_control_msg(struct atbm_usb_device *udev, unsigned int pipe, unsigned char request, unsigned char requestType,
                    unsigned short value, unsigned short index, unsigned char *reqdata, unsigned short len, unsigned short timeout);
//atbm_void atbm_usb_fill_bulk_urb(atbm_urb_s *purb, struct atbm_usb_device *udev,unsigned int pipe,
	//atbm_void *txdata, atbm_int32 tx_len, usb_complete_t complete_fn, struct sbus_urb *tx_urb);

atbm_uint32 atbm_usb_rcvbulkpipe(struct atbm_usb_device *udev, atbm_int32 pipe);
atbm_uint32 atbm_usb_sndbulkpipe(struct atbm_usb_device *udev, atbm_int32 pipe);
atbm_uint32 atbm_usb_sndctrlpipe(struct atbm_usb_device *udev, atbm_uint32 pipe);
atbm_uint32 atbm_usb_rcvctrlpipe(struct atbm_usb_device *udev, atbm_uint32 pipe);
struct atbm_usb_device *atbm_usb_get_dev(struct atbm_usb_device *udev);
struct atbm_usb_interface *atbm_usb_get_intf(struct atbm_usb_interface *intf);
struct atbm_usb_device *atbm_interface_to_usbdev(struct atbm_usb_interface *intf);
atbm_void atbm_usb_set_intfdata(struct atbm_usb_interface *usb_intf, struct dvobj_priv *pdvobjpriv);
struct dvobj_priv *atbm_usb_get_intfdata(struct atbm_usb_interface *intf);
atbm_void atbm_usb_put_dev(struct atbm_usb_device *udev);
int atbm_usb_register_init(atbm_void);
int atbm_usb_register_deinit(atbm_void);
atbm_void atbm_urb_queue_init(atbm_void);
atbm_void atbm_urb_queue_exit(atbm_void);

#endif /* ATBM_OS_USB_H */

