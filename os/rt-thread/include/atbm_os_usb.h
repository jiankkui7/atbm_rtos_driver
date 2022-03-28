#ifndef ATBM_OS_USB_H
#define ATBM_OS_USB_H
#include <usb.h>
#include "atbm_type.h"
typedef struct urb atbm_urb_s;
typedef struct usb_driver atbm_usb_driver;
#define atbm_usb_register(a) usb_register_driver(a)	
#define atbm_usb_deregister(a)	usb_deregister(a)
#define atbm_usb_init_urb(a)        usb_init_urb(a)
#define atbm_usb_alloc_urb(a, b)    usb_alloc_urb(a,b)//((a) == 0 ? ms_usb_alloc_urb(b) : ms_usb_alloc_isoc_urb(a, b))
#define atbm_usb_free_urb(a)        usb_free_urb(a)
#define atbm_usb_get_urb(a)         usb_get_urb(a)
#define atbm_usb_submit_urb(a,b)    usb_submit_urb(a,b)
#define atbm_usb_unlink_urb(a)      usb_unlink_urb(a)
#define atbm_usb_kill_urb(a)        usb_kill_urb(a)
#define atbm_usb_control_msg        usb_control_msg 
#define atbm_usb_fill_bulk_urb      usb_fill_bulk_urb	
#define atbm_usb_rcvbulkpipe(udev,a)	usb_rcvbulkpipe(udev,a)
#define atbm_usb_sndbulkpipe(udev,a)	usb_sndbulkpipe(udev,a)
#define atbm_usb_sndctrlpipe(udev,a)	usb_sndctrlpipe(udev,a)
#define atbm_usb_rcvctrlpipe(udev,a)	usb_rcvctrlpipe(udev,a)

#define atbm_usb_device         usb_device
#define atbm_usb_interface      usb_interface
#define atbm_usb_device_id      usb_device_id
static __INLINE struct atbm_usb_device *atbm_interface_to_usbdev(struct atbm_usb_interface *intf)
{
	return intf->usb_dev;
}
static __INLINE struct atbm_usb_device *atbm_usb_get_dev(struct atbm_usb_device *udev)
{
	return udev;
}
static __INLINE struct atbm_usb_interface *atbm_usb_get_intf(struct atbm_usb_interface *intf)
{
	return intf;
}
//static __INLINE int atbm_usb_set_intfdata(struct atbm_usb_interface *usb_intf,void* user_data){
	//usb_intf->user_data=user_data;
	//return 0;
//}
#define atbm_usb_set_intfdata(a,b) usb_set_intfdata(a,b)
#define atbm_usb_get_intfdata(a) usb_get_intfdata(a)
#define atbm_usb_endpoint_is_bulk_in(a) usb_endpoint_is_bulk_in(a)
#define atbm_usb_endpoint_num(a) usb_endpoint_num(a)
#define atbm_usb_endpoint_is_bulk_out(a) usb_endpoint_is_bulk_out(a)
#define atbm_usb_put_dev(a) (a)
#define atbm_usb_reset_device(a) (a)

#endif /* ATBM_OS_USB_H */


