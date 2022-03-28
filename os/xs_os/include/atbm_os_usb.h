#ifndef ATBM_OS_USB_H
#define ATBM_OS_USB_H

typedef struct urb atbm_urb_s;
/*USB Sturct */
#define atbm_usb_driver usb_driver
#define atbm_usb_interface usb_interface
#define atbm_usb_device_id usb_device_id
#define atbm_usb_device_descriptor usb_device_descriptor
#define atbm_usb_host_config usb_host_config
#define atbm_usb_config_descriptor usb_config_descriptor
#define atbm_usb_host_interface	usb_host_interface
#define atbm_usb_interface_descriptor	usb_interface_descriptor
#define atbm_usb_host_endpoint usb_host_endpoint
#define atbm_usb_endpoint_descriptor usb_endpoint_descriptor
#define atbm_usb_device	usb_device
/*USB Interface*/
#define atbm_usb_register(a) ms_usb_register(a)	
#define atbm_usb_deregister(a)	ms_usb_deregister(a)
#define atbm_usb_alloc_urb(a, b) ((a) == 0 ? ms_usb_alloc_urb(b) : ms_usb_alloc_isoc_urb(a, b))
#define atbm_usb_free_urb(a)  ms_usb_free_urb(a)
#define atbm_usb_rcvbulkpipe(udev,a)	usb_rcvbulkpipe(udev,a)
#define atbm_usb_sndbulkpipe(udev,a)	usb_sndbulkpipe(udev,a)
#define atbm_usb_sndctrlpipe(udev,a) usb_sndctrlpipe(udev,a)
#define atbm_usb_rcvctrlpipe(udev,a) usb_rcvctrlpipe(udev,a)
#define atbm_usb_control_msg(fmt, arg...) ms_usb_control_cmd(fmt, ##arg)
#define atbm_usb_fill_bulk_urb ms_usb_stuff_bulk_urb	
#define atbm_usb_submit_urb(a,b) ms_usb_submit_urb(a, b)
#define atbm_usb_kill_urb(a) ms_usb_kill_urb(a)
#define atbm_interface_to_usbdev(a) interface_to_usbdev(a)
#define atbm_usb_set_intfdata(a,b) ms_usb_set_intfdata(a,b)
#define atbm_usb_get_intfdata(a) ms_usb_get_intfdata(a)
#define atbm_usb_endpoint_is_bulk_in(a) endpoint_is_bulk_in(a)
#define atbm_usb_endpoint_num(a) usb_endpoint_num(a)
#define atbm_usb_endpoint_is_bulk_out(a) endpoint_is_bulk_out(a)
#define atbm_usb_get_dev(a) ms_usb_get_dev(a)
#define atbm_usb_put_dev(a) ms_usb_put_dev(a)
#define atbm_usb_reset_device(a) ms_usb_reset_device(a)
#define atbm_usb_get_intf(a) usb_get_intf(a)

/////////////////////////////////////////////////////////////////////
#endif /* ATBM_OS_USB_H */

