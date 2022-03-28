#ifndef ATBM_OS_MAILBOX_H
#define ATBM_OS_MAILBOX_H
#include <rtdef.h>
#include <rtthread.h>
#include "atbm_hal.h"
static pAtbm_thread_t atbm_maibox_bh;
struct rt_mailbox MailBox;

atbm_urb_s *g_usb_pool[32];
int atbm_createMailBox(atbm_void *data);
atbm_urb_s* atbm_mailBox_recv(rt_int32_t timeout);
int atbm_mailBox_send(atbm_urb_s *urb);
#endif
