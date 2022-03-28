COMPILE := api/atbm_api.c
COMPILE += hal/atbm_ap.c
COMPILE += hal/atbm_config.c
COMPILE += hal/atbm_etf.c
COMPILE += hal/atbm_init.c
COMPILE += hal/atbm_main.c
COMPILE += hal/atbm_queue.c
COMPILE += hal/atbm_skbuf.c
COMPILE += hal/atbm_smartconfig.c
COMPILE += hal/atbm_sta.c
COMPILE += hal/atbm_task.c
COMPILE += hal/atbm_txrx.c
COMPILE += hal/atbm_wifi_driver_api.c
COMPILE += hal/atbm_wsm.c
COMPILE += hal/smartconfig.c
COMPILE += hal/usb/atbm_usb.c
COMPILE += hal/usb/atbm_usb_bh.c
COMPILE += hal/usb/atbm_usb_hwio.c
COMPILE += hal/usb/atbm_usb_fwio.c
COMPILE += net/app_wifi_cmd.c
COMPILE += net/atbm_key.c
COMPILE += net/atbm_mgmt.c
COMPILE += net/atbm_ratectrl.c
COMPILE += net/atbm_rc80211_minstrel.c
COMPILE += net/atbm_rc80211_minstrel_ht.c
COMPILE += net/atbm_rc80211_pid_algo.c
COMPILE += net/atbm_util.c
COMPILE += net/wpa/aes_core.c
COMPILE += net/wpa/hostapd_main.c
COMPILE += net/wpa/sha1.c
COMPILE += net/wpa/wpa_common.c
COMPILE += net/wpa/wpa_main.c
COMPILE += net/wpa/wpa_timer.c
COMPILE += os/ecos/atbm_os_api.c
COMPILE += os/ecos/atbm_os_atomic.c
COMPILE += os/ecos/atbm_os_mem.c
COMPILE += os/ecos/atbm_os_mutex.c
COMPILE += os/ecos/atbm_os_skbuf.c
COMPILE += os/ecos/atbm_os_spinlock.c
#COMPILE += os/ecos/atbm_os_test_cmd.c
COMPILE += os/ecos/atbm_os_thread.c
COMPILE += os/ecos/atbm_os_timer.c
COMPILE += os/ecos/atbm_os_usb.c
COMPILE += os/ecos/atbm_os_workqueue.c
COMPILE += os/ecos/atbm_wifi_init.cpp

include ../../script/config.mk
include ../../script/rules.mk

CFLAGS += -I./include -I./api -I./hal/include -I./hal/usb -I./net/include -I./os/include -I./os/ecos/include -I./net/include/proto -I../../../ecos3.0/packages/net/bcd_tcpip/v3.0/include -I../../gxcoreapi/ecos3.0/packages/devs/eth/gx/gxmac/v3_0/include -I../../../ecos3.0/packages/devs/usbhost/gx/lib/v3.0/include

pre-build:
pre-clean:

#all: echo "start build" make -C build INTF=USB OsType=ecos project=AthenaB
#clean: echo "clean complete" rm -rf lib/*.a

