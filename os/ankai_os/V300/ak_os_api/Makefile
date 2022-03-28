TOPDIR 	?= $(shell pwd)/../../../..
KERNELDIR ?= $(TOPDIR)/kernel
CUR_DIR ?= $(shell pwd)
TARGET = libwifi_atbmwifi
LDFLAGS = -p -X -Map maps.txt -T section.lds
chips := ak39e
LWIP_VER := 1.4.1

WRAP_FUNC = malloc calloc realloc free

LDFLAGS += $(addprefix --wrap=, $(WRAP_FUNC))
KER_INCLUDE    =     -I. \
                -I$(KERNELDIR)/include \
                -I$(KERNELDIR)/include/driver \
                -I$(KERNELDIR)/include/os \
                -I$(KERNELDIR)/include/lwip_$(LWIP_VER) \
                -I$(KERNELDIR)/include/lwip_$(LWIP_VER)/ipv4 \
                -I$(KERNELDIR)/include/fs \
                -I$(KERNELDIR)/mach/mach-$(chips) \
                -I$(KERNELDIR)/common \
                -I$(KERNELDIR)/fs \
                -I$(KERNELDIR)/include/partition \
                -I$(KERNELDIR)/partition \
                -I$(KERNELDIR)/net/wifi \
                -I$(KERNELDIR)/driver/include

#include .h
INCLUDE    =	-I. \
		-I$(CUR_DIR)/api \
		-I$(CUR_DIR)/hal \
		-I$(CUR_DIR)/hal/sdio \
		-I$(CUR_DIR)/hal/include \
		-I$(CUR_DIR)/include \
		-I$(CUR_DIR)/net/include \
		-I$(CUR_DIR)/net/include/proto \
		-I$(CUR_DIR)/os/include	\
		-I$(CUR_DIR)/os/ankai_os/include

INCLUDE += $(GLB_INCLUDE) $(KER_INCLUDE)

#include .c
SRCDIR += \
		$(CUR_DIR)/api \
		$(CUR_DIR)/hal	\
		$(CUR_DIR)/hal/sdio \
		$(CUR_DIR)/net \
		$(CUR_DIR)/net/wpa \
		$(CUR_DIR)/os/ankai_os

CSRCS += $(foreach d, $(SRCDIR), $(wildcard $d/*.c))

COBJS += $(patsubst %.c, %.o, $(CSRCS))



#build rule
.PHONY: all $(TARGET) clean

all: $(TARGET) 

$(TARGET): $(COBJS) 
	@echo ---------------------[build obj complete]----------------------------------	
	$(AR) rc $(TARGET).a $(COBJS) $(CLIB)


clean : 
	$(RM) $(COBJS)
	$(RM) $(TARGET).a

# Rules
include $(TOPDIR)/rules.mk
