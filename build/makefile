# build options
## platform: AG101P, AG102, AE210P
PLAT ?= AE210P
## address: 16MB, 4GB
ADDR ?= 4GB
## mode: LOAD, BURN, XIP
MODE ?= XIP
## feature: EX9, IFC
FEAT ?= ""
## debug: YES, NO
DEBU ?= YES
## SIMU: YES, NO
B2B_SIMU ?= YES
## INTF: SDIO, USB, SPI
INTF ?= SDIO
project ?=AthenaB
$(info platform: $(PLAT), address:$(ADDR), caseNum:$(caseNum), mode:$(MODE), feature:$(FEAT), B2B_SIMU:$(B2B_SIMU) ,INTF:$(INTF), project:$(project))


ifeq (XIP,$(MODE))
 OPT_LLINIT := y
 OPT_REMAP  := n
else
 $(error This demo supports MODE "XIP" only!)
endif

ifeq (YES,$(B2B_SIMU))
CFLAGS += -DCFG_B2B_SIMU
# tool-chain
# TOOLCHAINS = /wfhome/tools/Andestech/toolchains/nds32le-elf-mculib-v3/bin/
endif

ifeq (USB,$(INTF))
CFLAGS += -DUSB_BUS
InType = usb
endif
ifeq (SDIO,$(INTF))
CFLAGS += -DSDIO_BUS
InType = sdio
endif
ifeq (SPI,$(INTF))
CFLAGS += -DSPI_BUS
InType = spi
endif
###################OS ######################
ifeq (rtos,$(OsType))
OsType = rtos
endif
ifeq (ucos,$(OsType))
OsType = ucos
endif
ifeq (tizen,$(OsType))
OsType = tizen
endif
###################TARGET#############################
ifeq (ap,$(TARGET))
CFLAGS += -DHMAC_AP_MODE
endif
# tool-chain
CROSS_COMPILE = $(TOOLCHAINS)nds32le-elf-

#CROSS_COMPILE ?= nds32le-elf-

CC = g++44
OBJCOPY = objcopy
OBJDUMP = objdump
NM = nm

LD_PATH  = .build/
API_SRC_PATH = ../api/
HAL_SRC_PATH = ../hal/
NET_SRC_PATH = ../net/
HAL_INTYPE_SRC_PATH = ../hal/$(InType)/
OSTYPE_SRC_PATH = ../os/$(OsType)/

#######################c#########################
vpath %.c $(API_SRC_PATH)
API_SRC := \
	atbm_api.c
vpath %.c $(HAL_SRC_PATH)
HAL_SRC := \
	atbm_ap.c \
	atbm_smartconfig.c \ 
	atbm_bh.c \
	atbm_config.c \
	atbm_main.c \
	smartconfig.c \
	atbm_sta.c \
	atbm_txrx.c \
	atbm_wsm.c 
vpath %.c $(HAL_INTYPE_SRC_PATH)
USB_SRC := \
	atbm_usb.c \
	atbm_usb_bh.c \
	atbm_usb_hwio.c \
	atbm_usb_fwio.c
SDIO_SRC := \
	atbm_sdio.c \
	atbm_sdio_bh.c \
	atbm_sdio_hwio.c \
	atbm_sdio_fwio.c
vpath %.c $(NET_SRC_PATH)
NET_SRC := \
	atbm_ratectrl.c \
	atbm_key.c \
	atbm_rc80211_pid_algo.c \
	atbm_util.c 
vpath %.c $(OS_SRC_PATH)
OS_SRC := \
	atbm_heap_2.c \
	atbm_hmac_sched.c \
	atbm_timer.c \
	atbm_queue.c \
	atbm_skbuf.c
vpath %.c $(OSTYPE_SRC_PATH)
	RTOS_SRC: = \
INCLUDE_PATH = \
	-I$(API_SRC_PATH) \
	-I$(HAL_SRC_PATH) \
	-I$(HWIO_SRC_PATH) \
	-I$(NET_SRC_PATH) \
	-I$(OS_SRC_PATH) 
HMAC_SRCS = \
	$(API_SRC) \
	$(HAL_SRC) \
	$(USB_SRC) \
	$(NET_SRC) \
	$(OS_SRC) \
	$(RTOS_SRC)

AFLAGS = -D__ASSEMBLY__
CFLAGS += -fPIC -g -Os -c $(CEXTFLAGS) -w -Wall -m64 -DCFG_MAKEFILE -DCFG_$(PLAT) $(INCLUDE_PATH) -DCONFIG_CW1200_WSM_DEBUG
LDFLAGS += -fPIC -shared -m64 -Os -Wl,-Map,link.map -mrelax
OBJCOPYFLAGS = -O binary -R .note -R .comment -S
NMFLAGS = -B -n
TARGET = hmac

# feature check
ifeq (YES,$(EX9))
  LDFLAGS += -Wl,--mex9
else
  LDFLAGS += -Wl
#  CFLAGS += -DCONFIG_NO_NDS32_EXT_EX9
endif
# others
ifeq (y,$(OPT_LLINIT))
 CFLAGS += -DCFG_LLINIT
endif

ifeq (y,$(OPT_REMAP))
 CFLAGS += -DCFG_REMAP
endif

# debug support
ifeq (YES,$(DEBU))
 CFLAGS := $(subst -g3 -Os,-g -O0,$(CFLAGS))
 LDFLAGS := $(subst -Os,-O0,$(LDFLAGS))
 CFLAGS += -DCFG_DEBUG
endif
OBJ_DIR			=	..

GEN_C_SRCS 	= $(filter %.c,$(HMAC_SRCS))
GEN_S_SRCS 	= $(filter %.S,$(HMAC_SRCS))

GEN_C_OBJS1 = 	$(patsubst %.c,%.o1,$(GEN_C_SRCS) )
GEN_S_OBJS1 = 	$(patsubst %.S,%.o1,$(GEN_S_SRCS) )
OBJS1	=       $(addprefix $(OBJ_DIR)/,$(patsubst %.c, %.o1, $(patsubst %.S, %.o1,$(HMAC_SRCS))))

GEN_C_OBJS2 = 	$(patsubst %.c,%.o2,$(GEN_C_SRCS) )
GEN_S_OBJS2 = 	$(patsubst %.S,%.o2,$(GEN_S_SRCS) )
OBJS2	=       $(addprefix $(OBJ_DIR)/,$(patsubst %.c, %.o2, $(patsubst %.S, %.o2,$(HMAC_SRCS))))
ifeq (YES,$(TEST_STAP))
GEN_C_OBJS3 =   $(patsubst %.c,%.o3,$(GEN_C_SRCS) )
GEN_S_OBJS3 =   $(patsubst %.S,%.o3,$(GEN_S_SRCS) )
OBJS3   =       $(addprefix $(OBJ_DIR)/,$(patsubst %.c, %.o3, $(patsubst %.S, %.o3,$(HMAC_SRCS))))
endif
ALL_C_OBJS1 =	$(addprefix $(OBJ_DIR)/,$(GEN_C_OBJS1))
ALL_S_OBJS1 =	$(addprefix $(OBJ_DIR)/,$(GEN_S_OBJS1))

ALL_C_OBJS2 =	$(addprefix $(OBJ_DIR)/,$(GEN_C_OBJS2))
ALL_S_OBJS2 =	$(addprefix $(OBJ_DIR)/,$(GEN_S_OBJS2))
ifeq (YES,$(TEST_STAP))
ALL_C_OBJS3 =   $(addprefix $(OBJ_DIR)/,$(GEN_C_OBJS3))
ALL_S_OBJS3 =   $(addprefix $(OBJ_DIR)/,$(GEN_S_OBJS3))
endif
ALL_C_SRCS =	$(GEN_C_SRCS)
ALL_S_SRCS =	$(GEN_S_SRCS)






LOGFILE = log.txt
#all:$(TARGET).so
all:$(TARGET).elf 

$(ALL_C_OBJS1): $(OBJ_DIR)/%.o1 : %.c
	@echo      $(CC) $(CFLAGS) -DHMAC_AP_MODE  $(AFLAGS) -o $@ $<   
	@ $(CC) $(CFLAGS) -DHMAC_AP_MODE  $(AFLAGS) -o $@ $<  
	    
$(ALL_C_OBJS2): $(OBJ_DIR)/%.o2 : %.c
	@echo    $(CC) $(CFLAGS) -DHMAC_STA_MODE  $(AFLAGS) -o $@ $<   
	@ $(CC) $(CFLAGS)  -DHMAC_STA_MODE $(AFLAGS) -o $@ $<           
ifeq (YES,$(TEST_STAP))
$(ALL_C_OBJS3): $(OBJ_DIR)/%.o3 : %.c
	@echo    $(CC) $(CFLAGS) -DHMAC_STA2_MODE  $(AFLAGS) -o $@ $<   
	@ $(CC) $(CFLAGS)  -DHMAC_STA2_MODE $(AFLAGS) -o $@ $< 
endif
$(ALL_S_OBJS1): $(OBJ_DIR)/%.o1 : %.S
	#@echo compiling $<   
	@echo      $(CC) $(CFLAGS)  -DHMAC_AP_MODE $(AFLAGS) -o $@ $<       
	@ $(CC) $(CFLAGS) -DHMAC_AP_MODE $(AFLAGS)   -o $@ $<
	
$(ALL_S_OBJS2): $(OBJ_DIR)/%.o2 : %.S
	#@echo compiling $<
	@echo       $(CC) $(CFLAGS) -DHMAC_STA_MODE $(AFLAGS) -o $@ $<      
	@ $(CC) $(CFLAGS) -DHMAC_STA_MODE $(AFLAGS)   -o $@ $<
ifeq (YES,$(TEST_STAP))
$(ALL_S_OBJS3): $(OBJ_DIR)/%.o3 : %.S
	#@echo compiling $<
	@echo       $(CC) $(CFLAGS) -DHMAC_STA2_MODE $(AFLAGS) -o $@ $< 
	@ $(CC) $(CFLAGS) -DHMAC_STA2_MODE $(AFLAGS)   -o $@ $<
endif
#$(TARGET).so: $(OBJS)
#	$(CC) $(LDFLAGS) $(CEXTLDFLAGS) -o $(TARGET).so $(OBJS)

$(TARGET).elf: $(OBJS1) $(OBJS2) $(OBJS3)
	$(CC) $(LDFLAGS) -DHMAC_AP_MODE  $(OBJS1)  $(OBJS2) $(OBJS3) $(CEXTLDFLAGS) -o $(TARGET).elf $(LIB_VECTOR)
	$(OBJDUMP) -d -S $(TARGET).elf > $(TARGET).s
	$(OBJCOPY) $(OBJCOPYFLAGS) $(TARGET).elf $(TARGET).bin
	$(NM) $(NMFLAGS) $(TARGET).elf > $(TARGET).map
	


ifneq "$(word 1,$(MAKECMDGOALS))" "clean"
-include $(OBJS:.o=.d)
endif

.PHONY: clean
clean:
#	rm -rf $(TARGET).* *.o *.d *.map *.out *.so *.gcno *.gcda
	$(RM) $(OBJS)
