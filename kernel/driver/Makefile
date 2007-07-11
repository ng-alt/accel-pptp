TARGET = pptp
OBJS = pptp.o  
MDIR = net

EXTRA_CFLAGS = -DEXPORT_SYMTAB
CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
PWD = $(shell pwd)
DEST = /lib/modules/$(CURRENT)/kernel/$(MDIR)
KERNEL_INCLUDE := /lib/modules/$(CURRENT)/build/include

obj-m      := $(TARGET).o
#$(TARGET)-objs      := $(OBJS)

ifneq (,$(findstring 2.4.,$(CURRENT)))
CC = gcc -c

CFLAGS := -Wall -fno-strength-reduce -fomit-frame-pointer -O2 -fno-common 
CFLAGS := $(CFLAGS) -D__KERNEL__ -DMODULE -I$(KERNEL_INCLUDE) -DMOD_VERSIONS -include $(KERNEL_INCLUDE)/linux/modversions.h
CFLAGS := $(CFLAGS) -Wall -Wno-unused -Wno-multichar
all: $(SOURCES)
	ld  -r -o pptp_mod.o $(SOURCES)
else
default:
	make -C $(KDIR) SUBDIRS=$(PWD) modules
endif

$(TARGET).o: $(OBJS)
	$(LD) $(LD_RFLAG) -r -o $@ $(OBJS)

ifneq (,$(findstring 2.4.,$(CURRENT)))
install:
	su -c "cp -v $(TARGET)_mod.o $(DEST)/$(TARGET).o && /sbin/depmod -a"
else
install:
	su -c "cp -v $(TARGET).ko $(DEST) && /sbin/depmod -a"
endif

clean:
	-rm -f *.o *.ko .*.cmd .*.flags *.mod.c

ifneq (,$(findstring 2.6.,$(CURRENT)))
-include $(KDIR)/Rules.make
endif
