# KernelPatch KPM Makefile
# Adaptado del repo selinux_avc_bypass

ifndef KP_DIR
$(error KP_DIR is not set)
endif

ifndef ANDROID_NDK_HOME
$(error ANDROID_NDK_HOME is not set)
endif

TOOLCHAIN := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64
CROSS_COMPILE := $(TOOLCHAIN)/bin/aarch64-linux-android31-
CC := $(CROSS_COMPILE)clang

INCLUDES := -I$(KP_DIR)/kernel/include -I$(KP_DIR)/include
CFLAGS := -Wall -Wextra -Wno-unused-parameter -O2 -fno-PIC -fno-stack-protector
CFLAGS += -fno-builtin -ffreestanding -nostdinc -isystem $(TOOLCHAIN)/sysroot/usr/include

KPM_NAME := module_crc_bypass
KPM_VERSION := 1.0.0
KPM_OUT := $(KPM_NAME)_$(KPM_VERSION).kpm

OBJS := module_crc_bypass.o

all: $(KPM_OUT)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(KPM_OUT): $(OBJS)
	$(CC) $(CFLAGS) -r -o $@ $^

clean:
	rm -f *.o *.kpm

.PHONY: all clean
