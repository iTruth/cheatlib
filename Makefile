#Copyright (C). All rights reserved

CC := gcc
AR := ar
CFLAGES := -std=c11 -Wall -D NDEBUG
RM := del

#The name of the program
TARGET_NAME := cheatlib

dlls := capstone.dll keystone.dll
srcs := $(wildcard *.c)
objs := $(patsubst %.c,%.o, $(srcs))

x32: $(dlls) $(srcs)
	$(CC) $(CFLAGES) -c -m32 $(srcs)
	$(CC) $(CFLAGES) -shared -m32 $(objs) $(dlls) -o $(TARGET_NAME).dll

x64: $(dlls) $(srcs)
	$(CC) $(CFLAGES) -c -m64 $(srcs) -D CHEATLIB_TARGET_X64
	$(CC) $(CFLAGES) -shared -m64 $(objs) $(dlls) -o $(TARGET_NAME).dll -D CHEATLIB_TARGET_X64

x32s: $(srcs)
	$(CC) $(CFLAGES) -static -c -m32 $(srcs)
	$(AR) r cheatlib.lib $(objs)

x64s: $(srcs)
	$(CC) $(CFLAGES) -static -c -m64 $(srcs) -D CHEATLIB_TARGET_X64
	$(AR) r cheatlib.lib $(objs)

.PHONY: clean
clean:
	-$(RM) *.o

