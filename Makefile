#Copyright (C). All rights reserved

CC := gcc
AR := ar
CFLAGES := -std=c11 -Wall -D NDEBUG
RM := del

#The name of the program
TARGET_NAME := cheatlib

dlls := capstone.dll keystone.dll

x32: $(dlls) $(TARGET_NAME).c
	$(CC) $(CFLAGES) -shared -m32 $^ -o $(TARGET_NAME).dll

x64: $(dlls) $(TARGET_NAME).c
	$(CC) $(CFLAGES) -shared -m64 $^ -o $(TARGET_NAME).dll -D CHEATLIB_TARGET_X64

x32static: $(libs) $(TARGET_NAME).c
	$(CC) $(CFLAGES) -static -m32 $(TARGET_NAME).c -c
	$(AR) r cheatlib.lib cheatlib.o


x64static: $(libs) $(TARGET_NAME).c
	$(CC) $(CFLAGES) -static -m64 $(TARGET_NAME).c -c -D CHEATLIB_TARGET_X64
	$(AR) r cheatlib.lib cheatlib.o

.PHONY: clean
clean:
	-$(RM) *.o
	-$(RM) *.d

