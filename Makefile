#Copyright (C). All rights reserved

CC := gcc
CFLAGES := -Wall -shared
RM := del
MKDIR := mkdir

#The name of the program
TARGET_NAME := cheatlib

dlls := BeaEngine_d_l.dll keystone.dll

#main target
$(TARGET_NAME).dll: $(dlls)
	$(CC) $(CFLAGES) $^ -o $@ -I beaengine/include/

.PHONY: clean
clean:
	-$(RM) *.o
	-$(RM) *.d

