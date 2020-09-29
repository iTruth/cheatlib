#Copyright (C). All rights reserved

CC := GCC
CFLAGES := -std=c11 -Wall -D NDEBUG
RM := del

x32: target.c inject_dll_test.c cheatlib_test.c
	$(CC) $(CFLAGES) target.c -o target.exe -m32
	$(CC) $(CFLAGES) -shared cheatlib.dll inject_dll_test.c -o inject_dll_test.dll -m32
	$(CC) $(CFLAGES) cheatlib.dll cheatlib_test.c -o cheatlib_test.exe -m32

x64: target.c inject_dll_test.c cheatlib_test.c
	$(CC) $(CFLAGES) target.c -o target.exe -m64
	$(CC) $(CFLAGES) -shared cheatlib.dll inject_dll_test.c -o inject_dll_test.dll -m64 -D CHEATLIB_TARGET_X64
	$(CC) $(CFLAGES) cheatlib.dll cheatlib_test.c -o cheatlib_test.exe -m64 -D CHEATLIB_TARGET_X64

.PHONY: clean
clean:
	-$(RM) *.exe
	-$(RM) *.dll
