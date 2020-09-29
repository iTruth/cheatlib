#include <stdio.h>
#include "cheatlib.h"

PDllInjectionInfo inject_dll_test_info = NULL;
PCodeInjectionInfo code_info = NULL;

int main()
{
	puts("Cheatlib v2.0 Test Program\n");
	puts("Getting target program handle...");
	HANDLE hTarget = GetHandleByTitle("Cheatlib Target");
	if(hTarget == NULL){
		puts("Failed to get target handle");
		return EXIT_FAILURE;
	}
	puts("done\n");
	puts("Start dll injection and function hook test");
	inject_dll_test_info = DllInjection(hTarget, "inject_dll_test.dll");
	if(inject_dll_test_info == NULL){
		printf("Dll injection Failed\n");
		return EXIT_FAILURE;
	}
	Sleep(1000);
	puts("Start dll Outjection and function unhook test");
	DllOutjection(inject_dll_test_info);
	puts("done\n");

	puts("Start code injection test");
#ifdef CHEATLIB_TARGET_X64
	code_info = CodeInjection(hTarget, (LPVOID)0x40159a,
			"add dword ptr ss:[rbp-0x4], 0xff;"
			"push 0x401574;"
			"ret;"
			);
#else
	code_info = CodeInjection(hTarget, (LPVOID)0x40156a,
			"add dword ptr ss:[ebp-0xC], 0xff;"
			"push 0x40153E;"
			"ret;"
			);
#endif
	if(code_info == NULL){
		printf("Code Injection Failed\n");
		return EXIT_FAILURE;
	}
	Sleep(2000);
	puts("Start code outjection test");
	CodeOutjection(code_info);
	puts("done\n");

	return EXIT_SUCCESS;
}
