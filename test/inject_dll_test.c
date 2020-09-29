#include <stdio.h>
#include "cheatlib.h"

PFuncHookInfo func_hook_info = NULL;
PIATHookInfo iat_hook_info = NULL;


int func_hooked_printf(const char * restrict format, ...)
{
	// to do something here...
	return CallOrigFunc(func_hook_info, "This is Func hooked printf\n");
}

int iat_hooked_printf(const char * restrict format, ...)
{
	// to do something here...
	return ((int(*)(const char * restrict, ...))iat_hook_info->pFuncAddress)("This is IAT hooked printf\n");
}

BOOL WINAPI DllMain(
		HINSTANCE hinstDLL,  // handle to DLL module
		DWORD fdwReason,     // reason for calling function
		LPVOID lpReserved )  // reserved
{
	// Perform actions based on the reason for calling.
	switch( fdwReason ) 
	{ 
		case DLL_PROCESS_ATTACH:
			{
				// Initialize once for each new process.
				// Return FALSE to fail DLL load.
				printf("\ninject_dll_test: Dll Process Attach\n");
				printf("Successful inject dll\n");
				printf("Start Function Hook Test(printf Hook)\n");
				LPVOID addr = GetFuncFromIAT(NULL, "printf");
				func_hook_info = FuncHook(addr, (LPVOID)func_hooked_printf);
				if(func_hook_info == NULL){
					printf("function hook failed\n");
				}
				Sleep(2000);
				FuncUnhook(func_hook_info);
				printf("done\n\n");
				printf("Start IAT Hook Test(printf Hook)\n");
				iat_hook_info = IATHook(NULL, "printf", (LPVOID)iat_hooked_printf);
				Sleep(2000);
				IATUnhook(iat_hook_info);
				printf("done\n\n");
			}
			break;

		case DLL_THREAD_ATTACH:
			// Do thread-specific initialization.
			printf("inject_dll_test: Dll Thread Attach\n\n");
			break;

		case DLL_THREAD_DETACH:
			// Do thread-specific cleanup.
			printf("inject_dll_test: Dll Thread Detach\n\n");
			break;

		case DLL_PROCESS_DETACH:
			// Perform any necessary cleanup.
			printf("inject_dll_test: Dll Process Detach\n\n");
			break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
