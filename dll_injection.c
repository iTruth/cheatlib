/*
    dll injection moudle
    Copyright (C) 2020  iTruth

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
    USA
*/

#include <windows.h>

#include "cheatlib.h"
#include "dll_injection.h"

PDllInjectionInfo DllInjection(HANDLE hProcess, LPCSTR pszLibFile)
{
	assert(hProcess!=NULL && pszLibFile!=NULL);
	// 计算dll名称大小
	DWORD dwSize = (strlen(pszLibFile) + 1) * sizeof(char);
	// 在远程进程中为dll名称分配空间
	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
		return NULL;
	// 将DLL名称复制到远程进程地址空间
	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, dwSize, NULL);
	if (n == 0)
		return NULL;
	// 从Kernel32.dll获取LoadLibraryA地址
	PTHREAD_START_ROUTINE pfnThreadRtn =
		(PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
	if (pfnThreadRtn == NULL)
		return NULL;
	// 创建远程线程调用 LoadLibraryA(DLLPathname)
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
	if (hThread == NULL)
		return NULL;
	NtSetInformationThreadPtr NtSetInformationThread =
		(NtSetInformationThreadPtr)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtSetInformationThread");
	// 取消远程线程的调试后运行该线程
	NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);
	SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
	ResumeThread(hThread);
	PDllInjectionInfo ptInfo = (PDllInjectionInfo)malloc(sizeof(DllInjectionInfo));
	ptInfo->hProcess = hProcess;
	ptInfo->hThread = hThread;
	ptInfo->pszLibFileRemote = pszLibFileRemote;
	return ptInfo;
}

void DllOutjection(PDllInjectionInfo ptInfo)
{
	assert(ptInfo!=NULL);
	//等待远程线程结束
	WaitForSingleObject(ptInfo->hThread, INFINITE);
	if (ptInfo->pszLibFileRemote != NULL)
		VirtualFreeEx(ptInfo->hProcess, ptInfo->pszLibFileRemote, 0, MEM_RELEASE);
	if (ptInfo->hThread != NULL)
		CloseHandle(ptInfo->hThread);
	free(ptInfo);
	ptInfo = NULL;
}
