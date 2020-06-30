/*
    cheatlib main moudle
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
#include <string.h>
#include <Psapi.h>
#include "beaengine/include/beaengine/BeaEngine.h"
#include "keystone/include/keystone/keystone.h"
#include "cheatlib.h"
#include "util.h"

typedef enum _THREADINFOCLASS { ThreadHideFromDebugger = 17 } THREADINFOCLASS;

typedef NTSTATUS (*NtSetInformationThreadPtr)(HANDLE threadHandle,
		THREADINFOCLASS threadInformationClass,
		PVOID threadInformation,
		ULONG threadInformationLength);

HANDLE GetHandleByTitle(const char *pszTitle)
{
	assert(pszTitle!=NULL);
	HWND hWnd = FindWindow(NULL, pszTitle);
	if(hWnd == 0){
		return NULL;
	}
	DWORD dwPid = 0;
	GetWindowThreadProcessId(hWnd, &dwPid);
	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
}

PDllInjectionInfo DllInjection(HANDLE hProcess, const char *pszLibFile)
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

static void FreeRequiredAsmInfo(PCheatLibRequiredAsmInfo ptInfo)
{
	assert(ptInfo != NULL && ptInfo->pbOpCode != NULL);
	free(ptInfo->pbOpCode);
	ptInfo->pbOpCode = NULL;
	free(ptInfo);
	ptInfo = NULL;
}

static PCheatLibRequiredAsmInfo GetRequiredAsmInfo(HANDLE hProcess, LPVOID pAddress)
{
	PCheatLibRequiredAsmInfo ptInfo = (PCheatLibRequiredAsmInfo)malloc(sizeof(CheatLibRequiredAsmInfo));
	int nOpCodeSize = 32; // opcode的字节数
	ptInfo->pbOpCode = (BYTE*)malloc(sizeof(BYTE)*nOpCodeSize);
	DISASM disAsm;
	memset(&disAsm, 0, sizeof disAsm);
	ReadProcessMemory(hProcess, pAddress, (LPVOID)ptInfo->pbOpCode, nOpCodeSize, NULL);
	disAsm.EIP = (UIntPtr)ptInfo->pbOpCode; // 保存opcode的缓冲区首地址
	disAsm.VirtualAddr = (int)pAddress; // pbOpCode 指令的地址
	disAsm.Archi = 32; // 32位
	disAsm.Options = 0x0; // masm 汇编指令格式
	int nCount = 0;// 用于记录在循环当中，反汇编了多少个字节
	int nLen = 0 ; // 用于记录当前的汇编指令的字节数
	// 调用Disasm()进行反汇编来获取指令长度
	while(nCount < nOpCodeSize)
	{
		nLen = Disasm(&disAsm); // 每次只反汇编一条汇编指令， 并且返回当前得到的汇编指令的长度
		if(nCount == 0){ // 获取第一条汇编指令大小
			ptInfo->iFirstCmdSize = nLen;
		}
		nCount += nLen; // 累加已经反汇编的字节数
		disAsm.EIP += nLen; // 定位到下一条汇编指令
		disAsm.VirtualAddr += nLen; // 设置到下一条汇编指令的地址
		if(nCount>=5)break; // 如果已经反汇编的字节数超过了jmp指令的字节数就不用继续分析了
	}
	ptInfo->iRequiredSize = nCount;
	return ptInfo;
}

static void FreeAsmEncodeInfo(PCheatLibAsmEncodeInfo ptInfo)
{
	// 如果反汇编错误那么pbOpCode会是NULL所以不能断言pbOpCode
	assert(ptInfo != NULL);
	if(ptInfo->pbOpCode != NULL)
		ks_free(ptInfo->pbOpCode);
	free(ptInfo);
	ptInfo = NULL;
}

static PCheatLibAsmEncodeInfo EncodeAsm(const char *pszAsmCode, LPVOID pAddress)
{
	// 根据pszAsmCode编译汇编代码
	ks_engine *pengine = NULL;
	if(KS_ERR_OK != ks_open(KS_ARCH_X86 , KS_MODE_32 , &pengine)){
		return NULL;
	}
	PCheatLibAsmEncodeInfo ptInfo = (PCheatLibAsmEncodeInfo)malloc(sizeof(CheatLibAsmEncodeInfo));
	ptInfo->pszAsmCode = pszAsmCode;
	ptInfo->u64Address = (DWORD)pAddress;
	int nRet = 0; // 保存函数的返回值，用于判断函数是否执行成功
	nRet = ks_asm(pengine, /* 汇编引擎句柄，通过ks_open函数得到*/
			pszAsmCode, /*要转换的汇编指令*/
			(DWORD)pAddress, /*汇编指令所在的地址*/
			&ptInfo->pbOpCode,/*输出的opcode*/
			&ptInfo->nOpCodeSize,/*输出的opcode的字节数*/
			&ptInfo->nCmdCount /*输出成功汇编的指令的条数*/
			);
	// 返回值等于-1时反汇编错误
	if(nRet == -1) {
		FreeAsmEncodeInfo(ptInfo);
		return NULL;
	}
	// 关闭句柄
	ks_close(pengine);
	return ptInfo;
}

static void FreeCodeInjectionInfo(PCodeInjectionInfo ptInfo)
{
	assert(ptInfo != NULL);
	// 释放代码空间
	if(ptInfo->pVirAddr != NULL){
		VirtualFreeEx(ptInfo->hProcess, ptInfo->pVirAddr, 0, MEM_RELEASE);
	}
	FreeRequiredAsmInfo(ptInfo->ptRequiredAsmInfo);
	free(ptInfo);
	ptInfo = NULL;
}

PCodeInjectionInfo CodeInjection(HANDLE hProcess, LPVOID pAddress, const char *pszAsmCode)
{
	// 在pAddress处收集必要的信息
	PCheatLibRequiredAsmInfo ptRequiredAsmInfo = GetRequiredAsmInfo(hProcess, pAddress);
	PCodeInjectionInfo ptCodeInjectionInfo = (PCodeInjectionInfo)malloc(sizeof(CodeInjectionInfo));
	ptCodeInjectionInfo->hProcess = hProcess;
	ptCodeInjectionInfo->pOrigAddr = pAddress;
	ptCodeInjectionInfo->ptRequiredAsmInfo = ptRequiredAsmInfo;
	DWORD WrittenLen = 0;

	// 如果pszAsmCode是空字符串或NULL就使用nop填充该指令
	if(pszAsmCode == NULL || strlen(pszAsmCode) == 0){
		ptCodeInjectionInfo->pVirAddr = NULL;
		BYTE *nopCode = (BYTE*)malloc(sizeof(BYTE)*ptRequiredAsmInfo->iFirstCmdSize);
		memset(nopCode, 0x90, ptRequiredAsmInfo->iFirstCmdSize);
		// 写入空指令
		WriteProcessMemory(hProcess,
				(LPVOID)pAddress,
				nopCode,
				ptRequiredAsmInfo->iFirstCmdSize,
				&WrittenLen);
		free(nopCode);
		nopCode = NULL;
		return ptCodeInjectionInfo;
	}

	// 开始构造我们自己的代码
	// 我们不知道pszAsmCode中的汇编指令在函数申请的空间中会生成多少机器码
	// 但使用这种方式计算出来的大小一定不会小于实际所需大小
	int nCodeSize = strlen(pszAsmCode)+5;
	// 在远程进程申请空间用于存放我们自己的代码
	LPVOID virAddr = (PWSTR)VirtualAllocEx(hProcess,
			NULL,
			nCodeSize,
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE);
	ptCodeInjectionInfo->pVirAddr = virAddr;
	// 汇编pszAsmCode,需要virAddr来正确计算指令中的偏移
	PCheatLibAsmEncodeInfo ptAsmCodeInfo = EncodeAsm(pszAsmCode, virAddr);
	// 大概率是pszAsmCode有问题导致的
	if(ptAsmCodeInfo == NULL){
		FreeCodeInjectionInfo(ptCodeInjectionInfo);
		return NULL;
	}
	BYTE *exeCode = (BYTE*)malloc(sizeof(BYTE)*(nCodeSize));
	// 先使用nop填充
	memset(exeCode, 0x90, nCodeSize);
	// 将生成的汇编代码拷贝到exeCode中
	memcpy(exeCode, ptAsmCodeInfo->pbOpCode, ptAsmCodeInfo->nOpCodeSize);
	// 构建跳转指令
	JmpBuilder(exeCode+ptAsmCodeInfo->nOpCodeSize,
			(DWORD)pAddress+ptRequiredAsmInfo->iRequiredSize,
			(DWORD)virAddr+ptAsmCodeInfo->nOpCodeSize);
	// 把构建好的代码写入刚刚申请的空间中
	WriteProcessMemory(hProcess, (LPVOID)virAddr, exeCode, nCodeSize, &WrittenLen);
	free(exeCode);
	exeCode = NULL;
	FreeAsmEncodeInfo(ptAsmCodeInfo);

	// 开始构造注入点跳转指令
	BYTE *jmpCode = (BYTE*)malloc(sizeof(BYTE)*ptRequiredAsmInfo->iRequiredSize);
	memset(jmpCode, 0x90, ptRequiredAsmInfo->iRequiredSize);
	JmpBuilder(jmpCode, (DWORD)virAddr, (DWORD)pAddress);
	// 向注入点写入跳转指令
	WriteProcessMemory(hProcess,
			(LPVOID)pAddress,
			jmpCode,
			ptRequiredAsmInfo->iRequiredSize,
			&WrittenLen);
	free(jmpCode);
	jmpCode = NULL;
	return ptCodeInjectionInfo;
}

void CodeOutjection(PCodeInjectionInfo ptInfo)
{
	assert(ptInfo != NULL && ptInfo->ptRequiredAsmInfo != NULL);
	DWORD WrittenLen = 0;
	// 恢复原始代码
	WriteProcessMemory(ptInfo->hProcess,
			ptInfo->pOrigAddr,
			ptInfo->ptRequiredAsmInfo->pbOpCode,
			ptInfo->ptRequiredAsmInfo->iRequiredSize,
			&WrittenLen);
	FreeCodeInjectionInfo(ptInfo);
}

