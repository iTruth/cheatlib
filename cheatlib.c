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
#include "capstone/include/capstone/capstone.h"
#include "keystone/include/keystone/keystone.h"
#include "cheatlib.h"

typedef enum _THREADINFOCLASS { ThreadHideFromDebugger = 17 } THREADINFOCLASS;

typedef NTSTATUS (*NtSetInformationThreadPtr)(HANDLE threadHandle,
		THREADINFOCLASS threadInformationClass,
		PVOID threadInformation,
		ULONG threadInformationLength);

#ifdef CHEATLIB_TARGET_X64

void JmpBuilder_x64(BYTE *pCmdOutput, LPVOID dwTargetAddr)
{
	assert(pCmdOutput != NULL);
	int i = 0;
	pCmdOutput[i++] = 0x68;
	*(DWORD*)&pCmdOutput[i] = (DWORD)((int64_t)dwTargetAddr & 0xffffffff);
	i+=4;
	*(DWORD*)&pCmdOutput[i] = (DWORD)0x042444c7;
	i+=4;
	*(DWORD*)&pCmdOutput[i] = (DWORD)((int64_t)dwTargetAddr >> 32);
	i+=4;
	pCmdOutput[i] = 0xC3;
}

int64_t __attribute__((naked)) cheatlib_func_caller_x64(LPVOID pOrigFuncAddr, ...)
{
	__asm__ __volatile__(
			"movapd %%xmm0, %%xmm3;"
			"movq (%%rsp), %%rax;"
			"movq %%rax, 8(%%rsp);"
			"movq %%rdx, %%rcx;"
			"movq %%r8, %%rdx;"
			"movq %%r9, %%r8;"
			"movq 0x28(%%rsp), %%r9;"
			"movq %0, %%rax;"
			"movq %%rax, (%%rsp);"
			"ret;"
			:"=m"(pOrigFuncAddr)
			);
}

#else

void IntToByte(int i, BYTE* bytes) 
{
	assert(bytes != NULL);
	bytes[0] = (byte) (0xff & i);
	bytes[1] = (byte) ((0xff00 & i) >> 8);
	bytes[2] = (byte) ((0xff0000 & i) >> 16);
	bytes[3] = (byte) ((0xff000000 & i) >> 24);
}

void JmpBuilder(BYTE *pCmdOutput, LPVOID dwTargetAddr, LPVOID dwCurrentAddr)
{
	assert(pCmdOutput != NULL);
	pCmdOutput[0] = 0xE9;
	DWORD jmpOffset = (DWORD)dwTargetAddr - (DWORD)dwCurrentAddr - 5;
	IntToByte(jmpOffset, pCmdOutput+1);
}

void __attribute__((naked)) cheatlib_func_caller(LPVOID pOrigFuncAddr, ...)
{
	__asm__ __volatile__(
			"popl %%eax;"
			"popl %%ebx;"
			"pushl %%eax;"
			"jmp *%%ebx;"
			:);
}

#endif

static PIMAGE_IMPORT_DESCRIPTOR GetImportDirectory(LPVOID pImageBase)
{
#ifdef CHEATLIB_TARGET_X64
	int64_t ImageBase = (int64_t)pImageBase;
#else
	int32_t ImageBase = (int32_t)pImageBase;
#endif
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(ImageBase + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeader->FileHeader;
#ifdef CHEATLIB_TARGET_X64
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((int64_t)pFileHeader + sizeof(IMAGE_FILE_HEADER));
#else
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((int32_t)pFileHeader + sizeof(IMAGE_FILE_HEADER));
#endif
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionalHeader->DataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(ImageBase + (pDataDirectory + 1)->VirtualAddress);
	return pImportDirectory;
}

static LPVOID GetIATFuncAddr(LPCSTR lpModuleName, LPCSTR lpFuncName)
{
#ifdef CHEATLIB_TARGET_X64
	int64_t ImageBase = (int64_t)GetModuleHandle(lpModuleName);
#else
	int32_t ImageBase = (int32_t)GetModuleHandle(lpModuleName);
#endif
	PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = GetImportDirectory((LPVOID)ImageBase);
	while (pImportDirectory->FirstThunk != 0 && pImportDirectory->OriginalFirstThunk != 0)
	{
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(ImageBase + pImportDirectory->FirstThunk);
		PIMAGE_THUNK_DATA pThunkName = (PIMAGE_THUNK_DATA)(ImageBase + pImportDirectory->OriginalFirstThunk);
#ifdef CHEATLIB_TARGET_X64
		while(*(int64_t*)pThunk)
#else
		while(*(int32_t*)pThunk)
#endif
		{
			PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pThunkName->u1.AddressOfData);
#ifdef CHEATLIB_TARGET_X64
			char *szIATFuncName = (char*)(pName->Name + (int64_t)ImageBase);
#else
			char *szIATFuncName = (char*)(pName->Name + (int32_t)ImageBase);
#endif
			LPVOID pFuncAddr = (LPVOID)&pThunk->u1.Function;

			if (strcmp(lpFuncName, szIATFuncName) == 0) {
				return pFuncAddr;
			}
			++pThunk;
			++pThunkName;
		}
		++pImportDirectory;
	}
	return NULL;
}

HANDLE GetHandleByTitle(LPCSTR pszTitle)
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

LPVOID GetFuncFromIAT(LPCSTR lpModuleName, LPCSTR lpFuncName)
{
	return *(LPVOID*)GetIATFuncAddr(lpModuleName, lpFuncName);
}

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
	ReadProcessMemory(hProcess, pAddress, (LPVOID)ptInfo->pbOpCode, nOpCodeSize, NULL);

	csh handle;  // 反汇编引擎句柄
	cs_err err; // 错误信息
	cs_insn* pInsn; // 保存反汇编得到的指令的缓冲区首地址
	unsigned int count = 0; // 保存得到的反汇编的指令条数

	//初始化反汇编器句柄,(x86_64架构)
	err = cs_open(CS_ARCH_X86 ,  /*x86指令集*/
#ifdef CHEATLIB_TARGET_X64
			CS_MODE_64 , /*使用64位模式解析opcode*/
#else
			CS_MODE_32 , /*使用32位模式解析opcode*/
#endif
			&handle /*输出的反汇编句柄*/
			);

	if(err != CS_ERR_OK)
	{
		FreeRequiredAsmInfo(ptInfo);
		return NULL;
	}

	// 开始反汇编.
	// 函数会返回总共得到了几条汇编指令
	count = cs_disasm(handle ,/*反汇编器句柄,从cs_open函数得到*/
			ptInfo->pbOpCode,/*需要反汇编的opcode的缓冲区首地址*/
			nOpCodeSize , /*opcode的字节数*/
#ifdef CHEATLIB_TARGET_X64
			(uint64_t)pAddress, /*opcode的所在的内存地址*/
#else
			(uint32_t)pAddress, /*opcode的所在的内存地址*/
#endif
			0, /*需要反汇编的指令条数,如果是0,则反汇编出全部*/
			&pInsn/*反汇编输出*/
			);

	int nCount = 0;
	for(size_t i = 0; i < count; ++i) {
#ifdef CHEATLIB_TARGET_X64
		nCount = (int)((uint64_t)pInsn[i].address - (uint64_t)pAddress);
#else
		nCount = (int)((uint32_t)pInsn[i].address - (uint32_t)pAddress);
#endif
		if(i == 1){
			ptInfo->iFirstCmdSize = nCount;
		}
		if(nCount >= JMP_SIZE){
			break;
		}
	}
	cs_free(pInsn , count);
	cs_close(&handle);
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

static PCheatLibAsmEncodeInfo EncodeAsm(LPCSTR pszAsmCode, LPVOID pAddress)
{
	// 根据pszAsmCode编译汇编代码
	ks_engine *pengine = NULL;

#ifdef CHEATLIB_TARGET_X64
	if(KS_ERR_OK != ks_open(KS_ARCH_X86 , KS_MODE_64 , &pengine)){
		return NULL;
	}
#else
	if(KS_ERR_OK != ks_open(KS_ARCH_X86 , KS_MODE_32 , &pengine)){
		return NULL;
	}
#endif
	PCheatLibAsmEncodeInfo ptInfo = (PCheatLibAsmEncodeInfo)malloc(sizeof(CheatLibAsmEncodeInfo));
	ptInfo->pszAsmCode = pszAsmCode;
#ifdef CHEATLIB_TARGET_X64
	ptInfo->u64Address = (uint64_t)pAddress;
#else
	ptInfo->u64Address = (uint32_t)pAddress;
#endif
	int nRet = 0; // 保存函数的返回值，用于判断函数是否执行成功
	nRet = ks_asm(pengine, /* 汇编引擎句柄，通过ks_open函数得到*/
			pszAsmCode, /*要转换的汇编指令*/
#ifdef CHEATLIB_TARGET_X64
			(uint64_t)pAddress, /*汇编指令所在的地址*/
#else
			(uint32_t)pAddress, /*汇编指令所在的地址*/
#endif
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

PCodeInjectionInfo CodeInjection(HANDLE hProcess, LPVOID pAddress, LPCSTR pszAsmCode)
{
	// 在pAddress处收集必要的信息
	PCheatLibRequiredAsmInfo ptRequiredAsmInfo = GetRequiredAsmInfo(hProcess, pAddress);
	PCodeInjectionInfo ptCodeInjectionInfo = (PCodeInjectionInfo)malloc(sizeof(CodeInjectionInfo));
	ptCodeInjectionInfo->hProcess = hProcess;
	ptCodeInjectionInfo->pOrigAddr = pAddress;
	ptCodeInjectionInfo->ptRequiredAsmInfo = ptRequiredAsmInfo;
	SIZE_T WrittenLen = 0;

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
	int nCodeSize = strlen(pszAsmCode)+JMP_SIZE;
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
#ifdef CHEATLIB_TARGET_X64
	JmpBuilder_x64(exeCode+ptAsmCodeInfo->nOpCodeSize,
			pAddress+ptRequiredAsmInfo->iRequiredSize);
#else
	JmpBuilder(exeCode+ptAsmCodeInfo->nOpCodeSize,
			(LPVOID)pAddress+ptRequiredAsmInfo->iRequiredSize,
			(LPVOID)virAddr+ptAsmCodeInfo->nOpCodeSize);
#endif
	// 把构建好的代码写入刚刚申请的空间中
	WriteProcessMemory(hProcess, (LPVOID)virAddr, exeCode, nCodeSize, &WrittenLen);
	free(exeCode);
	exeCode = NULL;
	FreeAsmEncodeInfo(ptAsmCodeInfo);

	// 开始构造注入点跳转指令
	BYTE *jmpCode = (BYTE*)malloc(sizeof(BYTE)*ptRequiredAsmInfo->iRequiredSize);
	memset(jmpCode, 0x90, ptRequiredAsmInfo->iRequiredSize);
#ifdef CHEATLIB_TARGET_X64
	JmpBuilder_x64(jmpCode, virAddr);
#else
	JmpBuilder(jmpCode, (LPVOID)virAddr, (LPVOID)pAddress);
#endif
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
	SIZE_T WrittenLen = 0;
	// 恢复原始代码
	WriteProcessMemory(ptInfo->hProcess,
			ptInfo->pOrigAddr,
			ptInfo->ptRequiredAsmInfo->pbOpCode,
			ptInfo->ptRequiredAsmInfo->iRequiredSize,
			&WrittenLen);
	FreeCodeInjectionInfo(ptInfo);
}

PFuncHookInfo FuncHook(LPVOID pOrigAddr, LPVOID pHookFuncAddr)
{
	DWORD oldProtect;
	VirtualProtect(pOrigAddr, JMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
	PFuncHookInfo ptInfo = (PFuncHookInfo)malloc(sizeof(FuncHookInfo));
	if(ptInfo == NULL) return NULL;
	ptInfo->pOrigFuncAddr = pOrigAddr;
	ptInfo->pHookFuncAddr = pHookFuncAddr;
	ptInfo->last_return_value = 0;
	ptInfo->pbOpCode = (BYTE*)malloc(sizeof(BYTE)*JMP_SIZE);
	if(ptInfo->pbOpCode != NULL) memcpy(ptInfo->pbOpCode, pOrigAddr, JMP_SIZE);
#ifdef CHEATLIB_TARGET_X64
	JmpBuilder_x64((BYTE*)pOrigAddr, pHookFuncAddr);
#else
	JmpBuilder((BYTE*)pOrigAddr, (LPVOID)pHookFuncAddr, (LPVOID)pOrigAddr);
#endif
	VirtualProtect(pOrigAddr, JMP_SIZE, PAGE_EXECUTE, &oldProtect);
	return ptInfo;
}

void FuncUnhook(PFuncHookInfo ptInfo)
{
	assert(ptInfo != NULL && ptInfo->pbOpCode != NULL);
	DWORD oldProtect;
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(ptInfo->pOrigFuncAddr, ptInfo->pbOpCode, JMP_SIZE);
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE, &oldProtect);
	free(ptInfo->pbOpCode);
	free(ptInfo);
}

PIATHookInfo IATHook(LPCSTR lpModuleName, LPCSTR lpFuncName, LPVOID pHookFuncAddr)
{
	DWORD dwOldProtect;
	LPVOID pIATAddr = GetIATFuncAddr(lpModuleName, lpFuncName);
	LPVOID pFuncAddr = *(LPVOID*)pIATAddr;
	VirtualProtect(pIATAddr, 
			sizeof(LPVOID), 
			PAGE_EXECUTE_READWRITE, 
			&dwOldProtect);

	*(LPVOID*)pIATAddr = (LPVOID)pHookFuncAddr;
	VirtualProtect(pIATAddr, 
			sizeof(LPVOID), 
			dwOldProtect, 
			&dwOldProtect);
	PIATHookInfo ptInfo = (PIATHookInfo)malloc(sizeof(IATHookInfo));
	ptInfo->pIATAddress = pIATAddr;
	ptInfo->pFuncAddress = pFuncAddr;
	return ptInfo;
	return NULL;
}

void IATUnhook(PIATHookInfo ptInfo)
{
	assert(ptInfo != NULL);
	DWORD dwOldProtect;
	LPVOID pIATAddr = ptInfo->pIATAddress;
	VirtualProtect(pIATAddr, 
			sizeof(LPVOID), 
			PAGE_EXECUTE_READWRITE, 
			&dwOldProtect);
	*(void**)pIATAddr = ptInfo->pFuncAddress;
	VirtualProtect(pIATAddr, 
			sizeof(LPVOID), 
			dwOldProtect, 
			&dwOldProtect);
	free(ptInfo);
}

