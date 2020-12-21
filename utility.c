/*
    utility moudle
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

#include "utility.h"
#include "capstone/include/capstone/capstone.h"
#include "keystone/include/keystone/keystone.h"

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

PIMAGE_IMPORT_DESCRIPTOR GetImportDirectory(LPVOID pImageBase)
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

LPVOID GetIATFuncAddr(LPCSTR lpModuleName, LPCSTR lpFuncName)
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

LPVOID GetFuncFromIAT(LPCSTR lpModuleName, LPCSTR lpFuncName)
{
	return *(LPVOID*)GetIATFuncAddr(lpModuleName, lpFuncName);
}

void FreeRequiredAsmInfo(PCheatLibRequiredAsmInfo ptInfo)
{
	assert(ptInfo != NULL && ptInfo->pbOpCode != NULL);
	free(ptInfo->pbOpCode);
	ptInfo->pbOpCode = NULL;
	free(ptInfo);
	ptInfo = NULL;
}

PCheatLibRequiredAsmInfo GetRequiredAsmInfo(HANDLE hProcess, LPVOID pAddress)
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

void FreeAsmEncodeInfo(PCheatLibAsmEncodeInfo ptInfo)
{
	// 如果反汇编错误那么pbOpCode会是NULL所以不能断言pbOpCode
	assert(ptInfo != NULL);
	if(ptInfo->pbOpCode != NULL)
		ks_free(ptInfo->pbOpCode);
	free(ptInfo);
	ptInfo = NULL;
}

PCheatLibAsmEncodeInfo EncodeAsm(LPCSTR pszAsmCode, LPVOID pAddress)
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
