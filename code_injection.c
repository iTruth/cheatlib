/*
    code injection moudle
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

#include "cheatlib.h"
#include "code_injection.h"

void FreeCodeInjectionInfo(PCodeInjectionInfo ptInfo)
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

