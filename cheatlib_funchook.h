/*
    cheatlib function hook moudle
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

#ifndef _H_CHEATLIB_DLLFUNC
#define _H_CHEATLIB_DLLFUNC

#include <windows.h>
#include <assert.h>
#include "cheatlib_utils.h"

typedef struct _FuncHookInfo{
	LPVOID pOrigFuncAddr;	// 代码源地址
	LPVOID pHookFuncAddr;	// Hook代码源地址
	BYTE *pbOpCode;			// 机器码用于恢复现场
	int last_return_value;	// CallOrigFunc源函数返回值(eax)
} FuncHookInfo, *PFuncHookInfo;

/* 说明:	将pOrigAddr处的函数直接替换为pHookAddr处的函数执行
 * 注意:	pOrigAddr和pHookAddr处的函数定义必须一致
 *			此函数一般写在dll中,注入到程序中将程序中的函数替换为dll中的
 * 参数:	pOrigAddr	- 源函数地址
 *			pHookAddr	- hook函数地址
 * 返回值:	PFuncHookInfo */
PFuncHookInfo FuncHook(LPVOID pOrigAddr, LPVOID pHookAddr)
{
	DWORD oldProtect;
	VirtualProtect(pOrigAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	PFuncHookInfo ptInfo = (PFuncHookInfo)malloc(sizeof(FuncHookInfo));
	if(ptInfo == NULL) return NULL;
	ptInfo->pOrigFuncAddr = pOrigAddr;
	ptInfo->pHookFuncAddr = pHookAddr;
	ptInfo->last_return_value = 0;
	ptInfo->pbOpCode = (BYTE*)malloc(sizeof(BYTE)*5);
	if(ptInfo->pbOpCode != NULL) memcpy(ptInfo->pbOpCode, pOrigAddr, 5);
	JmpBuilder((BYTE*)pOrigAddr, (DWORD)pHookAddr, (DWORD)pOrigAddr);
	VirtualProtect(pOrigAddr, 5, PAGE_EXECUTE, &oldProtect);
	return ptInfo;
}

/* 说明:	撤销函数钩子
 * 参数:	ptInfo	- FuncHook函数返回值
 * 返回值:	void */
void FuncUnhook(PFuncHookInfo ptInfo)
{
	assert(ptInfo != NULL && ptInfo->pbOpCode != NULL);
	DWORD oldProtect;
	VirtualProtect(ptInfo->pOrigFuncAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(ptInfo->pOrigFuncAddr, ptInfo->pbOpCode, 5);
	VirtualProtect(ptInfo->pOrigFuncAddr, 5, PAGE_EXECUTE, &oldProtect);
	free(ptInfo->pbOpCode);
	free(ptInfo);
}

/* 说明:	在Hook函数里调用源函数
 * 注意:	函数参数必须一致,否则会出现栈损
 *			不支持返回结构体的函数,否则可能会覆盖栈内的合法数据
 * 参数:	PFuncHookInfo ptInfo	- FuncHook函数的返回值
 *			...						- 函数参数 */
#define CallOrigFunc(ptInfo, ...) do{\
	DWORD oldProtect;\
	VirtualProtect(ptInfo->pOrigFuncAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);\
	memcpy(ptInfo->pOrigFuncAddr, ptInfo->pbOpCode, 5);\
	cheatlib_func_caller(ptInfo->pOrigFuncAddr, __VA_ARGS__);\
	__asm__ __volatile__("movl %%eax, %0;"::"m"(ptInfo->last_return_value): "eax");\
	JmpBuilder((BYTE*)ptInfo->pOrigFuncAddr, (DWORD)ptInfo->pHookFuncAddr, (DWORD)ptInfo->pOrigFuncAddr);\
	VirtualProtect(ptInfo->pOrigFuncAddr, 5, PAGE_EXECUTE, &oldProtect);\
} while(0);

void __attribute__((naked)) cheatlib_func_caller(LPVOID pOrigFuncAddr, ...)
{
	__asm__ __volatile__(
			"popl %%eax;"
			"popl %%ebx;"
			"pushl %%eax;"
			"jmp *%%ebx;"
			:);
}

/* 说明:	在Hook函数里调用源函数
 * 注意:	函数参数必须一致,否则会出现栈损
 *			只支持返回结构体的函数,否则会出现栈损
 * 参数:	PFuncHookInfo ptInfo	- FuncHook函数的返回值
 *			void *pSaveStructAddr	- 函数返回的结构体保存位置
 *			...						- 函数参数 */
#define CallOrigFunc_RetStruct(ptInfo, pSaveStructAddr, ...) do{\
	DWORD oldProtect;\
	VirtualProtect(ptInfo->pOrigFuncAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);\
	memcpy(ptInfo->pOrigFuncAddr, ptInfo->pbOpCode, 5);\
	cheatlib_ret_struct_func_caller(pSaveStructAddr, ptInfo->pOrigFuncAddr, __VA_ARGS__);\
	JmpBuilder((BYTE*)ptInfo->pOrigFuncAddr, (DWORD)ptInfo->pHookFuncAddr, (DWORD)ptInfo->pOrigFuncAddr);\
	VirtualProtect(ptInfo->pOrigFuncAddr, 5, PAGE_EXECUTE, &oldProtect);\
} while(0);

void __attribute__((naked)) cheatlib_ret_struct_func_caller(LPVOID pStructAddr, LPVOID pOrigFuncAddr, ...)
{
	__asm__ __volatile__(
			"popl %%eax;"
			"popl %%ebx;"
			"popl %%ecx;"
			"pushl %%ebx;"
			"pushl %%eax;"
			"jmp *%%ecx;"
			:);
}

#endif

