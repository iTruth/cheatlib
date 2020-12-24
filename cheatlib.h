/*
    cheatlib header
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

#ifndef _H_CHEATLIB
#define _H_CHEATLIB

#include <stdint.h>
#include <assert.h>
#include <windows.h>

typedef struct _CheatLibRequiredAsmInfo{
	BYTE *pbOpCode;     // 机器码
	int iRequiredSize;  // 跳转指令覆盖的指令总大小
	int iFirstCmdSize;  // 注入点第一条指令的大小
} CheatLibRequiredAsmInfo, *PCheatLibRequiredAsmInfo;

typedef struct _CheatLibAsmEncodeInfo{
	LPCSTR pszAsmCode;     // 汇编代码
	uint64_t u64Address;        // 汇编代码的所在地址
	unsigned char *pbOpCode;    // 机器码
	size_t nOpCodeSize;         // 机器码长度
	size_t nCmdCount;           // 汇编指令数量
} CheatLibAsmEncodeInfo, *PCheatLibAsmEncodeInfo;

typedef struct _DllInjectionInfo{
	HANDLE hProcess;            // 进程句柄
	HANDLE hThread;             // 远程线程句柄
	LPVOID pszLibFileRemote;    // dll文件路径字符串首地址
} DllInjectionInfo, *PDllInjectionInfo;

typedef struct _CodeInjectionInfo{
	HANDLE hProcess;                            // 进程句柄
	LPVOID pOrigAddr;                           // 代码源地址
	LPVOID pVirAddr;                            // 申请的远程进程空间的首地址
	PCheatLibRequiredAsmInfo ptRequiredAsmInfo; // 记录原始代码信息用于恢复
} CodeInjectionInfo, *PCodeInjectionInfo;

#ifdef CHEATLIB_TARGET_X64
typedef struct _ShadowSpace{
	int64_t shadow_a;
	int64_t shadow_b;
	int64_t shadow_c;
	int64_t shadow_d;
} ShadowSpace, *PShadowSpace;
#define JMP_SIZE 14
#else
#define JMP_SIZE 5
#endif

typedef struct _FuncHookInfo{
	LPVOID pOrigFuncAddr;       // 代码源地址
	LPVOID pHookFuncAddr;       // Hook代码源地址
	BYTE *pbOpCode;             // 机器码用于恢复现场
#ifdef CHEATLIB_TARGET_X64
	int64_t last_return_value;      // CallOrigFunc源函数返回值(rax)
	int64_t last_return_2nd_value;  // 在返回值是有两个整型值的结构体时这里保存第二个元素(rdx)
#else
	int32_t last_return_value;      // CallOrigFunc源函数返回值(eax)
	int32_t last_return_2nd_value;  // 在返回值是有两个整型值的结构体时这里保存第二个元素(edx)
#endif
} FuncHookInfo, *PFuncHookInfo;

typedef struct _IATHookInfo{
	LPVOID pIATAddress;    // IAT地址
	LPVOID pFuncAddress;   // 函数地址
} IATHookInfo, *PIATHookInfo;

#include "code_injection.h"
#include "dll_injection.h"
#include "func_hook.h"
#include "iat_hook.h"
#include "utility.h"

/* 说明:    根据窗口标题获取进程句柄
 * 参数:    pszTitle  - 窗口标题
 * 返回值:  成功找到该窗口返回进程句柄
 *          没有找到该窗口返回NULL */
HANDLE GetHandleByTitle(LPCSTR pszTitle);

#ifdef CHEATLIB_TARGET_X64
/* 说明:  在Hook函数里调用源函数
 * 注意:  函数参数必须一致,否则会出现栈损
 *        不支持返回结构体的函数,否则可能会覆盖栈内的合法数据
 * 参数:  PFuncHookInfo ptInfo  - FuncHook函数的返回值
 *        ...                   - 函数参数 */
#define CallOrigFunc(ptInfo, ...) ({ \
	DWORD oldProtect; \
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect); \
	memcpy(ptInfo->pOrigFuncAddr, ptInfo->pbOpCode, JMP_SIZE); \
	ShadowSpace shadow_space_backup;\
	__asm__ __volatile__( \
			"subq $0x8, %%rsp;" \
			"movq 0x10(%%rbp), %%rax;" \
			"movq %%rax, %0;" \
			"movq 0x18(%%rbp), %%rax;" \
			"movq %%rax, %1;" \
			"movq 0x20(%%rbp), %%rax;" \
			"movq %%rax, %2;" \
			"movq 0x28(%%rbp), %%rax;" \
			"movq %%rax, %3;" \
			:"=m"(shadow_space_backup.shadow_a), \
			"=m"(shadow_space_backup.shadow_b), \
			"=m"(shadow_space_backup.shadow_c), \
			"=m"(shadow_space_backup.shadow_d) \
			); \
	ptInfo->last_return_value = cheatlib_func_caller_x64(ptInfo->pOrigFuncAddr, ##__VA_ARGS__); \
	__asm__ __volatile__( \
			"movq %%rdx, %4;" \
			"movq %0, %%rax;" \
			"movq %%rax, 0x10(%%rbp);" \
			"movq %1, %%rax;" \
			"movq %%rax, 0x18(%%rbp);" \
			"movq %2, %%rax;" \
			"movq %%rax, 0x20(%%rbp);" \
			"movq %3, %%rax;" \
			"movq %%rax, 0x28(%%rbp);" \
			:"=m"(shadow_space_backup.shadow_a), \
			"=m"(shadow_space_backup.shadow_b), \
			"=m"(shadow_space_backup.shadow_c), \
			"=m"(shadow_space_backup.shadow_d) \
			:"m"(ptInfo->last_return_2nd_value) \
			); \
	JmpBuilder_x64((BYTE*)ptInfo->pOrigFuncAddr, ptInfo->pHookFuncAddr); \
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE, &oldProtect); \
	ptInfo->last_return_value; \
})

/* 说明:  在Hook函数里调用源函数
 * 注意:  函数参数必须一致,否则会出现栈损
 *        只支持返回结构体的函数,否则会出现栈损
 *        如果结构体内的元素都是整型且数量小于或等于二的话
 *        那么元素将分别保存在rax和rdx里
 *        这个情况下不适合使用此宏,而是使用CallOrigFunc宏
 * 参数:  PFuncHookInfo ptInfo  - FuncHook函数的返回值
 *        void *pSaveStructAddr - 函数返回的结构体保存位置
 *        ...                 - 函数参数 */
#define CallOrigFunc_RetStruct(ptInfo, pSaveStructAddr, ...) ({ \
	DWORD oldProtect; \
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect); \
	memcpy(ptInfo->pOrigFuncAddr, ptInfo->pbOpCode, JMP_SIZE); \
	ShadowSpace shadow_space_backup;\
	__asm__ __volatile__( \
			"subq $0x8, %%rsp;" \
			"movq 0x10(%%rbp), %%rax;" \
			"movq %%rax, %0;" \
			"movq 0x18(%%rbp), %%rax;" \
			"movq %%rax, %1;" \
			"movq 0x20(%%rbp), %%rax;" \
			"movq %%rax, %2;" \
			"movq 0x28(%%rbp), %%rax;" \
			"movq %%rax, %3;" \
			:"=m"(shadow_space_backup.shadow_a), \
			"=m"(shadow_space_backup.shadow_b), \
			"=m"(shadow_space_backup.shadow_c), \
			"=m"(shadow_space_backup.shadow_d) \
			); \
	cheatlib_func_caller_x64(ptInfo->pOrigFuncAddr, pSaveStructAddr, ##__VA_ARGS__); \
	__asm__ __volatile__( \
			"movq %0, %%rax;" \
			"movq %%rax, 0x10(%%rbp);" \
			"movq %1, %%rax;" \
			"movq %%rax, 0x18(%%rbp);" \
			"movq %2, %%rax;" \
			"movq %%rax, 0x20(%%rbp);" \
			"movq %3, %%rax;" \
			"movq %%rax, 0x28(%%rbp);" \
			:"=m"(shadow_space_backup.shadow_a), \
			"=m"(shadow_space_backup.shadow_b), \
			"=m"(shadow_space_backup.shadow_c), \
			"=m"(shadow_space_backup.shadow_d) \
			); \
	JmpBuilder_x64((BYTE*)ptInfo->pOrigFuncAddr, ptInfo->pHookFuncAddr); \
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE, &oldProtect); \
	pSaveStructAddr; \
})

int64_t __attribute__((naked)) cheatlib_func_caller_x64(LPVOID pOrigFuncAddr, ...);

#else

/* 说明:  在Hook函数里调用源函数
 * 注意:  函数参数必须一致,否则会出现栈损
 *        不支持返回结构体的函数,否则可能会覆盖栈内的合法数据
 * 参数:  PFuncHookInfo ptInfo  - FuncHook函数的返回值
 *        ...                   - 函数参数 */
#define CallOrigFunc(ptInfo, ...) ({ \
	DWORD oldProtect; \
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect); \
	memcpy(ptInfo->pOrigFuncAddr, ptInfo->pbOpCode, JMP_SIZE); \
	cheatlib_func_caller(ptInfo->pOrigFuncAddr, ##__VA_ARGS__); \
	__asm__ __volatile__( \
			"movl %%eax, %0;" \
			"movl %%edx, %1;":: \
			"m"(ptInfo->last_return_value), \
			"m"(ptInfo->last_return_2nd_value): \
			"eax", "edx"); \
	JmpBuilder((BYTE*)ptInfo->pOrigFuncAddr, (LPVOID)ptInfo->pHookFuncAddr, (LPVOID)ptInfo->pOrigFuncAddr); \
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE, &oldProtect); \
	ptInfo->last_return_value; \
})


/* 说明:  在Hook函数里调用源函数
 * 注意:  函数参数必须一致,否则会出现栈损
 *        只支持返回结构体的函数,否则会出现栈损
 *        如果结构体内的元素都是整型且数量小于或等于二的话
 *        那么元素将分别保存在eax和edx里
 *        这个情况下不适合使用此宏,而是使用CallOrigFunc宏
 * 参数:  PFuncHookInfo ptInfo  - FuncHook函数的返回值
 *        void *pSaveStructAddr - 函数返回的结构体保存位置
 *        ...                 - 函数参数 */
#define CallOrigFunc_RetStruct(ptInfo, pSaveStructAddr, ...) ({ \
	DWORD oldProtect; \
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect); \
	memcpy(ptInfo->pOrigFuncAddr, ptInfo->pbOpCode, JMP_SIZE); \
	cheatlib_func_caller(ptInfo->pOrigFuncAddr, pSaveStructAddr, ##__VA_ARGS__); \
	JmpBuilder((BYTE*)ptInfo->pOrigFuncAddr, (LPVOID)ptInfo->pHookFuncAddr, (LPVOID)ptInfo->pOrigFuncAddr); \
	VirtualProtect(ptInfo->pOrigFuncAddr, JMP_SIZE, PAGE_EXECUTE, &oldProtect); \
	pSaveStructAddr; \
})

void __attribute__((naked)) cheatlib_func_caller(LPVOID pOrigFuncAddr, ...);

#endif
#endif

