/*
    cheatlib main moudle header
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
	BYTE *pbOpCode;		// 机器码
	int iRequiredSize;	// jmp指令覆盖的指令总大小
	int iFirstCmdSize;	// 注入点第一条指令的大小
} CheatLibRequiredAsmInfo, *PCheatLibRequiredAsmInfo;

typedef struct _CheatLibAsmEncodeInfo{
	const char *pszAsmCode;		// 汇编代码
	uint64_t u64Address;		// 汇编代码的所在地址
	unsigned char *pbOpCode;	// 机器码
	size_t nOpCodeSize;			// 机器码长度
	size_t nCmdCount;			// 汇编指令数量
} CheatLibAsmEncodeInfo, *PCheatLibAsmEncodeInfo;

typedef struct _DllInjectionInfo{
	HANDLE hProcess;			// 进程句柄
	HANDLE hThread;				// 远程线程句柄
	LPVOID pszLibFileRemote;	// dll文件路径字符串首地址
} DllInjectionInfo, *PDllInjectionInfo;

typedef struct _CodeInjectionInfo{
	HANDLE hProcess;							// 进程句柄
	LPVOID pOrigAddr;							// 代码源地址
	LPVOID pVirAddr;							// 申请的远程进程空间的首地址
	PCheatLibRequiredAsmInfo ptRequiredAsmInfo;	// 记录原始代码信息用于恢复
} CodeInjectionInfo, *PCodeInjectionInfo;

/* 说明:    根据窗口标题获取进程句柄
 * 参数:    pszTitle  - 窗口标题
 * 返回值:  成功找到该窗口返回进程句柄
 *          没有找到该窗口返回NULL */
HANDLE GetHandleByTitle(const char *pszTitle);

/* 说明:    向目标进程注入dll
 * 参数:    hProcess    - 进程句柄
 *          pszLibFile  - dll文件名称
 * 返回值:  PDllInjectionInfo */
PDllInjectionInfo DllInjection(HANDLE hProcess, const char *pszLibFile);

/* 说明:    等待dll执行完毕并注出dll
 * 参数:    PDllInjectionInfo - DllInjection函数的返回值
 * 返回值:  void */
void DllOutjection(PDllInjectionInfo ptInfo);

/* 说明:  代码注入 -
 *        如果pszAsmCode包含汇编指令那么函数会在远程进程中申请空间写入
 *        pszAsmCode的指令并在空间最后写入jmp指令,目标为pAddress处将被
 *        jmp指令覆盖的一条或多条指令的下一地址处.最后在pAddress处写入
 *        jmp指令,目标为函数申请的空间.最后nop填充多余的字节
 *        如果pszAsmCode是空字符串或NULL那么函数将会直接用nop填充pAddress
 *        指定的汇编指令
 * 注意:  此函数的主要功能是把pAddress处的那条指令替换为pszAsmCode的指令执行,
 *        但一条jmp指令有5字节,可能会覆盖2条或以上指令.考虑到那些多覆盖的
 *        指令也有可能需要被修改所以此函数不会把那些指令在函数申请的空间
 *        中重新生成.如果不想修改那些被多覆盖的指令请在pszAsmCode的最后写入
 *        那些指令
 * 参数:  hProcess    - 进程句柄
 *        pAddress    - 待替换指令的地址
 *        pszAsmCode  - 汇编指令,以分号或回车分隔.例如xor eax,eax;mov ecx,9
 *        此参数也可以是空字符串或NULL,这样函数将会用nop填充
 *        pAddress指定的汇编指令
 * 返回值:成功执行返回PCodeInjectionInfo
 *        在汇编引擎初始化失败或pszAsmCode有错误的情况下返回NULL */
PCodeInjectionInfo CodeInjection(HANDLE hProcess, LPVOID pAddress, const char *pszAsmCode);

/* 说明:  代码注出 - 恢复注入的代码
 * 参数:  PCodeInjectionInfo - CodeInjection函数的返回值
 * 返回值:void */
void CodeOutjection(PCodeInjectionInfo ptInfo);

#endif

