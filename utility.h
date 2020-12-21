/*
    utility moudle header
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

#ifndef UTILITY_H
#define UTILITY_H

#include <windows.h>
#include <Psapi.h>

#include "cheatlib.h"

typedef enum _THREADINFOCLASS { ThreadHideFromDebugger = 17 } THREADINFOCLASS;

typedef NTSTATUS (*NtSetInformationThreadPtr)(HANDLE threadHandle,
		THREADINFOCLASS threadInformationClass,
		PVOID threadInformation,
		ULONG threadInformationLength);

#ifdef CHEATLIB_TARGET_X64

void JmpBuilder_x64(BYTE *pCmdOutput, LPVOID dwTargetAddr);
int64_t __attribute__((naked)) cheatlib_func_caller_x64(LPVOID pOrigFuncAddr, ...);

#else

void IntToByte(int i, BYTE* bytes);
void JmpBuilder(BYTE *pCmdOutput, LPVOID dwTargetAddr, LPVOID dwCurrentAddr);
void __attribute__((naked)) cheatlib_func_caller(LPVOID pOrigFuncAddr, ...);

#endif

PIMAGE_IMPORT_DESCRIPTOR GetImportDirectory(LPVOID pImageBase);
LPVOID GetIATFuncAddr(LPCSTR lpModuleName, LPCSTR lpFuncName);
LPVOID GetFuncFromIAT(LPCSTR lpModuleName, LPCSTR lpFuncName);
void FreeRequiredAsmInfo(PCheatLibRequiredAsmInfo ptInfo);
PCheatLibRequiredAsmInfo GetRequiredAsmInfo(HANDLE hProcess, LPVOID pAddress);
void FreeAsmEncodeInfo(PCheatLibAsmEncodeInfo ptInfo);
PCheatLibAsmEncodeInfo EncodeAsm(LPCSTR pszAsmCode, LPVOID pAddress);

#endif

