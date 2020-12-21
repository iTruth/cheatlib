/*
    function hook moudle
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
#include "func_hook.h"

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
