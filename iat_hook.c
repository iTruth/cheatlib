/*
    iat hook moudle
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
#include "iat_hook.h"
#include "utility.h"

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

