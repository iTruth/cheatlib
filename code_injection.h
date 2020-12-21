/*
    code injection moudle header
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

#ifndef CODE_INJECTION_H
#define CODE_INJECTION_H

#include <windows.h>

#include "code_injection.h"
#include "cheatlib.h"

void FreeCodeInjectionInfo(PCodeInjectionInfo ptInfo);
PCodeInjectionInfo CodeInjection(HANDLE hProcess, LPVOID pAddress, LPCSTR pszAsmCode);
void CodeOutjection(PCodeInjectionInfo ptInfo);

#endif

