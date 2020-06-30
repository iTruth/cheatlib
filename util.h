/*
    cheatlib util moulde
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

#ifndef _H_UTIL
#define _H_UTIL

#include <windows.h>
#include <assert.h>

void IntToByte(int i, BYTE *bytes)
{
	assert(bytes != NULL);
	bytes[0] = (byte) (0xff & i);
	bytes[1] = (byte) ((0xff00 & i) >> 8);
	bytes[2] = (byte) ((0xff0000 & i) >> 16);
	bytes[3] = (byte) ((0xff000000 & i) >> 24);
}

void JmpBuilder(BYTE *pCmdOutput, DWORD dwTargetAddr, DWORD dwCurrentAddr)
{
	assert(pCmdOutput != NULL);
	pCmdOutput[0] = 0xE9;
	DWORD jmpOffset = dwTargetAddr - dwCurrentAddr - 5;
	IntToByte(jmpOffset, pCmdOutput+1);
}

#endif

