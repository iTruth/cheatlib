#include <stdio.h>
#include <windows.h>

int main()
{
	SetConsoleTitle("Cheatlib Target");
	for(int i=0;;++i)
	{
		printf("Target Program: %d printf address: %p\n", i, printf);
		Sleep(200);
	}
	return 0;
}
