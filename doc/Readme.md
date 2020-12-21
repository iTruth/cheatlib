# Cheatlib API
## HANDLE GetHandleByTitle(LPCSTR pszTitle);
说明:    根据窗口标题获取进程句柄  
参数:    pszTitle  - 窗口标题  
返回值:  成功找到该窗口返回进程句柄,没有找到该窗口返回NULL  
```c
HANDLE hTarget = GetHandleByTitle("Cheatlib Target");
if(hTarget == NULL){
  puts("Failed to get target handle");
  return EXIT_FAILURE;
}
```

## LPVOID GetFuncFromIAT(LPCSTR lpModuleName, LPCSTR lpFuncName);
说明: 从IAT获取函数地址  
参数: lpModuleName    - 模块名称,如果是NULL则是.exe模块  
      lpFuncName      - 函数名  
返回值:  IAT内存放指定函数的地址内存指针  
```c
LPVOID addr = GetFuncFromIAT(NULL, "printf");
```

## PDllInjectionInfo DllInjection(HANDLE hProcess, LPCSTR pszLibFile);
说明:    向目标进程注入dll  
参数:    hProcess    - 进程句柄  
         pszLibFile  - dll文件名称  
返回值:  PDllInjectionInfo  
```c
PDllInjectionInfo inject_dll_test_info = NULL;
inject_dll_test_info = DllInjection(hTarget, "inject_dll_test.dll");
if(inject_dll_test_info == NULL){
  printf("Dll injection Failed\n");
  return EXIT_FAILURE;
}
```

## void DllOutjection(PDllInjectionInfo ptInfo);
说明:    等待dll执行完毕并注出dll  
参数:    PDllInjectionInfo - DllInjection函数的返回值  
返回值:  void  
```c
DllOutjection(inject_dll_test_info);
```

## PCodeInjectionInfo CodeInjection(HANDLE hProcess, LPVOID pAddress, LPCSTR pszAsmCode);
说明:  代码注入,实现的是CheatEngine(CE)的代码注入  
注意:  在x32下实现跳转的指令长度是5字节,在x64下是14字节.  
       跳转指令所覆盖的指令不会拷贝到代码执行空间内执行.  
参数:  hProcess    - 进程句柄  
       pAddress    - 待替换指令的地址  
       pszAsmCode  - 汇编指令,以分号或回车分隔.例如xor eax,eax;mov ecx,9  
       此参数也可以是空字符串或NULL,这样函数将会用nop填充  
       pAddress指定的汇编指令  
返回值:成功执行返回PCodeInjectionInfo  
       在汇编引擎初始化失败或pszAsmCode有错误的情况下返回NULL  
```c
PCodeInjectionInfo code_info = NULL;
code_info = CodeInjection(hTarget, (LPVOID)0x40159a,
    "add dword ptr ss:[rbp-0x4], 0xff;"
    "push 0x401574;"
    "ret;"
    );
if(code_info == NULL){
  printf("Code Injection Failed\n");
  return EXIT_FAILURE;
}
```

## void CodeOutjection(PCodeInjectionInfo ptInfo);
说明:  代码注出 - 恢复注入的代码  
参数:  PCodeInjectionInfo - CodeInjection函数的返回值  
返回值:void  
```c
CodeOutjection(code_info);
```

## PFuncHookInfo FuncHook(LPVOID pOrigAddr, LPVOID pHookFuncAddr);
说明:  将pOrigAddr处的函数直接替换为pHookFuncAddr处的函数执行  
注意:  pOrigAddr和pHookFuncAddr处的函数定义必须一致  
       此函数一般写在dll中,注入到程序中将程序中的函数替换为dll中的  
参数:  pOrigAddr - 源函数地址  
       pHookFuncAddr - hook函数地址  
返回值:PFuncHookInfo  
```c
int func_hooked_printf(const char * restrict format, ...)
{
	// to do something here...
	return CallOrigFunc(func_hook_info, "This is Func hooked printf\n");
}

...

LPVOID addr = GetFuncFromIAT(NULL, "printf");
PFuncHookInfo func_hook_info = NULL;
func_hook_info = FuncHook(addr, (LPVOID)func_hooked_printf);
if(func_hook_info == NULL){
  printf("function hook failed\n");
}
```

## void FuncUnhook(PFuncHookInfo ptInfo);
说明:    撤销函数钩子  
参数:    ptInfo  - FuncHook函数返回值  
返回值:  void  
```c
FuncUnhook(func_hook_info);
```

## PIATHookInfo IATHook(LPCSTR lpModuleName, LPCSTR lpFuncName, LPVOID pHookFuncAddr);
说明:  Hook IAT 函数  
注意:  pFuncName和pHookFuncAddr处的函数定义必须一致  
       此函数一般写在dll中,注入到程序中将程序中的函数替换为dll中的  
参数:  lpModuleName  - 模块名称,如果是NULL则是.exe模块  
       pFuncName     - IAT内函数名称  
       pHookFuncAddr - hook函数地址  
返回值:PIATHookInfo  
```c
int iat_hooked_printf(const char * restrict format, ...)
{
	// to do something here...
	return ((int(*)(const char * restrict, ...))iat_hook_info->pFuncAddress)("This is IAT hooked printf\n");
}

...

PIATHookInfo iat_hook_info = NULL;
iat_hook_info = IATHook(NULL, "printf", (LPVOID)iat_hooked_printf);
```

## void IATUnhook(PIATHookInfo ptInfo);
说明:    撤销导入表钩子  
参数:    ptInfo  - IATHook函数返回值  
返回值:  void  
```c
IATUnhook(iat_hook_info);
```

# x64 API
## #define CallOrigFunc(ptInfo, ...)
说明:  在Hook函数里调用源函数  
注意:  函数参数必须一致,否则会出现栈损  
       不支持返回结构体的函数,否则可能会覆盖栈内的合法数据  
参数:  PFuncHookInfo ptInfo  - FuncHook函数的返回值  
       ...                   - 函数参数  
```c
return CallOrigFunc(func_hook_info, "This is Func hooked printf\n");
```

## #define CallOrigFunc_RetStruct(ptInfo, pSaveStructAddr, ...)
说明:  在Hook函数里调用源函数  
注意:  函数参数必须一致,否则会出现栈损  
       只支持返回结构体的函数,否则会出现栈损  
       如果结构体内的元素都是整型且数量小于或等于二的话  
       那么元素将分别保存在rax和rdx里  
       这个情况下不适合使用此宏,而是使用CallOrigFunc宏  
参数:  PFuncHookInfo ptInfo  - FuncHook函数的返回值  
       void *pSaveStructAddr - 函数返回的结构体保存位置  
       ...                 - 函数参数  
```c
typedef struct _struct_a{
  int a;
  int b;
  int c;
  int d;
} struct_a;

...

struct_a s;
return CallOrigFunc_RetStruct(func_hook_info, &s, 1, 2, 3);
```

# x32 API
## #define CallOrigFunc(ptInfo, ...)
说明:  在Hook函数里调用源函数  
注意:  函数参数必须一致,否则会出现栈损  
       不支持返回结构体的函数,否则可能会覆盖栈内的合法数据  
参数:  PFuncHookInfo ptInfo  - FuncHook函数的返回值  
       ...                   - 函数参数  
```c
return CallOrigFunc(func_hook_info, "This is Func hooked printf\n");
```

## #define CallOrigFunc_RetStruct(ptInfo, pSaveStructAddr, ...)
说明:  在Hook函数里调用源函数  
注意:  函数参数必须一致,否则会出现栈损  
       只支持返回结构体的函数,否则会出现栈损  
       如果结构体内的元素都是整型且数量小于或等于二的话  
       那么元素将分别保存在eax和edx里  
       这个情况下不适合使用此宏,而是使用CallOrigFunc宏  
参数:  PFuncHookInfo ptInfo  - FuncHook函数的返回值  
       void *pSaveStructAddr - 函数返回的结构体保存位置  
       ...                 - 函数参数  
```c
typedef struct _struct_a{
  int a;
  int b;
  int c;
  int d;
} struct_a;

...

struct_a s;
return CallOrigFunc_RetStruct(func_hook_info, &s, 1, 2, 3);
```

# 结构体
```c
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

typedef struct _FuncHookInfo{
	LPVOID pOrigFuncAddr;       // 代码源地址
	LPVOID pHookFuncAddr;       // Hook代码源地址
	BYTE *pbOpCode;             // 机器码用于恢复现场
#ifdef CHEATLIB_TARGET_X64
	int64_t last_return_value;      // CallOrigFunc源函数返回值(rax)
	int64_t last_return_2nd_value;  // 在返回值是有两个整型值的结构体时这里保存第二个元素(edx)
#else
	int32_t last_return_value;      // CallOrigFunc源函数返回值(eax)
	int32_t last_return_2nd_value;  // 在返回值是有两个整型值的结构体时这里保存第二个元素(edx)
#endif
} FuncHookInfo, *PFuncHookInfo;

typedef struct _IATHookInfo{
	LPVOID pIATAddress;    // IAT地址
	LPVOID pFuncAddress;   // 函数地址
} IATHookInfo, *PIATHookInfo;
```

