# cheatlib
为外挂作者准备的常用函数库(DLL injection & Code injection & Function Hook)  
注意: cheatlib所有模块均需要cheatlib_utils.h支持

## cheatlib主模块(cheatlib.h)
头文件: cheatlib.h  
库主体: cheatlib.dll  
依赖库: keystone.dll BeaEngine_d_l.dll  
### 获取HANDLE
```c
/* 说明:	  根据窗口标题获取进程句柄
 * 参数:	  pszTitle	- 窗口标题
 * 返回值:  成功找到该窗口返回进程句柄
 * 	    没有找到该窗口返回NULL */
HANDLE GetHandleByTitle(const char *pszTitle);
```
> // 获取窗口名为"Window Title"的窗口句柄   
> HANDLE hProcess = GetHandleByTitle("Window Title");   
> if(hProcess != NULL){...}   

### DLL注入&注出
```c
/* 说明:	向目标进程注入dll
 * 参数:    hProcess	- 进程句柄
 *          pszLibFile	- dll文件名称
 * 返回值:  PDllInjectionInfo */
PDllInjectionInfo DllInjection(HANDLE hProcess, const char *pszLibFile);

/* 说明:    等待dll执行完毕并注出dll
 * 参数:    PDllInjectionInfo - DllInjection函数的返回值
 * 返回值:  void */
void DllOutjection(PDllInjectionInfo ptInfo);
```
> // 在进程hProcess中注入test.dll   
> PDllInjectionInfo ptDllInfo = DllInjection(hProcess, "test.dll");   
> // 等待dll执行完毕并注出dll,最后释放ptDllInfo所占用的资源   
> DllOutjection(ptDllInfo);   

### 代码注入&注出
```c
/* 说明:	代码注入 -
 *	如果pszAsmCode包含汇编指令那么函数会在远程进程中申请空间写入
 *	pszAsmCode的指令并在空间最后写入jmp指令,目标为pAddress处将被
 *	jmp指令覆盖的一条或多条指令的下一地址处.最后在pAddress处写入
 *	jmp指令,目标为函数申请的空间.最后nop填充多余的字节
 *	如果pszAsmCode是空字符串或NULL那么函数将会直接用nop填充pAddress
 *	指定的汇编指令
 * 注意:	此函数的主要功能是把pAddress处的那条指令替换为pszAsmCode的指令执行,
 * 	但一条jmp指令有5字节,可能会覆盖2条或以上指令.考虑到那些多覆盖的
 * 	指令也有可能需要被修改所以此函数不会把那些指令在函数申请的空间
 * 	中重新生成.如果不想修改那些被多覆盖的指令请在pszAsmCode的最后写入
 * 	那些指令
 * 参数:	hProcess	- 进程句柄
 * 	pAddress	- 待替换指令的地址
 * 	pszAsmCode	- 汇编指令,以分号或回车分隔.例如xor eax,eax;mov ecx,9
 *			  此参数也可以是空字符串或NULL,这样函数将会用nop填充
 *			  pAddress指定的汇编指令
 * 返回值:成功执行返回PCodeInjectionInfo
 * 	 在汇编引擎初始化失败或pszAsmCode有错误的情况下返回NULL */
PCodeInjectionInfo CodeInjection(HANDLE hProcess, LPVOID pAddress, const char *pszAsmCode);

/* 说明:	代码注出 - 恢复注入的代码
 * 参数:	PCodeInjectionInfo - CodeInjection函数的返回值
 * 返回值:	void */
void CodeOutjection(PCodeInjectionInfo ptInfo);
```
> //将汇编代码写入到进程hProcess中地址0x401510处   
> PCodeInjectionInfo ptCodeInfo = CodeInjection(hProcess, (LPVOID)0x401510, "mov eax, 1; xor ebx, ebx;");   
> // 恢复代码注入现场并释放ptCodeInfo所占用的资源   
> CodeOutjection(ptCodeInfo);

## cheatlib函数钩子模块(cheatlib_funchook.h)
头文件: cheatlib_funchook.h  
库主体: 代码全部实现在了cheatlib_funchook.h里,没有库主体  
依赖库: 不依赖库  
注意: 此模块一般在dll中使用,用于将目标程序中的函数替换为dll中实现的   
### 函数Hook&Unhook
```c
/* 说明:	将pOrigAddr处的函数直接替换为pHookAddr处的函数执行
 * 注意:	pOrigAddr和pHookAddr处的函数定义必须一致
 *	此函数一般写在dll中,注入到程序中将程序中的函数替换为dll中的
 * 参数:	pOrigAddr	- 源函数地址
 *	pHookAddr	- hook函数地址
 * 返回值:PFuncHookInfo */
PFuncHookInfo FuncHook(LPVOID pOrigAddr, LPVOID pHookAddr);

/* 说明:    撤销函数钩子
 * 参数:    ptInfo	- FuncHook函数返回值
 * 返回值:  void */
void FuncUnhook(PFuncHookInfo ptInfo)

/* 说明:	在Hook函数里调用源函数
 * 注意:	函数参数必须一致,否则会出现栈损
 *	不支持返回结构体的函数,否则可能会覆盖栈内的合法数据
 * 参数:	PFuncHookInfo ptInfo	- FuncHook函数的返回值
 *	...	                - 函数参数 */
#define CallOrigFunc(ptInfo, ...)

/* 说明:	在Hook函数里调用源函数
 * 注意:	函数参数必须一致,否则会出现栈损
 *	只支持返回结构体的函数,否则会出现栈损
 *	如果结构体内的元素数量小于或等于2的话那么元素将分别保存在eax和edx里
 *	这个情况下不适合使用此宏,而是使用CallOrigFunc宏
 * 参数:	PFuncHookInfo ptInfo	- FuncHook函数的返回值
 *	void *pSaveStructAddr	- 函数返回的结构体保存位置
 *	...	                - 函数参数 */
#define CallOrigFunc_RetStruct(ptInfo, pSaveStructAddr, ...)
```
> // 此变量一般是全局的   
> PFuncHookInfo ptFuncHookInfo;   
> // 将0x401510处的函数替换为定义好的test函数,一般在DllMain中调用   
> ptFuncHookInfo = FuncHook((LPVOID)0x401510, (LPVOID)test);   
> // 在Hook函数中调用源函数, 后面的参数需要一致. 此函数不支持返回结构体的函数   
> CallOrigFunc(ptFuncHookInfo, paramer1, paramer2, ... ,paramerN);   
> // 获取源函数的返回值(调用完CallOrigFunc后)   
> int ret = ptFuncHookInfo->last_return_value;   
> // 撤销函数钩子并释放ptFuncHookInfo所占用的资源   
> FuncUnhook(ptFuncHookInfo);   
> // 在Hook函数中调用源函数, 那个函数的返回值是一个类似于st的结构体   
> typedef struct _st{int a; int b; int c;} st, *pst;   
> st s;   
> CallOrigFunc_RetStruct(ptInfo, &s, paramer1, paramer2, ... ,paramerN)   

## 编译
### 环境
OS: windows   
编译器: mingw 8.1.0   
### 步骤
1. 先编译keystone和beaengine
2. 将编译出来的dll复制到cheatlib下
3. 运行make
