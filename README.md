# cheatlib
DLL injection & Code injection & Function Hook & IAT Hook  
头文件: cheatlib.h  
库主体: cheatlib.dll  
依赖库: keystone.dll capstone.dll  
**注意: 如果你编译目标是x64的话需要定义CHEATLIB_TARGET_X64宏, x32不用**  

完整的功能测试代码见: [test](https://github.com/iTruth/cheatlib/tree/master/test)  
完整的函数说明见: [doc](https://github.com/iTruth/cheatlib/blob/master/doc)  

### 优势
* 完全支持x32和x64
* 简单的API设计,学习成本极低
* 线程安全设计
* 基于最强大的汇编/反汇编库
* 没有其它任何依赖

### 跳转种类
CodeInjection函数不会将跳转覆盖的指令复制到执行区执行  
因此有必要知道在x32和x64下跳转需要占用多大的空间  
x32下的跳转:  
> jmp hook function  

共计5字节  

x64下的跳转:  
> push target low address  
> mov dword ptr ss:[rsp], target high address  
> ret  

共计14字节  

## 编译
### 环境
```
OS: windows   
编译器: mingw 8.1.0   
```
### 步骤
```
1. 先编译keystone和capstone
2. 将编译出来的dll复制到cheatlib下
3. 编译x32运行make, 编译x64运行make x64
```
