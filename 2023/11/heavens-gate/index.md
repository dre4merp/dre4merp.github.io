# Heaven’s Gate

## Introduction

天堂之门 (Heaven's Gate) 是一种专属于 Windows 操作系统的技术，其独特之处在于主要依赖于 Windows 上的 WoW64 子系统。其核心功能包括在运行于 x64 系统下的 x86（WoW64）进程中直接执行 64 位代码，以及直接调用 64 位 Windows API 函数。

从正面角度来看，天堂之门可被视为一项软件保护技术。该技术的应用导致无法直接利用 IDA 等工具进行逆向分析，同时也支持跨位数的进程注入和 Hook 操作。然而，从恶意使用的角度考虑，这项技术也具有潜在风险，因为它能够隐藏对 Windows API 的调用，从而绕过一些应用层的检测机制。

## WoW64 Exploration

### WoW64

WoW64（Windows 32-bit on Windows 64-bit）是 Windows 中的一个子系统，其保证了在 x64 系统上运行 x86 程序的兼容性需求。

根据微软提供的 [WOW64 Implementation Details](https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details)，WoW64 子系统主要有以下 3 部分组成 (主要讨论 x64 系统)：

- Wow64.dll: `Nt*` 系统调用的翻译 (`ntoskrnl.exe`/`ntdll.dll`)
- Wow64Win.dll: 为 `NtGdi*`、`NtUser*` 和其他 GUI 相关系统调用的翻译 (`win32k.sys`/`win32u.dll`)
- Wow64Cpu.dll: 支持在 x64 上运行 x86 程序

除了 `Nt*` 系统调用转换之外， `wow64.dll` 还提供核心仿真基础设施。

### API Calling Process

下图展示了 x64 Windows API 的调用流程。可以观察到，它简单地将 `NtOpenFile` 的 Service Index 放入 `eax` 寄存器中，通过 `KUSER_SHARED_DATA` 中的 `SystemCall` 判断使用何种系统中断方式，然后触发系统中断进入内核。

![x64 Windows API 调用流程](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231125220607.png "20231125220607.png")

``` text
0:007> dt _KUSER_SHARED_DATA SystemCall 7FFE0000
combase!_KUSER_SHARED_DATA
   +0x308 SystemCall : 0
```

在 WOW64 进程中，对于 `NtOpenFile` 的调用过程也类似。首先，同样将 Service Index 放入 `eax` 寄存器中，之后调用 `ntdll!Wow64SystemServiceCall` 函数。

![WOW64 NtOpenFile 调用过程](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231125221312.png "20231125221312.png")

`ntdll!Wow64SystemServiceCall` 函数实际上只是通过一条 `jmp` 指令跳转到 `wow64cpu！Wow64Transition` 函数。

![Wow64SystemServiceCall 跳转](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231125221338.png "20231125221338.png")

下面是实际的 `wow64cpu！Wow64Transition` 函数的内容。关于为什么不使用 Windbg 的截图，是因为由于 CPU 的模式在这几条指令中会发生改变，导致无法正常解析出完全正确的汇编代码。

![Wow64Transition 内容](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231125221437.png "20231125221437.png")

`jmp 33:wow64cpu+6009` 这句汇编使用的是 opcode 为 EA 的 far jmp，与我们通常见到的基于偏移的 jmp 指令（E9）有些不同。这个指令是一种长跳转，EA 后面跟随的第一个操作数是绝对地址。成功执行后，段寄存器 cs 将被写入第二个操作数，在这个例子中为 0x33。

cs 的不同值会影响 Intel 使用不同指令集进行解析：

- 0x23 - 当前状态是 WOW64 架构中的 32 位 Thread 模式
- 0x33 - 当前状态是原生 64 位 Thread 状态（运行在原生 64 位系统中）
- 0x1B - 当前状态是原生 32 位 Thread 状态（运行在原生 32 位系统中）

![Far jump intel](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231125223954.png "20231125223954.png")

随后，CPU 识别到 cs 为 0x33，之后的代码都会以 x64 的模式运行，因此才会出现 **r15** 寄存器和 qword 的关键字。

### RunSimulatedCode

为了理解遇到的第一条 x64 指令中 **r15** 具体是什么，我们需要理解 WoW64 子系统是如何初始化自身的。具体的细节可以参考 [WoW64 internals - mindless-area](https://wbenny.github.io/2018/11/04/WoW64-internals.html)。WoW64 进程其实也是运行在一个 x64 进程下，初始化进程后通过执行 `BTCpuSimulate` 模拟 x86 模式，执行 x86 的代码。

而 `BTCpuSimulate` 实际上是一个大的 while 循环，循环执行 x86 代码，当需要调用 API 函数 (系统中断) 时，由于系统只支持 x64 的函数，就需要切换回 x64 模式并再执行后返回。从 IDA 和 XP leak code 我们都可以清楚的看出这个逻辑。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126164240.png "20231126164240.png")

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126164639.png "20231126164639.png")

下面是 `BTCpuSimulate` 中 `RunSimulatedCode` 函数入口点的代码片段，执行的重点操作如下：

1. 通过 gs:30 将当前进程的 64 位 TEB 结构保存在 r12 寄存器中
2. 将 `wow64cpu.dll` 上的一个函数列表 `TurboThunkDispatch` 保存在 **r15** 中
3. 从 TEB+1488h 中提取出来 [x86 Thread Context 结构](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)，并将其保存在 r13 中，这个结构是为了保存 x86 线程的状态

分析到现在我们就得到了上面关注的 r15 寄存器的值。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126162403.png "20231126162403.png")

分析 `TurboThunkDispatch` 列表，只有两个函数需要注意:

1. `CpupReturnFromSimulatedCode` 是 32 位程序切换回 64 位环境的第一个 64 位入口函数。当 32 位程序执行需要进行系统中断的 32 位系统函数时，它会进入 `wow64cpu.dll` 导出的这个函数。在这个函数中，当前 32 位线程的状态被备份，并跳转到 `TurboDispatchJumpAddressEnd`，以便模拟当前接收到的系统中断，并执行 64 位 `ntdll` 函数。
2. `TurboDispatchJumpAddressEnd` 的作用是调用 `wow64.dll` 导出的翻译机函数 `Wow64SystemServiceEx`，以完成对系统中断的仿真。在仿真完成后，它会从之前备份的线程状态中进行恢复，并跳回到上一次 32 位程序的返回地址，继续程序的正常执行。

指令 `jmp [r15 + 0xF8]` 相当于 C 代码 `jmp TurboThunkDispatch[0xF8 / sizeof(uint64_t)]`。查看此索引处的函数指针，我们可以看到我们位于函数 `wow64cpu!CpupReturnFromSimulatedCode`。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126165029.png "20231126165029.png")

### CpupReturnFromSimulatedCode

显而易见的，在整个 WoW64 进程的执行过程中，一个线程至少会涉及到两个堆栈：

- 32 位堆栈: 用于保存 32 位参数，主要用于 32 位程序的 push/pop/call/ret 等操作。
- 64 位堆栈: 另一个堆栈仅在 WOW64 翻译阶段使用，仅在线程切回 64 位时才会涉及。将这两个堆栈分开有许多好处，例如避免相互污染，防止参数内文或内存分配/释放大小的错误导致程序直接崩溃。

下图中的 `xchg rsp, r14` 将当前使用的 32 位堆栈从寄存器 `esp` 切换到寄存器 `r14`，将 64 位堆栈从 `r14` 取回并放入 `rsp` 中，作为当前的主要堆栈，完成了两个堆栈之间的无污染切换。

`r14` 中现在保存的是 32 位堆栈。因此，`mov r8d, [r14]` 取得 32 位应返回的地址 (call 时 push 的 eip)，接着将此地址保存到 `r13` 所指向的 Thread 快照纪录的 `CONTEXT.EIP` 中，以便后续跳回 32 位原始程序并继续执行。同理，`r11` 从 `r14+4` 处获取地址，即 32 位堆栈上保存当前系统函数参数的地址 (push a1 ,push a2 ...)。

接下来，将 32 位运行所必需的几个关键参数（如可能受到文本操作系列指令影响的寄存器 `edi`、`esi`，与栈帧相关的 `ebp`，运算旗标记录 `r8d` 等）一并写入 `r13` 指向的 Thread 快照纪录。这样就完成了对 32 位状态的快照备份，可以安心跳转到 `TurboDispatchJumpAddressStart` 函数中进行下一步操作。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126172712.png "20231126172712.png")

而 `TurboDispatchJumpAddressStart` 只是针对不同的 API 进行分发而已。eax 中保存的是 API 的 Service Index，计算方式是将 index 右移 16 位。所以其实 API 的 index 中高两位就是其在 TurboThunkDispatch 中的索引，而大部分的 API 的高两位都是 0，所以大部分都会执行 `TurboDispatchJumpAddressEnd`.

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126173807.png "20231126173807.png")

### TurboDispatchJumpAddressEnd

`TurboDispatchJumpAddressEnd` 调用 `Wow64SystemServiceEx`,一次传入 API 的 index 和参数，调用完成后将结果保存在 r13 的 context 中。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126174306.png "20231126174306.png")

之后便是复原刚才保存的各个寄存器的内容，最后通过 jmp far 切换回 x86 模式并继续执行。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126174319.png "20231126174319.png")

### Wow64SystemServiceEx

上面说过，该函数的第一参数是 API 的 index，而这个 index 其实是一个 `WOW64_SYSTEM_SERVICE` 结构，其大小为 16 位。其中低 12 位表示函数识别码，而较高的 4 位表示系统函数表的辨识码。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126175257.png "20231126175257.png")

这是个二维数组，其位于 `wow64.dll` 中，其中保存的是 wh 开头的 Nt 函数。执行 Nt 函数时，会调用对应的 whNt 函数，由其来调用对应的 64 位 Nt 函数。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126180617.png "20231126180617.png")

而 `Wow64SystemServiceEx` 的作用就是利用传入的 API index 进行分发。

![aaaddress1's fake code](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126222109.png "20231126222109.png")

![XP leaked Wow64SystemService](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126180815.png "20231126180815.png")

以上，便是对于 WoW64 实现原理的分析，之后我们来进入关于 Heaven’s Gate 的分析。

## Heaven’s Gate Exploration

现在我们已经清楚了 WoW64 进程的工作流程。在正常情况下，其调用应如下图一样。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126222720.png "20231126222720.png")

而某些安全软件的主动防御等监控功能会 Hook 掉一些恶意软件常用的 API 函数。Hook 后的流程如下图一样。而天堂之门技术的核心就是绕过 WoW64 子系统，直接在 WoW64 进程内调用 API 函数，这样就可以 ByPass 掉一些安全软件的防护措施。

![image.png](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/20231126223113.png "20231126223113.png")

而 WoW64 进程中直接调用 x64 的 API 函数也存在两种不同的方式：

1. 搜索目标 API 函数地址，构造参数，直接调用
2. 搜索 `Wow64SystemServiceEx` 函数的地址，通过其进行调用

显然，第二种方法是通过 WoW64 子系统进行的调用，鉴于其为 Windows 自身的子系统，可以确保调用的兼容性，所以本文采用第二种方法实现。

### Heaven’s Gate Implementation

天堂之门技术需要一些操作来绕过 WoW64 机制，手动切换到 64 位模式并调用 64 位下的 API 函数，大致流程如下 ([参考](https://speakerdeck.com/aaaddress1/rebuild-the-heavens-gate-from-32-bit-hell-back-to-heaven-wonderland?slide=34))：

1. 通过设置 cs 标志切换到 64 位 CPU 模式
2. 通过 (GS:0x30)->PEB 获取 PEB64
3. 通过 PEB->Ldr 枚举加载的 64 位模块
4. 找到 WoW64.dll 的 imageBase
5. 获取导出的 API wow64!Wow64SystemServiceEx
6. 传递 32 位 va_start 并执行它以将我们的 32 位模拟为 64 位中断

### Read x64 memmory in WoW64 process

上述流程中存在一个需要注意的问题，我们需要获取的 `wow64.dll` 的 imageBase 并在其中搜索导出函数 `Wow64SystemServiceEx`,但这个模块本身是 64 位的版本，其中的地址也是 64 位地址。而 32 位进程正常情况下，由于地址空间的问题，是无法读取 64 位进程的内存的。解决这个问题的办法就是将进程切换到 64 位模式，将内存复制到 32 位进程中，再正常进行读取。

#### switch to 64 bits

``` asm
push   0x33                 // 0x6A,0x33
call   $+5                  // 0xe8,0x00,0x00,0x00
add    DWORD PTR [esp],0x5  // 0x83,0x04,0x24,0x05
retf                        // 0xcb
// x64 code
```

1. push 0x33，将要赋给 cs 寄存器的值压入栈
2. 通过 call 将下一条语句的地址压入栈
3. 将上条语句压入的地址加 5 (当前语句和下条语句的长度，修改后指向 x64 code)
4. retf 会将 cs 设置为 0x33(x64 模式)，并返回到栈中保存的地址

#### memcpy64

``` asm
mov    rdi,QWORD PTR [esp+0x4]                   "\x67\x48\x8b\x7c\x24\x04"
mov    rsi,QWORD PTR [esp+0xc]                   "\x67\x48\x8b\x74\x24\x0c"
mov    rcx,QWORD PTR [esp+0x14]                  "\x67\x48\x8b\x4c\x24\x14"
rep movs BYTE PTR es:[rdi],BYTE PTR ds:[rsi]     "\xf3\xa4"                
```

通过 rep movs 命令实现 memcpy

#### switch to 32 bits

``` asm
 call   $+5                         "\xe8\x00\x00\x00\x00"              
 mov    DWORD PTR [rsp+0x4],0x23    "\xc7\x44\x24\x04\x23\x00\x00\x00"  
 add    DWORD PTR [rsp],0xd         "\x83\x04\x24\x0d"            
 retf                               "\xcb" 
// x64 code
```

1. 通过 call 将下一条语句的地址压入栈
2. 将要赋给 cs 寄存器的值放入栈
3. 将 call 压入的地址加 d (当前语句和下条语句的长度，修改后指向 x64 code)
4. retf 会将 cs 设置为 0x23(x86 模式)，并返回到栈中保存的地址

### Call x64 API in x86 Process

1. 通过 `memcpy64` 读取 64 位内存，并获取 API 地址
2. 通过 `memcpy64` 读取 64 位内存，并获取 `Wow64SystemServiceEx` 地址
3. 调用 API 函数时，将 API 地址写入 eax，将 translator 的地址写入 `0xdeadbeef` 所在位置
4. 实现通过 translator 调用 x64 函数

``` cpp
int X64Call(const char* NtApiName, ...) {
  PCHAR jit_stub;
  PCHAR api_addr = PCHAR(GetApiAddress(NtApiName));
  static uint64_t translator(0);
  if (!translator) GetWow64SystemServiceEx(translator);

  static uint8_t stub_template[] = {
      /* overwirte by API address*/
      0xB8, 0x00, 0x00, 0x00, 0x00,                   /* mov    eax,0x0                  */
      0x8b, 0x54, 0x24, 0x04,                         /* mov    edx,DWORD PTR [esp+0x4]  */
      0x89, 0xC1,                                     /* mov    ecx,eax                  */
      /* enter 64 bit mode */                         
      0x6A, 0x33,                                     /* push   0x33                     */
      0xE8, 0x00, 0x00, 0x00, 0x00,                   /* call   $+5                      */
      0x83, 0x04, 0x24, 0x05,                         /* add    DWORD PTR [esp],0x5      */
      0xCB,                                           /* retf                            */
      /* call API*/
      0x49, 0x87, 0xE6,                               /* xchg   r14,rsp                  */
      0xFF, 0x14, 0x25, 0xEF, 0xBE, 0xAD, 0xDE,       /* call   QWORD PTR ds:0xdeadbeef  */
      0x49, 0x87, 0xE6,                               /* xchg   r14,rsp                  */
      /* exit 64 bit mode */
      0xE8, 0x00, 0x00, 0x00, 0x00,                   /* call   $+5                      */
      0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, /* mov    DWORD PTR [rsp+0x4],0x23 */
      0x83, 0x04, 0x24, 0x0D,                         /* add    DWORD PTR [rsp],0xd      */
      0xCB,                                           /* retf                            */
      0xc3,                                           /* ret                             */
  };
  jit_stub = (PCHAR)VirtualAlloc(0, sizeof(stub_template), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(jit_stub, stub_template, sizeof(stub_template));
  va_list args;
  va_start(args, NtApiName);
  *((uint32_t*)&jit_stub[0x01]) = *(uint32_t*)&api_addr[1];
  *((uint32_t*)&jit_stub[0x1d]) = (size_t)&translator;
  auto ret = ((NTSTATUS(__cdecl*)(...))jit_stub)(args);
  return ret;
}
```

### example

参考 aaaddress1 的实现，通过 Heaven’s Gate 技术，利用 Process Hollowing 技术，实现了进程注入。

完整代码见 GitHub 仓库：[dre4merp/HeavenGate](https://github.com/dre4merp/HeavenGate)

## 参考

- [WoW64 internals - mindless-area](https://wbenny.github.io/2018/11/04/WoW64-internals.html)
- [Mixing x86 with x64 code – ReWolf's blog](http://blog.rewolf.pl/blog/?p=102)
- [Knockin’ on Heaven’s Gate – Dynamic Processor Mode Switching | RCE.co](https://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/)
- [WoW64!Hooks: WoW64 Subsystem Internals and Hooking Techniques | Mandiant](https://www.mandiant.com/resources/blog/WoW64-subsystem-internals-and-hooking-techniques)
- [重建天堂之門：從 32 位元地獄一路打回天堂聖地（上）深度逆向工程 WoW64 設計](https://blog.30cm.tw/2021/06/32-WoW64.html)
- [重建天堂之門：從 32 位元地獄一路打回天堂聖地（下）攻擊篇：x96 Shellcode、天堂聖杯 ＆ 天堂注入器](https://blog.30cm.tw/2021/06/32-x96-shellcode.html)

