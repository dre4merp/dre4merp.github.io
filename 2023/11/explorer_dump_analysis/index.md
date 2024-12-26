# Explorer_dump_analysis


## 背景

最近在工作中遇到了个桌面卡死问题，需要分析 dump 查找问题原因。第一次分析 dump 查找卡死问题，特此记录下。

## 流程

### 查看 explorer

因为卡死的外在表现就是桌面进程卡死了，所以入手点就选在 explorer 进程中。

> !process 0 0 explorer.exe

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109112441.png "Pasted%20image%2020231109112441.png")

发现系统存在两个 explorer.exe，其中 07ac 的 HandleCount 更多一些，明显是实际工作的进程

> .process /p /r ffffcf0f746ac080 \
> !process ffffcf0f746ac080 7

查看下所有的线程和对应的堆栈信息，需要重点关注

1. 堆栈长度，卡死的线程的堆栈都会比较深
2. `Ticks` 表示**等待的时间**，卡死的线程等待时间会比较长
3. `WAIT` 卡死问题很多都是 rpc/alpc 引起的，需要关注相关的等待类型
4. 如果直接有 `Waiting for reply` ，这个线程也需要关注

通过上述这些特征，找到了下面这个线程

> !thread ffffcf0f70d8d080

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109124110.png "Pasted%20image%2020231109124110.png")

windbg 有针对 rpc/alpc 的扩展，可以直接查看 rpc 消息并定位到对应的 ServerThread

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109124234.png "Pasted%20image%2020231109124234.png")

### 分析 COM 服务进程

如上图，可以清晰的看到当前 rpc 请求的服务进程是 sihost.exe，服务线程是 ffffcf0f71a6a2c0，点进去看一下

> .process /p /r ffffcf0f71a72440 \
> .thread ffffcf0f71a6a2c0 \
> !thread ffffcf0f`71a6a2c0

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109124620.png "Pasted%20image%2020231109124620.png")

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109124726.png "Pasted%20image%2020231109124726.png")

通过 KeWaitForMultipleObjects 的第一参数和第二参数可以看出其正在等待两个事件。

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109125454.png "Pasted%20image%2020231109125454.png")

等待事件的原因是在发起 COM 请求，所以我们需要找到其对应的服务进程和线程来确定为什么 COM 请求被卡住了

查看 COM 请求的发起函数 `combase!ThreadSendReceive` 发现符号非常全，甚至包括其参数的类符号，看一下参数中是否有对应的 server 相关信息

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109130449.png "Pasted%20image%2020231109130449.png")

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109130519.png "Pasted%20image%2020231109130519.png")

发现存在 pid 和 tid，那么就可以通过这两个成员获取服务进程。接下来就是找到这个参数在内存中保存的位置。因为目标机器是 x64 的，这个进程也是 x64 的进程，调用约定是 fastcall，参数的传递用的是寄存器。那么就需要查看对应代码，找到参数 rcx、rdx 在被赋值时被 push 保存到栈上的位置。

通过查看 `combase!ThreadSendReceive` 被调用时的参数赋值，可以看出目标第二参数 rdx，在赋值给 rdx 之前是由 rdi 进行保存的。而 rdi 寄存器在会被其在初始化函数时保存在栈上，由此可以找到第二参数

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109131024.png "Pasted%20image%2020231109131024.png")

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109131155.png "Pasted%20image%2020231109131155.png")

下图是 `combase!ThreadSendReceive` 的栈顶位置 (rsp)

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109131343.png "Pasted%20image%2020231109131343.png")

回溯堆栈就需要将函数初始化时的操作进行逆置，也就是

> 000000ac`4cffa720 + 5b0 + 4 * 8

``` asm
push    rbp
push    rsi
push    rdi
push    r12
push    r13
push    r14
push    r15
lea     rbp, [rsp-4B0h]
```

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109132839.png "Pasted%20image%2020231109132839.png")

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109133038.png "Pasted%20image%2020231109133038.png")

至此，我们找到了 COM 的服务进程，需要继续切换进 468 进程中查看问题

### 分析 RPC 消息

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109133135.png "Pasted%20image%2020231109133135.png")

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109135919.png "Pasted%20image%2020231109135919.png")

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109135936.png "Pasted%20image%2020231109135936.png")

发现了两个正在等待 alpc reply 的线程，且 port 都属于 ffffcf0f7000d540 进程，可见是该进程内出现了卡死。重复上面 alpc 相关的分析过程，查看 message 和 ServerThread

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109140447.png "Pasted%20image%2020231109140447.png")

![image](https://dre4merp-cloud-images.oss-cn-beijing.aliyuncs.com/Pasted%20image%2020231109140516.png "Pasted%20image%2020231109140516.png")

另一个线程是相同的堆栈，可以看出是 360FsFlt 驱动向应用层发消息时卡住了，终于就要找到问题了。接下来就是要找到这个 Filter 对应的应用层进程了。

> 0: kd> x FLTMGR!FltSendMessage \
  fffff80d`9032b610 FLTMGR!FltSendMessage (void)

根据堆栈可以看出是 360FsFlt 这个驱动对创建进程进行了监控，在创建新进程时会向应用层发消息。

## 结果

**至于具体是哪个应用层进程，其实大概可以猜出来。首先肯定是 360 的进程，最大概率就是 360Tray.exe ZhuDongFangYu.exe 360EDRSensor.exe 这些。经过分析，这个应用层进程是 360EDRSensor.exe.**

**目前还没有找到如何直接找到 FltSendMessage 应用层进程的方法，尝试通过 `!fltkd.fliter ffffcf0f68774010` 获取相关信息，但是没有找到可行的方法。之后再遇到看看有没有其他方法吧**

**至于最后应用层到底是因为什么卡死，就交给对应的同事去分析了，没有符号很难看出具体原因**

