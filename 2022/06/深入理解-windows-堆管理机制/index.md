# 深入理解 Windows 堆管理机制


## 理解堆

栈是分配局部变量和储存函数调用参数及返回地址的主要场所，栈空间是在程序设计时已经规定好怎么使用，使用多少内存空间的。栈变量在使用的时候不需要额外的申请操作，系统栈会根据函数中的变量声明自动在函数栈帧中给其预留空间。栈空间由系统维护，它的分配（如 sub esp ，xx ;）和回收（如 add esp，xxx）都由系统来完成，最终达到栈平衡。所有的这些对程序员来说都是透明的。

同时栈也存在一些不足之处。

1. 栈空间（尤其是内核态栈）的容量是相对较小的，其很难完成一些需要很大空间的操作。
2. 栈空间会在函数返回时释放，不适合保存生命周期较长的变量和对象。
3. 栈空间在程序编译时确定大小，无法分配运行期才能决定大小的缓冲区。

堆（Heap）克服了栈的以上局限，是程序申请和使用内存空间的另一种重要途径。应用程序通过内存分配函数（如 malloc 或 HeapAlloc）或 new 操作符获得的内存空间都来自于堆。

通过堆，内存管理器（Memory Manager）将一块较大的内存空间委托给堆管理器（Heap Manager）来管理。堆管理器将大块的内存分割成不同大小的很多个小块来满足应用程序的需要。这样的分层设计可以减轻内存管理器的负担，同时大大缩短应用程序申请内存分配所需的时间，提高程序的运行速度。

下图展示了操作系统中不同层次的内存分配方法。

![20220512112641](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/20220512112641.png)

## 堆和栈的区别

|          | 堆内存                                   | 栈内存                                                     |
| -------- | ---------------------------------------- | ---------------------------------------------------------- |
| 典型用例 | 动态增长的链表等数据结构                 | 函数局部数组                                               |
| 申请方式 | 需要用函数申请，通过返回的指针使用       | 在程序中直接声明即可                                       |
| 释放方式 | 需要把指针传给专用的释放函数             | 函数返回时，由系统自动回收                                 |
| 管理方式 | 需要程序员处理申请与释放                 | 申请后直接使用，申请与释放由系统自动完成，最后达到栈区平衡 |
| 所处位置 | 变化范围很大                             |                                                            |
| 增长方向 | 由内存低址向高址排列（不考虑碎片等情况） | 由内存高址向低址增加                                       |

## 堆管理器结构

每个进程通常都有很多个堆，程序可以通过自己的需要创建新的堆。它会有一个默认的进程堆，指向这个堆的指针被存放在进程环境块 PEB(Process Environment Block) 中，而这个进程的所有堆，都以链表的形式被挂在 PEB 上。

如下图所示，堆管理器被结构化为 2 层：一个可选的前端层，以及核心堆层（也叫做后端堆层）。核心堆处理基本功能，并且是最为常见跨越用户与内核模式堆的实现。其核心功能包括段内块（blocks inside segments）的管理，段的管理，扩展堆的策略，提交和回收内存，以及大型块的管理（之后会具体分析）。

![Heap-manager-layers](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Heap-manager-layers.jpg)

## 进程默认堆

Windows 系统在创建一个新的进程时，在加载器函数执行新城的用户态初始化阶段，会调用`RtlCreateHeap`函数为进程创建第一个堆，作为进程的默认堆（Process Heap）。创建好的堆句柄会被保存到进程环境块（PEB）的`ProcessHeap`字段中。

``` txt
kd> dt _PEB 7ffdb000
nt!_PEB
   ...
   +0x018 ProcessHeap      : 0x00090000 Void                    //进程默认堆
   ...
   +0x078 HeapSegmentReserve : 0x100000                         //堆的默认保留大小，字节数，1MB
   +0x07c HeapSegmentCommit : 0x2000                            //堆的默认提交大小，8KB （两个内存页，x86 默认内存页 4KB）
   ...
   +0x088 NumberOfHeaps    : 0x10                               //堆的数量
   +0x08c MaximumNumberOfHeaps : 0x10                           //堆的最大数量
   +0x090 ProcessHeaps     : 0x7c99cfc0  -> 0x00090000 Void     //堆句柄数组
   ...
```

``` txt
kd> dd 0x7c99cfc0 l 10
7c99cfc0  00090000 00190000 001a0000 00410000
7c99cfd0  00420000 00440000 00030000 003d0000
7c99cfe0  00890000 009a0000 01810000 01830000
7c99cff0  01cd0000 01dd0000 016e0000 016f0000
```

## 进程私有堆

## Windows XP SP2 – Windows 2003

### 堆的数据结构

![20220512234513](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/20220512234513.png)

#### 堆段

堆管理器在向内存管理器成功申请一块内存后，该内存被称为一个内存段（Segment）。堆中的第一个内存段，我们称其为 0 号段（Segment00）。每个堆最少都会拥有一个段，最多拥有 64 个段。

在 0 号段的开头出存放当前堆的头信息，是一个`HEAP`结构，保存了自身的关键信息。此外每个段都有一个`HEAP_SEGMENT`结构来描述自身，0 号段位于`HEAP`之后，其他段位于起始位置。

``` txt
kd> dt _HEAP 00090000
ntdll!_HEAP
   +0x000 Entry            : _HEAP_ENTRY
   +0x008 Signature        : 0xeeffeeff                                     //标志
   +0x00c Flags            : 2
   +0x010 ForceFlags       : 0
   +0x014 VirtualMemoryThreshold : 0xfe00                                   //最大堆块大小
   +0x018 SegmentReserve   : 0x100000                                       
   +0x01c SegmentCommit    : 0x2000
   +0x020 DeCommitFreeBlockThreshold : 0x200
   +0x024 DeCommitTotalFreeThreshold : 0x2000
   +0x028 TotalFreeSize    : 0x1687
   +0x02c MaximumAllocationSize : 0x7ffdefff
   +0x030 ProcessHeapsListIndex : 1
   +0x032 HeaderValidateLength : 0x608
   +0x034 HeaderValidateCopy : (null) 
   +0x038 NextAvailableTagIndex : 0
   +0x03a MaximumTagIndex  : 0
   +0x03c TagEntries       : (null) 
   +0x040 UCRSegments      : 0x00e70000 _HEAP_UCR_SEGMENT
   +0x044 UnusedUnCommittedRanges : 0x000905e8 _HEAP_UNCOMMMTTED_RANGE
   +0x048 AlignRound       : 0xf
   +0x04c AlignMask        : 0xfffffff8
   +0x050 VirtualAllocdBlocks : _LIST_ENTRY [ 0x90050 - 0x90050 ]
   +0x058 Segments         : [64] 0x00090640 _HEAP_SEGMENT                  //保存堆的所有段，为数组，所以最多拥有 64 个段
   +0x158 u                : __unnamed
   +0x168 u2               : __unnamed
   +0x16a AllocatorBackTraceIndex : 0
   +0x16c NonDedicatedListLength : 6
   +0x170 LargeBlocksIndex : (null) 
   +0x174 PseudoTagEntries : (null) 
   +0x178 FreeLists        : [128] _LIST_ENTRY [ 0x119e60 - 0x14e008 ]     //空闲链表
   +0x578 LockVariable     : 0x00090608 _HEAP_LOCK
   +0x57c CommitRoutine    : (null) 
   +0x580 FrontEndHeap     : 0x00090688 Void                               //前端堆
   +0x584 FrontHeapLockCount : 0                                           //前端堆同步锁计数
   +0x586 FrontEndHeapType : 0x1 ''                                        //前端堆的类型
   +0x587 LastSegmentIndex : 0 ''
```

``` txt
kd> dt _HEAP_SEGMENT 00090640
ntdll!_HEAP_SEGMENT
   +0x000 Entry            : _HEAP_ENTRY
   +0x008 Signature        : 0xffeeffee
   +0x00c Flags            : 0
   +0x010 Heap             : 0x00090000 _HEAP                      //段所属的堆
   +0x014 LargestUnCommittedRange : 0x29000
   +0x018 BaseAddress      : 0x00090000 Void                       //段的基地址
   +0x01c NumberOfPages    : 0x100                                 //段的内存页数
   +0x020 FirstEntry       : 0x00090680 _HEAP_ENTRY                //第一个堆块
   +0x024 LastValidEntry   : 0x00190000 _HEAP_ENTRY                //堆块的边界值
   +0x028 NumberOfUnCommittedPages : 0x3b
   +0x02c NumberOfUnCommittedRanges : 6
   +0x030 UnCommittedRanges : 0x000905a8 _HEAP_UNCOMMMTTED_RANGE
   +0x034 AllocatorBackTraceIndex : 0
   +0x036 Reserved         : 0
   +0x038 LastEntryInSegment : 0x00143000 _HEAP_ENTRY              //最后一个堆块
```

#### 堆块

为了更高效的分配内存，堆区的内存按不同大小组织成块，以堆块为单位进行标识，而不是传统的按字节标识。一个堆块包括两个部分：块首和块身。块首是一个`HEAP_ENTRY`结构，大小为八个字节，用来标识这个堆块自身的信息。包括前面说过的`HEAP`结构本身也是一个堆块，所以其开始部分也是一个`HEAP_ENTRY`结构。

``` txt
kd> dx -id 0,0,81f7a980 -r1 (*((ntdll!_HEAP_ENTRY *)0x90000))
(*((ntdll!_HEAP_ENTRY *)0x90000))                 [Type: _HEAP_ENTRY]
    [+0x000] Size             : 0xc8 [Type: unsigned short]
    [+0x002] PreviousSize     : 0x0 [Type: unsigned short]
    [+0x000] SubSegmentCode   : 0xc8 [Type: void *]
    [+0x004] SmallTagIndex    : 0x4 [Type: unsigned char]
    [+0x005] Flags            : 0x1 [Type: unsigned char]
    [+0x006] UnusedBytes      : 0x0 [Type: unsigned char]
    [+0x007] SegmentIndex     : 0x0 [Type: unsigned char]
```

`HEAP_ENTRY`前两个字节以分配粒度表示堆块的大小，分配粒度通常是 8，这意味着每个堆块的最大值是`0x10000*8=0x80000=512KB`。因为每个堆块知识有 8 字节的管理信息，因此应用程序可以使用的最大堆块便是`0x80000-8=0x7FFF8`。更大块的分配后面讲解。

在 Windows 中，占用态的堆块被使用它的程序索引，而堆表只索引所有空闲态的堆块。空闲双向链表 Freelist 便是索引空闲态堆块的链表。

#### 空表

空闲堆块的块首中包含一对重要的指针，这对指针用于将空闲堆块组织成双向链表。按照堆块的大小不同，空表总共被分为 128 条。

Windows 中的空表其实是一个 128 项的指针数组，每项包含两个指针，用于指向空闲的堆块。

空闲堆块的大小＝索引项（ID）×8（字节）

而其中索引为 0 的项中保存的是所有超过 1024（包含）字节的空闲堆块，按照堆块大小升序排列。具体如下图所示。

![20220414100256](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/20220414100256.png)

该结构指针位于`HEAP`的`+0x178`处，具体分析 Freelist 可以使用`!heap -f xxxxxxxx`命令

``` txt
kd> dt _HEAP 00090000
ntdll!_HEAP
   ...
   +0x178 FreeLists        : [128] _LIST_ENTRY [ 0x119e60 - 0x14e008 ]
   ...
```

#### 空表位图

FreeListInUse 是一个大小为 16 字节的结构，位于 HeapBase 的 `+0x0158` 处。这个字字段的每个 bit 位组成了一个 bitmap，标识着对应的`FreeList[n]`中是否存在空闲块。这个字段的目的是为了在通过 FreeList 分配内存时，扫描 FreeList 来加速分配。

``` txt
kd> dt _HEAP 00090000
ntdll!_HEAP
   ...
   +0x158 u                : __unnamed
   +0x168 u2               : __unnamed
   ...

kd> dx -id 0,0,81cdd520 -r1 (*((ntdll!__unnamed *)0x90158))
(*((ntdll!__unnamed *)0x90158))                 [Type: __unnamed]
    [+0x000] FreeListsInUseUlong [Type: unsigned long [4]]
    [+0x000] FreeListsInUseBytes [Type: unsigned char [16]]
```

#### 堆缓存

堆缓存是一个包含有 896 个指针的数组，数组中的指针为 NULL 指向 0 号空表中 1024-8192 字节的空闲堆块。数组中的每个元素都对应着 0 号空表中大小为 (1K+8 字节*其索引号）的空闲堆块，若 0 号空表中存在与其大小匹配的空闲堆块，则堆缓存数组中对应的元素为指向该空闲堆块的指针，若无，则对应元素为 NULL。堆缓存数组中的最后一个元素较为特殊，该元素并不会仅指向大小为 8192 字节的空闲堆块，而是指向 0 号空表中第一个大于等于 8192 字节的空闲堆块。为加快对堆缓存的遍历，又引入了堆缓存位图对堆缓存中的非空指针进行了标记，其作用机理与上文中的空表位图相同，在此不做过多赘述。在利用空表位图从非 0 号空表中分配内存失败后，系统将尝试通过堆缓存位图索引到堆缓存数组查找满足分配大小的 0 号空表中的空闲堆块。

#### 快表

快表是 Windows 用来加速堆块分配而采用的一种堆表。这里之所以把它叫做“快表”是因为这类单向链表中从来不会发生堆块合并（其中的空闲块块首被设置为占用态，用来防止堆块合并）。

快表也有 128 条，组织结构与空表类似，只是其中的堆块按照单链表组织。快表总是被初始化为空，而且每条快表最多只有 4 个结点，故很快就会被填满。

![20220414100848](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/20220414100848.png)

该结构指针位于`HEAP`的`+0x178`处，具体分析空表可以使用`!heap -f xxxxxxxx`命令

``` txt
kd> dt _HEAP 00090000
ntdll!_HEAP
   ...
   +0x580 FrontEndHeap     : 0x00090688 Void
   ...
```

``` txt
kd> dt _HEAP_LOOKASIDE 0x00090688+30+30
nt!_HEAP_LOOKASIDE
   +0x000 ListHead         : _SLIST_HEADER
   +0x008 Depth            : 0x20
   +0x00a MaximumDepth     : 0x100
   +0x00c TotalAllocates   : 0xe63
   +0x010 AllocateMisses   : 0xde
   +0x014 TotalFrees       : 0xd8e
   +0x018 FreeMisses       : 0
   +0x01c LastTotalAllocates : 0x200
   +0x020 LastAllocateMisses : 0x5d
   +0x024 Counters         : [2] 0x44

kd> dx -id 0,0,81f7a980 -r1 (*((ntkrnlpa!_SLIST_HEADER *)0x906e8))
(*((ntkrnlpa!_SLIST_HEADER *)0x906e8))                 [Type: _SLIST_HEADER]
    [+0x000] Alignment        : 0xd8e0009000e0c28 [Type: unsigned __int64]
    [+0x000] Next             [Type: _SINGLE_LIST_ENTRY]
    [+0x004] Depth            : 0x9 [Type: unsigned short]
    [+0x006] Sequence         : 0xd8e [Type: unsigned short]

kd> dx -id 0,0,81f7a980 -r1 (*((ntkrnlpa!_SINGLE_LIST_ENTRY *)0x906e8))
(*((ntkrnlpa!_SINGLE_LIST_ENTRY *)0x906e8))                 [Type: _SINGLE_LIST_ENTRY]
    [+0x000] Next             : 0xe0c28 [Type: _SINGLE_LIST_ENTRY *]

kd> dt _HEAP_ENTRY 0xe0c28-8
ntdll!_HEAP_ENTRY
   +0x000 Size             : 2
   +0x002 PreviousSize     : 8
   +0x000 SubSegmentCode   : 0x00080002 Void
   +0x004 SmallTagIndex    : 0x80 ''
   +0x005 Flags            : 0x1 ''
   +0x006 UnusedBytes      : 0xe ''
   +0x007 SegmentIndex     : 0 ''

kd> !heap -x 0xe0c28-8
Entry     User      Heap      Segment       Size  PrevSize  Unused    Flags
-----------------------------------------------------------------------------
000e0c20  000e0c28  00090000  00090640        10        40         e  busy 
```

### 堆的管理策略

在内存中，堆块按大小分为 3 种，分别为小块 (<1KB)、大块 (<512KB) 和巨块 (≥512KB)，堆块间主要存在 3 中操作方式，分别是堆块的分配、堆块的释放、堆块的合并。

#### 后端堆管理策略

从空表进行堆块分配时，首先会找到维护对应大小的空表，将最后链入表中的空闲堆块从表中卸下，分配给用户使用，并将空表头的后项指针指向被卸下的堆块的后项堆块。若对应大小的空表内分配失败，则会寻找次优项，在下一个空表中进行分配，直到寻找到能够满足内存分配的最小内存的空闲堆块。当在空表中寻找次优项成功时，会进行切割分配，即从找到的较大堆块中切割下申请大小的堆块分配给程序使用，并将切割剩余的部分按大小加上堆头链入对应的空表。若将所有除 0 号空表外的所有空表都遍历完仍然没有分配成功，则判断 0 号空表中的最后一个堆块大小是否大于所需分配内存大小，若大于则从 0 号空表中正向查找满足分配大小的最小堆块进行分配。

#### 前端堆管理策略

从快表进行堆块分配时，首先会通过用户申请堆块大小索引到维护对应大小的快表，将最后链入表中的空闲堆块从表中卸下，分配给用户使用，并将快表头指向后项空闲堆块。

#### 堆块分配

堆块在进行分配时，主要会从上文提到的快表和空表中进行分配。

堆的分配被划分为前端堆管理器 (Front-End Manager) 和后端堆管理器 (Back-End Manager)，其中前端堆管理器主要由上文中提到的快表有关的分配机制构成，后端堆管理器则是由空表有关的分配机制构成。

在用户申请分配某一大小的内存空间时，系统会首先判断申请的堆块是否属于巨块范畴，若是巨块，则采用虚分配，在漏洞利用中遇到较少，本文不予讨论。若申请大块，则首先考虑堆缓存进行分配，若分配不成功，则从 0 号空表中寻找最合适的空闲块进行分配。若申请小块，则首先查看对应大小的快表中有没有空闲的堆块，若无则查看对应大小的空表中有没有空闲的堆块，若无则通过空表位图查找更大的空表中有没有空闲的堆块进行切割分配，若无则采用堆缓存进行分配，若分配失败，则从 0 号空表中寻找最适合的空闲快进行分配，若依然失败，则会先进行内存紧缩后再尝试分配。堆块分配流程如下图所示。

![HeapChunkAllocate](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/HeapChunkAllocate.png)

#### 堆块释放

堆块释放，即将堆块从占用状态更改为空闲状态。在准备释放某一大小的内存空间时，首先会判断释放释放的堆块是否属于巨块范畴，若是巨块，则直接将该空间释放，不会进入任何堆表。若是大块，则尝试将其释放入堆缓存，若堆缓存已满，则链入 0 号空表。若是小块，则首先尝试链入对应大小的快表，若链入快表，为了加快堆块的分配，系统不会更改其占用状态。若对应大小的快表中已经链满了 4 个空闲堆块，则将该堆块链入对应大小的空表中。

#### 堆块合并

在进行堆块释放时，若释放堆块直接进入空表（链接在快表中的空闲堆块不会进行合并操作），并且与该堆块物理地址相邻的堆块同为空闲态，则会进行堆块的合并。在进行堆块合并时，会将堆块从空表中卸下，将两个相邻的内存空间整合后更新新空闲堆块的堆头信息，并根据新空闲堆块的大小链入相应大小的空表中。除了堆块的释放会触发堆块合并外，在申请堆块时，若未成功从快表、堆缓存及空表中分配空间，则会触发内存紧缩。内存紧缩会将堆空间中的所有空闲堆块，无论地址是否连续，都整合成一个大的空闲堆块再进行堆块分配。

## Windows Vista – Windows 7

### 术语

`block`: 表示 8 字节连续内存。它是堆块头部在引用大小时所用的最小度量单位。一个 chunk 是一片连续的内存空间，可以使用 blocks 或 bytes 来度量。

`BlocksIndex`: 是`_HEAP_LIST_LOOKUP`结构的别名。BlocksIndex 结构体通过 Lists 来管理 chunks，低于 0x400（1024）字节的 chunks 所在的 Lists 作为第一个 BlocksIndex，而从 0x400 到 0x4000(16k) 的块所在的 Lists 作为第二个 BlocksIndex。大于 16k 的且低于 DeCommitThreshold 和 0xFE00 blocks 的 chunks 会被组织在类似 FreeList[0] 的结构体中（在文章后面讨论）。**专用 FreeLists 的概念已经消失**

`ListHint, FreeList` : 用来表示指向 Heap->FreeLists 中特定位置的一个链表。

`HeapBin, Bin, UserBlock` : 表示 LFH 分配的一块具体大小的内存。很多人称之为 `Bucket`，但是`_HEAP_BUCKET` 本身是一个 0x4 字节的数据结构，用来指定一个尺寸而不是用于内存容器。

### 重要结构

#### _HEAP(HeapBase)

前面介绍过每个堆都是`_HEAP`结构进行描述的，而 Win7 针对`_HEAP`结构进行了一些更改，重要的更改点已经标出在结构体中。

``` txt
kd> dt _HEAP
ntdll!_HEAP
   +0x000 Entry            : _HEAP_ENTRY
   +0x010 SegmentSignature : Uint4B
   +0x014 SegmentFlags     : Uint4B
   +0x018 SegmentListEntry : _LIST_ENTRY
   +0x028 Heap             : Ptr64 _HEAP
   +0x030 BaseAddress      : Ptr64 Void
   +0x038 NumberOfPages    : Uint4B
   +0x040 FirstEntry       : Ptr64 _HEAP_ENTRY
   +0x048 LastValidEntry   : Ptr64 _HEAP_ENTRY
   +0x050 NumberOfUnCommittedPages : Uint4B
   +0x054 NumberOfUnCommittedRanges : Uint4B
   +0x058 SegmentAllocatorBackTraceIndex : Uint2B
   +0x05a Reserved         : Uint2B
   +0x060 UCRSegmentList   : _LIST_ENTRY
   +0x070 Flags            : Uint4B
   +0x074 ForceFlags       : Uint4B
   +0x078 CompatibilityFlags : Uint4B
   +0x07c EncodeFlagMask   : Uint4B                    //用于判断堆 chunk 头部是否被编码。
   +0x080 Encoding         : _HEAP_ENTRY               //在异或 (XOR) 操作中用于编码 chunk 头，防止可预知的元数据被污染。
   +0x090 PointerKey       : Uint8B
   +0x098 Interceptor      : Uint4B
   +0x09c VirtualMemoryThreshold : Uint4B
   +0x0a0 Signature        : Uint4B
   +0x0a8 SegmentReserve   : Uint8B
   +0x0b0 SegmentCommit    : Uint8B
   +0x0b8 DeCommitFreeBlockThreshold : Uint8B
   +0x0c0 DeCommitTotalFreeThreshold : Uint8B
   +0x0c8 TotalFreeSize    : Uint8B
   +0x0d0 MaximumAllocationSize : Uint8B
   +0x0d8 ProcessHeapsListIndex : Uint2B
   +0x0da HeaderValidateLength : Uint2B
   +0x0e0 HeaderValidateCopy : Ptr64 Void
   +0x0e8 NextAvailableTagIndex : Uint2B
   +0x0ea MaximumTagIndex  : Uint2B
   +0x0f0 TagEntries       : Ptr64 _HEAP_TAG_ENTRY
   +0x0f8 UCRList          : _LIST_ENTRY
   +0x108 AlignRound       : Uint8B
   +0x110 AlignMask        : Uint8B
   +0x118 VirtualAllocdBlocks : _LIST_ENTRY
   +0x128 SegmentList      : _LIST_ENTRY
   +0x138 AllocatorBackTraceIndex : Uint2B
   +0x13c NonDedicatedListLength : Uint4B
   +0x140 BlocksIndex      : Ptr64 Void
   +0x148 UCRIndex         : Ptr64 Void
   +0x150 PseudoTagEntries : Ptr64 _HEAP_PSEUDO_TAG_ENTRY
   +0x158 FreeLists        : _LIST_ENTRY              //指向堆上所有空闲 chunk 的指针。
   +0x168 LockVariable     : Ptr64 _HEAP_LOCK
   +0x170 CommitRoutine    : Ptr64     long 
   +0x178 FrontEndHeap     : Ptr64 Void               //指向关联的前端堆。
   +0x180 FrontHeapLockCount : Uint2B
   +0x182 FrontEndHeapType : UChar                    //1-->Lookaside Lists 2-->LFH Win7 实际上不支持 Lookaside Lists。
   +0x188 Counters         : _HEAP_COUNTERS
   +0x1f8 TuningParameters : _HEAP_TUNING_PARAMETERS
```

#### _HEAP_LIST_LOOKUP(HeapBase->BlocksIndex)

``` txt
kd> dt _HEAP_LIST_LOOKUP
ntdll!_HEAP_LIST_LOOKUP
   +0x000 ExtendedLookup   : Ptr64 _HEAP_LIST_LOOKUP    //
   +0x008 ArraySize        : Uint4B
   +0x00c ExtraItem        : Uint4B
   +0x010 ItemCount        : Uint4B
   +0x014 OutOfRangeItems  : Uint4B
   +0x018 BaseIndex        : Uint4B
   +0x020 ListHead         : Ptr64 _LIST_ENTRY
   +0x028 ListsInUseUlong  : Ptr64 Uint4B
   +0x030 ListHints        : Ptr64 Ptr64 _LIST_ENTRY
```

## 参考

<https://www.jianshu.com/p/a853040d2804>

