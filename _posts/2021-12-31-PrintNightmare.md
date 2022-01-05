---
layout: article
title: "PrintNightmare"
mode: immersive
header:
  theme: dark
article_header:
  type: cover
  image:
    src: images/cover.jpg
tags:
    - PrintNightmare
---

## 漏洞简介

前段时间，微软公布了名为`Windows PrintNightmare`的安全漏洞，获得编号`CVE-2021-34527`。其与漏洞`CVE-2021-1675`极其相似，都是通过加载DLL的方式实现代码执行。未经身份验证的远程攻击者可利用该漏洞以SYSTEM权限在域控制器上执行任意代码，从而获得整个域的控制权。微软对于该漏洞的修补工作并没有一步到位，在第一次漏洞爆出并发布修补程序后，仍可以通过其他方式绕过补丁继续利用该漏洞，微软不得不二次进行修补才成功杜绝该漏洞所带来的安全问题。

影响范围：Windows Server 2008-Windows Server 2019

## 漏洞分析

### 漏洞点分析

`CVE-2021-1675`的漏洞点位于`RpcAddPrinterDriverEx`中,`CVE-2021-34527`的漏洞点位于`RpcAsyncAddPrinterDriver`中。系统在对上述两个函数进行相关处理后，都调用了`YAddPrinterDriverEx`函数，但是这个过程并没有对参数`dwFileCopyFlags`进行条件判断，所以可以添加一个标志`APD_INSTALL_WARNED_DRIVER`，使得添加打印机驱动时，以system权限加载恶意DLL。

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.016](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.016.png)

Mimikatz中针对PrintNightmare攻击的实现代码

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.002](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.002.png)
![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.003](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.003.png)
![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.004](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.004.png)

两个漏洞分别的漏洞点

### 漏洞具体分析

#### 越过权限校验

通过`YAddPrinterDriverEx`添加打印机驱动时，Windows原本会在`SplAddPrinterDriverEx`中通过`ValidateObjectAccess`对当前用户权限进行校验，如果权限校验失败将无法加载驱动。但是由于添加了标志`APD_INSTALL_WARNED_DRIVER(0x8000)`，所以成功越过了对于权限的检查。

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.005](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.005.png)

`YAddPrinterDriverEx`本地的内部实现位于`localspl.dll`中的`InternalAddPrinterDriverEx`函数，添加驱动的过程如下：

 检查驱动签名
 建立驱动文件列表
 检查驱动兼容性
 拷贝驱动文件

如果能够绕过其中的限制，将恶意DLL复制到驱动目录并加载，就可以完成本地提权。

#### 检查驱动签名

`localspl!ValidateDriverInfo`在如下代码会校验加载驱动的签名，可以使用0x8000的`dwFileCopyFlags`绕过，0x8000即`RpcAddPrinterDriverEx` 的API文档中提到的`APD_INSTALL_WARNED_DRIVER`，翻译过来即强制加载驱动。

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.006](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.006.png)
![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.007](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.007.png)

#### 建立驱动文件列表

`localspl!CreateInternalDriverFileArray`中会使用如下代码根据`RpcAddPrinterDriverEx`的`dwFileCopyFlags`参数生成`CreateFile`的参数，根据文件操作标志来决定是否检查spool驱动目录。在`CreateInternalDriverFileArray`中，如果 a5 flag被标志为False，驱动加载函数只会检查用户目录中是否包含要拷贝的驱动文件；否则，函数会尝试到spool驱动目录寻找目标驱动，这将导致列表建立失败。通过分析可以发现，在`FileCopyFlags`中设置`APD_COPY_FROM_DIRECTORY(0x10)`，即可跳过spool目录检查。

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.008](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.008.png)
![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.009](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.009.png)

#### 检查驱动兼容性

`localsp!InternalAddPrinterDriverEx`会通过`GetPrintDriverVersion`获得驱动文件的版本号并对其进行检查。如果其等于2或大于3则不兼容而无法加载。之后的驱动兼容性检查通过`SplIsCompatibleDriver`进行，而其内部实现`ntprint!InternalCompatibleInfDriverCheck`又限制了版本号只能大于2，所以恶意DLL必须设置版本号为3。

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.010](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.010.png)
![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.011](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.011.png)
![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.012](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.012.png)

#### 拷贝驱动文件

驱动文件拷贝函数`CopyFileToFinalDirectory`会将恶意DLL及其依赖拷贝到`%spooler%\drivers\x64\3`目录下并自动加载。

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.013](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.013.png)

## 漏洞利用条件

当攻击机为域内一台Windows主机时，为了实现恶意DLL从域内主机到域控的横向移动，需要在主机上创建一个共享文件夹用以存放恶意DLL，并且需要允许Everyone和Anonymous对该文件夹进行访问。此外，需要将该共享设置为允许匿名的网络访问。通过注册表设置的代码如下：

``` powershell
mkdir C:\share
icacls C:\share\ /T /grant Anonymous` logon:r
icacls C:\share\ /T /grant Everyone:r
New-SmbShare -Path C:\share -Name share -ReadAccess 'ANONYMOUS LOGON','Everyone'
REG ADD "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d srvsvc /f 
REG ADD "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d share /f
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 1 /f
REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 0 /f
# Reboot
```
