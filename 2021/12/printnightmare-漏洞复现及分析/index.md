# PrintNightmare 漏洞复现及分析


## 漏洞简介

前段时间，微软公布了名为`Windows PrintNightmare`的安全漏洞，获得编号`CVE-2021-34527`。其与漏洞`CVE-2021-1675`极其相似，都是通过加载DLL的方式实现代码执行。未经身份验证的远程攻击者可利用该漏洞以SYSTEM权限在域控制器上执行任意代码，从而获得整个域的控制权。微软对于该漏洞的修补工作并没有一步到位，在第一次漏洞爆出并发布修补程序后，仍可以通过其他方式绕过补丁继续利用该漏洞，微软不得不二次进行修补才成功杜绝该漏洞所带来的安全问题。

影响范围：Windows Server 2008-Windows Server 2019

## 漏洞分析

### 漏洞点分析

`CVE-2021-1675`的漏洞点位于`RpcAddPrinterDriverEx`中,`CVE-2021-34527`的漏洞点位于`RpcAsyncAddPrinterDriver`中。系统在对上述两个函数进行相关处理后，都调用了`YAddPrinterDriverEx`函数，但是这个过程并没有对参数`dwFileCopyFlags`进行条件判断，所以可以添加一个标志`APD_INSTALL_WARNED_DRIVER`，使得添加打印机驱动时，以system权限加载恶意DLL。

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.016](https://github.com/dre4merp/Drawing-bed/blob/main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.016.png)

Mimikatz中针对PrintNightmare攻击的实现代码

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.002](https://github.com/dre4merp/Drawing-bed/blob/main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.002.png)
![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.003](https://github.com/dre4merp/Drawing-bed/blob/main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.003.png)
![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.004](https://github.com/dre4merp/Drawing-bed/blob/main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.004.png)

两个漏洞分别的漏洞点

### 漏洞具体分析

#### 越过权限校验

通过`YAddPrinterDriverEx`添加打印机驱动时，Windows原本会在`SplAddPrinterDriverEx`中通过`ValidateObjectAccess`对当前用户权限进行校验，如果权限校验失败将无法加载驱动。但是由于添加了标志`APD_INSTALL_WARNED_DRIVER(0x8000)`，所以成功越过了对于权限的检查。

![Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.005](https://github.com/dre4merp/Drawing-bed/blob/main/images/Aspose.Words.2a55de83-1c35-49eb-98b2-393b538b46b8.005.png)

`YAddPrinterDriverEx`本地的内部实现位于`localspl.dll`中的`InternalAddPrinterDriverEx`函数，添加驱动的过程如下：

 检查驱动签名
 建立驱动文件列表
 检查驱动兼容性
 拷贝驱动文件

如果能够绕过其中的限制，将恶意DLL复制到驱动目录并加载，就可以完成本地提权。

#### 检查驱动签名

`localspl!ValidateDriverInfo`在如下
