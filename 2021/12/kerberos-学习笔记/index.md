# Kerberos 学习笔记


## 基本知识

### Kerberos基本概念

Kerberos是一种第三方认证协议，通过使用对称加密技术为客户端/服务器应用程序提供强身份验证。在希腊神话中Kerberos是守护地狱之门的一条三头神犬，而这三个头分别代表着协议的三个角色，如下图所示它们分别是：  

![KDC架构](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/KDC架构.png "KDC架构.png")

1. 访问服务的Client
2. 提供服务的Server
3. KDC，密钥分发中心，该中心里又包含以下两个服务：
   - AS，身份验证服务
   - TGS，票据授权服务

在Windows域中通常由DC扮演其中的KDC进行所有票据的发放。DC中会默认创建一个Krbtgt账户，对应着Kerberos的认证服务。

### Kerberos基本流程

Kerberos认证主要通过三个子协议来完成，它们分别为：

- Authentication Service Exchange，身份认证服务交换，是Client与AS之间交互，包含KRB_AS_REQ和KRB_AS_REP两个包。
- Ticket-Granting Service (TGS) Exchange，票据授权服务交换，是Client与TGS之间交互，包含KRB_TGS_REQ和KRB_TGS_REP两个包。
- Client/Server Authentication Exchange，客户端/服务认证交换，是Client与Server之间交互，包含KRB_AP_REQ和KRB_AP_REP两个包。

具体流程如下图所示：

![Kerberos流程图](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/Kerberos流程图.png "Kerberos流程图.png")

1. **AS_REQ**: Client向KDC发起AS_REQ,请求凭据是Client hash加密的时间戳
2. **AS_REP**: KDC使用Client hash进行解密，如果结果正确就返回用krbtgt hash加密的TGT票据，TGT里面包含PAC,PAC包含Client的sid，Client所在的组。
3. **TGS_REQ**: Client凭借TGT票据向KDC发起针对特定服务的TGS_REQ请求
4. **TGS_REP**: KDC使用krbtgt hash进行解密，如果结果正确，就返回用服务hash 加密的TGS票据(这一步不管用户有没有访问服务的权限，只要TGT正确，就返回TGS票据)
5. **AP_REQ**: Client拿着TGS票据去请求服务
6. **AP_REP**: 服务使用自己的hash解密TGS票据。如果解密正确，就拿着PAC去KDC那边问Client有没有访问权限，域控解密PAC。获取Client的sid，以及所在的组，再根据该服务的ACL，判断Client是否有访问服务的权限。

### Kerberos委派

委派（Delegation）是kerberos相对于NTLM认证独有的特性，指的是A可以让B“代理”自己去访问C服务，说是代理，也可以理解为“假冒”。

具体为：域中A使用Kerberos身份验证访问域中的服务B，而B再利用A的身份去请求域中的服务C，因为用的是A的身份，所以只有A有权限访问C的时候，委派才能成功。
委派存在三种形式：

- 非约束委派
- 约束委派
- 基于资源的约束委派

## 调试分析基本流程

DC：Windows Server 2003 调试版  IP：192.168.45.10
Client1：Windows Server 2003 调试版  IP：192.168.45.11
Client2：Windows 7  IP：192.168.45.15
**以下调试信息并非全部在同一次认证过程中截取**

### AS_REQ

当Clinet1用密码进行交互登陆时，其会向AS（由域控扮演）发送`AS_REQ`
AS_REQ: Client向KDC发起AS_REQ,请求凭据是Client hash加密的时间戳，请求TGT票据

调用堆栈如下：

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo1.png "kerberos-debuginfo1.png")

其中的`Logon Session`中存在当前账户的`NTLMHash`，之后便是用这个Hash去加密时间戳

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo2.png "kerberos-debuginfo2.png")

对KDC请求的服务名称为`krbtgt`

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo3.png "kerberos-debuginfo3.png")

之后会在`KerbBuildPreAuthData`中生成`PreAuthData`的认证消息，其中便包括使用用户Hash加密的时间戳

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo4.png "kerberos-debuginfo4.png")

``` cpp
KerbErr = KerbEncryptDataEx(
            &EncryptedData,
            EncryptedTimeSize,
            EncryptedTime,
            KERB_NO_KEY_VERSION,
            KERB_ENC_TIMESTAMP_SALT,
            UserKey
            );
```

该函数实现了加密过程，其中
`EncryptedTime`为打包后的时间戳
`UserKey`为用户Hash
`EncryptedData.cipher_text`为加密后的数据

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo5.png "kerberos-debuginfo5.png")

图中标记分别为用户Hash和加密后的时间戳
最后便是将认证包打包发送

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo6.png "kerberos-debuginfo6.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo7.png "kerberos-debuginfo7.png")

通过Wireshark抓包查看padata与分析一致

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo8.png "kerberos-debuginfo8.png")

### AS_REP

**AS_REP**: KDC使用Client hash进行解密，如果结果正确就返回用krbtgt hash加密的TGT票据，TGT里面包含PAC,PAC包含Client的sid，Client所在的组。

KDC会在KdcCheckPreAuthData函数中对所接收到的数据包进行检查。在
KdcVerifyEncryptedTimeStamp中使用用户Hash对PreAuthData进行解密，查看是否正确，时间偏差是否在信任范围内

``` cpp
KerbErr = KdcVerifyEncryptedTimeStamp(
            ListElement,
            ClientTicketInfo,
            RequestBody,
            UserHandle,
            &OutputElement,
            UsedOldPassword
            );
```

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo9.png "kerberos-debuginfo9.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo10.png "kerberos-debuginfo10.png")

之后会通过PacOptions确定是否需要建立PAC  

通过BuildTicketAS函数生成返回的AS_REP内容，
其中的encrypted_part. cipher_text为TGT，此时还未加密可以导出明文
其中key为Client与KDC通信所需要的Logon Session Key
authorization_data为PAC，会在下一步生成并填入其中

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo11.png "kerberos-debuginfo11.png")

之后会根据之前保存的标志确定是否构建PAC，会在KdcGetPacAuthData中构建PAC并对其进行签名后加入到上方TGT中的authorization_data中

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo12.png "kerberos-debuginfo12.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo13.png "kerberos-debuginfo13.png")

其实质上应该是`_KERB_VALIDATION_INFO`结构体，其中包括了登陆用户的一些信息。

``` cpp
 typedef struct _KERB_VALIDATION_INFO {
   FILETIME LogonTime;
   FILETIME LogoffTime;
   FILETIME KickOffTime;
   FILETIME PasswordLastSet;
   FILETIME PasswordCanChange;
   FILETIME PasswordMustChange;
   RPC_UNICODE_STRING EffectiveName;
   RPC_UNICODE_STRING FullName;
   RPC_UNICODE_STRING LogonScript;
   RPC_UNICODE_STRING ProfilePath;
   RPC_UNICODE_STRING HomeDirectory;
   RPC_UNICODE_STRING HomeDirectoryDrive;
   USHORT LogonCount;
   USHORT BadPasswordCount;
   ULONG UserId;
   ULONG PrimaryGroupId;
   ULONG GroupCount;
   [size_is(GroupCount)] PGROUP_MEMBERSHIP GroupIds;
   ULONG UserFlags;
   USER_SESSION_KEY UserSessionKey;
   RPC_UNICODE_STRING LogonServer;
   RPC_UNICODE_STRING LogonDomainName;
   PISID LogonDomainId;
   ULONG Reserved1[2];
   ULONG UserAccountControl;
   ULONG SubAuthStatus;
   FILETIME LastSuccessfulILogon;
   FILETIME LastFailedILogon;
   ULONG FailedILogonCount;
   ULONG Reserved3;
   ULONG SidCount;
   [size_is(SidCount)] PKERB_SID_AND_ATTRIBUTES ExtraSids;
   PISID ResourceGroupDomainSid;
   ULONG ResourceGroupCount;
   [size_is(ResourceGroupCount)] PGROUP_MEMBERSHIP ResourceGroupIds;
 } KERB_VALIDATION_INFO;
```

创建Reply消息，ReplyBody中包含最重要的就是Logon Session Key,该结构会使用Client Hash加密；明文TGT使用krbtgt hash进行加密  
加密后的ReplyBody

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo14.png "kerberos-debuginfo14.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo15.png "kerberos-debuginfo15.png")

加密后的TGT

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo16.png "kerberos-debuginfo16.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo17.png "kerberos-debuginfo17.png")

### TGS_REQ

**TGS_REQ**: Client凭借TGT票据向KDC发起针对特定服务的TGS_REQ请求
**AP_REQ**: Client拿着TGS票据去请求服务

Windows将这两步融合在了一起，具体信息可以Wireshark抓包查看

Client会在KerbMakeKdcCall中接收到KDC返回的AS_REP消息

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo18.png "kerberos-debuginfo18.png")

解包后内容，其中ticket就是加密后的TGT，encrypted_part为加密后的ReplyBody

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo19.png "kerberos-debuginfo19.png")

使用ClientKey对ReplyBody进行解密，获得Logon Session Key

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo20.png "kerberos-debuginfo20.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo21.png "kerberos-debuginfo21.png")

TGT由于是被Krbtgt hash加密的，并不能解密获得明文，而是使用它来认证自身的身份。其会被保存在本地，通过KerbCreateTicketCacheEntry建立一个新的TicketCacheEntry进行保存

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo22.png "kerberos-debuginfo22.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo23.png "kerberos-debuginfo23.png")

至此认证过程完全完成，下一步将向KDC请求ST（Service Ticket）

为了体现更加通用的场景，以下的Kerberos认证过程触发方式不再是用户登陆
Client1向KDC请求某一个共享文件夹的访问权限
命令：`dir \\KDCComputerName\C$`

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo24.png "kerberos-debuginfo24.png")

Client会在KerbGetServiceTicket中向KDC发起申请ST的TGS请求

首先会通过KerbGetTgtForService进行身份认证，即上述两次通信过程，获得的TGT储存在第7参数TicketGrantingTicket中

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo25.png "kerberos-debuginfo25.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo26.png "kerberos-debuginfo26.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo27.png "kerberos-debuginfo27.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo28.png "kerberos-debuginfo28.png")

之后使用KerbGetTgsTicket这个函数，通过TGT申请TGS

创建RequestBody，其中主要信息为我们所申请的服务名称

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo29.png "kerberos-debuginfo29.png")

由于我们要证明自己确实是向KDC申请TGT的机器，所以必须将该结构使用只有KDC与自己两个人知道的Key进行签名，即是用Logon Session Key进行签名
所以便会调用KerbComputeTgsChecksum进行签名

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo30.png "kerberos-debuginfo30.png")

Windows上的TgsRequest的TGT和身份认证部分都由Aprequest结果保存

通过KerbCreateApRequest创建ApRequest
通过KerbCreateAuthenticator创建Authenticator
将上面的checksum放入该结构体中，之后使用Logon Session Key进行加密

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo31.png "kerberos-debuginfo31.png")

至此ApRequest创建完成，其中包含
Krbtgt Hash 加密的TGT
Logon Session 加密的 Authenticator
最后在kerberos!KerbMakeSocketCall中发送

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo32.png "kerberos-debuginfo32.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo33.png "kerberos-debuginfo33.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo34.png "kerberos-debuginfo34.png")

![kerberos-debuginfo1](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo35.png "kerberos-debuginfo35.png")

### TGS_REP

**TGS_REP**: KDC使用krbtgt hash进行解密，如果结果正确，就返回用服务hash 加密的TGS票据(这一步不管用户有没有访问服务的权限，只要TGT正确，就返回TGS票据)

KDC在HandleTGSRequest中处理TGS_REQ消息
首先，通过krbtgt hash解密查看票据是否合法

![kerberos-debuginfo36](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo36.png "kerberos-debuginfo36.png")

之后，计算检查CheckSum中的签名

![kerberos-debuginfo37](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo37.png "kerberos-debuginfo37.png")

KDC在I_GetTGSTicket中构造TGS

![kerberos-debuginfo38](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo38.png "kerberos-debuginfo38.png")

通过KdcGetTicketInfo函数获取构建Ticket需要的信息

![kerberos-debuginfo39](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo39.png "kerberos-debuginfo39.png")

![kerberos-debuginfo40](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo40.png "kerberos-debuginfo40.png")

构建TGSTicket

![kerberos-debuginfo41](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo41.png "kerberos-debuginfo41.png")

Ticket内容如下

![kerberos-debuginfo42](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo42.png "kerberos-debuginfo42.png")

向其中添加对于客户端的认证信息
包括证书的有效时间和认证信息

![kerberos-debuginfo43](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo43.png "kerberos-debuginfo43.png")

最后申请Reply结构并进行填充，和之前一样进行打包加密
Ticket为用ServerHash加密的TGSTicket
enc-part为使用Logon Session Key加密的认证消息，包含Client和Server建立会话的Session Key

![kerberos-debuginfo44](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo44.png "kerberos-debuginfo44.png")

![kerberos-debuginfo45](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo45.png "kerberos-debuginfo45.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo46.png "kerberos-debuginfo46.png")

### AP_REQ & AS_REP

在TGS的请求过程中对于身份的验证便是通过AP_REQ，所以不再赘述

## 委派分析

### 非约束委派

#### 基本流程

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo47.png "kerberos-debuginfo47.png")

上图描述了以下协议步骤：

1. 用户通过发送KRB_AS_REQ消息请求可转发 TGT（forwardable TGT，为了方便我们称为TGT1）
2. KDC在KRB_AS_REP消息中返回TGT1
3. 用户再通过TGT1向KDC请求转发TGT（forwarded TGT，我们称为TGT2）
4. 在KRB_TGS_REP消息中返回转发TGT2
5. 用户使用TGT1向KDC申请访问Service1的ST（ServiceTicket）
6. TGS返回给用户一个ST
7. 用户发送KRB_AP_REQ请求至Service1，这个请求中包含了TGT1和ST、TGT2、TGT2的SessionKey
8. Service1使用用户的TGT2通过KRB_TGS_REQ发送给KDC，以用户的名义请求能够访问Service2的票据
9. KDC在KRB_TGS_REP消息中返回Service2到Service1的票据
10. Service1以用户的名义向Service2发送KRB_AP_REQ请求
11. Service2响应步骤10中Service1的请求
12. Service1响应步骤7中用户的请求
13. 在这个过程中的TGT转发机制，没有限制Service1对TGT2的使用，也就是说Service1可以通过TGT2来请求任意服务
14. KDC返回步骤13中请求的票据，15和16即为Service1通过模拟用户来访问其他Service
当user访问service1时，如果service1的服务账号开启了unconstrained delegation（非约束委派），则当user访问service1时会将user的TGT发送给service1并保存在内存中以备下次重用，然后service1 就可以利用这张TGT以user的身份去访问域内的任何服务（任何服务是指user能访问的服务）了

#### 配置

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo48.png "kerberos-debuginfo48.png")

每个账户都存在一个属性值UserAccountControl，其值可以决定Kerberos委派的性质
具体的值及其对应含义请参考：<https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties>
使用SysinternalsSuite中的ADExplorer工具可以很方便的查看AD域中的所有属性

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo49.png "kerberos-debuginfo49.png")

和非约束委派相关的属性为0x80000

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo50.png "kerberos-debuginfo50.png")

#### 调试分析

正常情况下一次请求只会出现一次TGS_REQ
但是在开启非约束委派的情况下会发起两次

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo51.png "kerberos-debuginfo51.png")

其中途中标号为9的请求对应上述描述中的第5步，为客户端请求需要的服务的ST的过程
所以kdc-options中的forwarded为0
sname为cifs

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo53.png "kerberos-debuginfo53.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo54.png "kerberos-debuginfo54.png")

标号为17的请求为对于TGT2（forwarded TGT）的请求，对应上述描述中的第3步
所以kdc-options中的forwarded为1
sname为krbtgt

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo55.png "kerberos-debuginfo55.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo56.png "kerberos-debuginfo56.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo57.png "kerberos-debuginfo57.png")

TGT2--- TicketGrantingTicket
TGT2的SessionKey---TicketGrantingTicket. SessionKey
TGT1--- TicketGrantingTicket.Ticket

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo58.png "kerberos-debuginfo58.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo59.png "kerberos-debuginfo59.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo60.png "kerberos-debuginfo60.png")

KerbBuildGssChecksum的第三参数Ticket即为ServiceTicket

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo61.png "kerberos-debuginfo61.png")

之后会将该结果后打包加密后放入CheckSumBody->DelegationInfo中

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo62.png "kerberos-debuginfo62.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo63.png "kerberos-debuginfo63.png")

### 约束委派

#### 基本流程

约束委派在Kerberos中User不会直接发送TGT给服务，而是对发送给service1的认证信息做了限制，不允许service1代表User使用这个TGT去访问其他服务。其中包括一组名为S4U2Self（Service for User to Self）和S4U2Proxy（Service for User to Proxy）的Kerberos协议扩展。

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo64.png "kerberos-debuginfo64.png")

请求过程如下：

1. 用户向Service1发送请求。
2. 这时在官方文档中的介绍是在这一流程开始之前Service1已经通过KRB_AS_REQ得到了用户用来访问Service1的TGT，然后通过S4U2self扩展模拟用户向KDC请求ST。
3. KDC这时返回给Service1一个用于用户验证Service1的ST（我们称为ST1），并且Service1用这个ST1完成和用户的验证过程。
4. Service1在步骤3使用模拟用户申请的ST1完成与用户的验证，然后响应用户。
注：这个过程中其实Service1是获得了用户的TGT和ST1的，但是S4U2Self扩展不允许Service1代表用户去请求其他的服务。
5. 用户再次向Service1发起请求，此时Service1需要以用户的身份访问Service2。这里官方文档提到了两个点：
A.Service1已经验证通过，并且有一个有效的TGT。
B.Service1有从用户到Service1的forwardableST（可转发ST）。个人认为这里的forwardable ST其实也就是ST1。
6. Service1代表用户向Service2请求一个用于认证Service2的ST（我们称为ST2）。用户在ST1中通过cname（client name）和crealm（client realm）字段标识。
7. KDC在接收到步骤6中Service1的请求之后，会验证PAC（特权属性证书，在第一篇中有说明）的数字签名。如果验证成功或者这个请求没有PAC（不能验证失败），KDC将返回ST2给Service1，不过这个ST2中cname和crealm标识的是用户而不是Service1。
8. Service1代表用户使用ST2请求Service2。Service2判断这个请求来自已经通过KDC验证的用户。
9. Service2响应Service1的请求。
10. Service1响应用户的请求。

在这个过程中：
**S4U2self可以代表自身请求针对其自身的Kerberos服务票据(ST)**
**S4U2proxy可以以用户的名义请求其它服务的ST**
同时注意forwardable字段，有forwardable标记为可转发的是能够通过S4U2Proxy扩展协议进行转发的，如果没有标记则不能进行转发。
最后的结果：**在约束委派中服务账号只能获取某用户的ST（也就是TGS），所以只能模拟用户访问特定的服务，是无法获取用户的TGT，如果我们能获取到开启了约束委派的服务用户的明文密码或者NTLM Hash，我们就可以伪造S4U请求，进而伪装成服务用户以任意账户的权限申请访问某服务的ST**

#### 配置

Windows Server 2003 已经支持约束委派，但是并没有可视化的设置界面，需要通过ADExplorer工具修改属性值，开启约束委派。

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo65.png "kerberos-debuginfo65.png")

约束委派对应值为

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo66.png "kerberos-debuginfo66.png")

#### 调试分析

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo67.png "kerberos-debuginfo67.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo68.png "kerberos-debuginfo68.png")

步骤2中S4U2Self是通过KerbGetS4USelfServiceTicket函数完成。
首先获取Service自身的TGT，进行身份认证

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo69.png "kerberos-debuginfo69.png")

其次将“冒充”客户的身份去申请针对自身的TGS

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo70.png "kerberos-debuginfo70.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo71.png "kerberos-debuginfo71.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo72.png "kerberos-debuginfo72.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo73.png "kerberos-debuginfo73.png")

 步骤5中的S4U2Proxy在KerbGetServiceTicketByS4UProxy中完成
与以往不同的是这次会存在一个AdditionTicket，其中是上一步返回的TGS
在KDC中会对这个AdditionTicket进行检查
其中最重要的一步便是通过KerbCheckA2D2Attribute对委派进行限制，只有
msDS-AllowedToDelegateto中存在的项才允许访问 返回TGS

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo75.png "kerberos-debuginfo75.png")

检查通过后KdcUnpackAdditionalTickets会返回S4UTicketInfo
内容如下
 ![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo76.png "kerberos-debuginfo76.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo77.png "kerberos-debuginfo77.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo78.png "kerberos-debuginfo78.png")

![kerberos-debuginfo46](https://raw.githubusercontent.com/dre4merp/Drawing-bed/main/images/kerberos-debuginfo79.png "kerberos-debuginfo79.png")

之后便是正常的返回TGS的流程

### 基于资源的约束委派

在约束委派中，对于计算机或服务账户的属性设置只能由域管理员进行设置，配置其是否可以委派和委派的服务列表。但是在Windows Server 2008后引入了基于资源的约束委派（Resource-based constrained delegation）。计算机的用户属性中新添了一个全新的项，名为msDS-AllowedToActOnBehalfOfOtherIdentity，这个属性的设置由计算机本身进行，其可以控制谁可以被委托来访问自己的某些资源
之前的约束委派限制的是Service1是否可以委派其他人，现在基于资源的约束委派可以保证Service2控制自身资源的访问限制，一个是在发起者方进行限制，一个是在接收者方进行防护。
基于资源的约束委派（Resource-based constrained delegation），它除了不再需要域管理员权限去设置相关属性之外，请求ST的过程是和传统的约束委派大同小异，要注意一点就是传统的约束S4U2Self返回的票据一定是可转发的，如果不可转发那么S4U2Proxy将失败；但是基于资源约束委派不同，就算S4U2Self返回的票据不可转发（可不可以转发由TrustedToAuthenticationForDelegation决定），S4U2Proxy也是可以成功，并且S4U2Proxy返回的票据总是可转发。

