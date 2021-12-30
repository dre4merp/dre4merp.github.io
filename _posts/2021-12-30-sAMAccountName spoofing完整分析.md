---
layout: article
title:      "sAMAccountName spoofing完整分析"
date:       2021-12-30 12:00:00
tags:
    - sAMAccountName
---

## 背景
  
漏洞编号为：`CVE-2021-42278` 和 `CVE-2021-42287`

CVE-2021-42278：通常情况下，机器账户应以\$结尾，即`DC$`。
但是AD域并没有对其进行强校验。通过建立与域控同名却不以\$结尾的机器账户，即`DC`，对域控进行欺骗。

- [MSRC CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [KB5008102 CVE-2021-42278](https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e)

CVE-2021-42287：利用上述漏洞进行欺骗，请求到DC的TGT后，修改自身的机器账号。之后，利用Kerberos的S4U2Self机制，请求对于“自己”（`DC`）的ST，但是由于此时机器名已经被修改而无法找到`DC`，域控将会用`DC$`的Key进行加密，并向其中添加请求的账户名的PAC。至此便得到了高权限ST。

- [MSRC CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)
- [KB5008102 CVE-2021-42287](https://support.microsoft.com/en-gb/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041)

## 环境配置

域控：Windows Server 2003 Debug版  
攻击机：Windows 7 x64 SP1  
武器化工具：<https://github.com/cube0x0/noPac>  

## 详细分析

### Active Directory 目录树

使用SysinternalsSuite中的ADExplorer64工具查看域内的所有机器账户  

![ADExplorer](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/ADExplorer.png)

~~上图显示了Active Directory中的完整目录树，其中需要注意的是Computers和Domain Controllers这两项在目录树中的相对位置，正是由于Computer在前，在遍历目录树时才会先获得新建的DC同名账户。~~  
从上图中可以很明确的看到域控的机器名为`WINSRVSERVER$`，之后会使用`WINSRVSERVER`作为机器账户名进行欺骗。

### 攻击准备工作

相关准备工作不是本文重点，可以在noPac项目中学习

``` c#
//new machine account
NewMachineAccount(argContainer, argDistinguishedName, argDomain, argDomainController, argMachineAccount, argMachinePassword, argVerbose, argRandom, credential);

//clean spn
SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, "serviceprincipalname", argMachineAccount, "", false, true, argVerbose, credential);

//set samaccountname
SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, "samaccountname", argMachineAccount, argDomainController.Split('.')[0], false, false, argVerbose, credential);
```

### 申请TGT

申请TGT时是根据修改后的机器账号`WINSRVSERVER`进行申请的。  
域控调用`I_GetASTicket`处理`AS_REQ`消息  
首先会调用`KdcNormalize`获得账户的相关信息包括`UserInfo`、`ClientTicketInfo`等  
！！！请谨记这个函数，之后的漏洞利用过程会展开分析！！！

``` cpp
KerbErr = KdcNormalize(
                ClientName,
                NULL,
                RequestRealm,
                NULL,           // no source ticket
                NameFlags | KDC_NAME_CLIENT | KDC_NAME_FOLLOW_REFERRALS | KDC_NAME_CHECK_GC,
                FALSE,          // do not restrict user accounts (user2user)
                &ClientReferral,
                ClientRealm,
                &ClientTicketInfo,
                pExtendedError,
                &UserHandle,
                WhichFields,
                0L,
                &UserInfo,
                &GroupMembership
                );
```

通过上面获得的`ClientTicketInfo`调用`BuildTicketAS`生成TGT，堆栈如下

``` text
kd> kc
# 
00 KDCSVC!BuildTicketAS
01 KDCSVC!I_GetASTicket
02 KDCSVC!KdcGetTicket
03 KDCSVC!KdcAtqIoCompletion
04 NTDSATQ!ATQ_CONTEXT::IOCompletion
05 NTDSATQ!AtqpProcessContext
06 NTDSATQ!AtqPoolThread
07 kernel32!BaseThreadStart
```

查看参数ClientTicketInfo和ClientName可以看到此次是以`WINSRVSERVER`的身份去申请TGT。  

``` text
kd> dt ClientTicketInfo
Local var @ 0x332fa00 Type _KDC_TICKET_INFO*
0x0332fcb4 
   +0x000 AccountName      : _UNICODE_STRING "WINSRVSERVER"
   +0x008 TrustedForest    : _UNICODE_STRING ""
   +0x010 PasswordExpires  : _LARGE_INTEGER 0x7fffffff`ffffffff
   +0x018 fTicketOpts      : 0x7b
   +0x01c UserAccountControl : 0x80
   +0x020 UserId           : 0x472
   +0x024 TrustType        : 0
   +0x028 TrustAttributes  : 0
   +0x02c Passwords        : 0x0015eab8 _KERB_STORED_CREDENTIAL
   +0x030 OldPasswords     : 0x001522d0 _KERB_STORED_CREDENTIAL
   +0x034 TrustSid         : (null) 
   +0x038 PasswordVersion  : 1
   +0x03c LockoutThreshold : 0
kd> dt ClientName
Local var @ 0x332fa04 Type KERB_PRINCIPAL_NAME*
0x00084c44 
   +0x000 name_type        : 0n1
   +0x004 name_string      : 0x000c3360 KERB_PRINCIPAL_NAME_name_string_s
kd> dx -id 0,0,89c47a68 -r1 ((KDCSVC!KERB_PRINCIPAL_NAME_name_string_s *)0xc3360)
((KDCSVC!KERB_PRINCIPAL_NAME_name_string_s *)0xc3360)                 : 0xc3360 [Type: KERB_PRINCIPAL_NAME_name_string_s *]
    [+0x000] next             : 0x0 [Type: KERB_PRINCIPAL_NAME_name_string_s *]
    [+0x004] value            : 0xb45d8 : "WINSRVSERVER" [Type: char *]
```

上述函数工作完成后，查看生成的Ticket，即`TGT`

``` text
kd> dt KERB_ENCRYPTED_TICKET 0x332fabc
KDCSVC!KERB_ENCRYPTED_TICKET
   +0x000 bit_mask         : 0xc0
   +0x000 o                : [1]  "???"
   +0x004 flags            : tagASN1bitstring_t
   +0x00c key              : KERB_ENCRYPTION_KEY
   +0x018 client_realm     : 0x000c5098  "RENPENGYU03.COM"
   +0x01c client_name      : KERB_PRINCIPAL_NAME
   +0x024 transited        : KERB_TRANSITED_ENCODING
   +0x030 authtime         : tagASN1generalizedtime_t
   +0x03e starttime        : tagASN1generalizedtime_t
   +0x04c endtime          : tagASN1generalizedtime_t
   +0x05a renew_until      : tagASN1generalizedtime_t
   +0x068 client_addresses : (null) 
   +0x06c authorization_data : (null) 
```

此时还没有向其中添加PAC，会通过之前获得的`UserInfo`调用`KdcGetPacAuthData`生成所需的PAC  
此时的PAC为`WINSRVSERVER`的PAC，属于正常流程

``` text
kd> dt AuthorizationData
Local var @ 0x332f9d0 Type PKERB_AUTHORIZATION_DATA_s
   +0x000 next             : (null) 
   +0x004 value            : PKERB_AUTHORIZATION_DATA_Seq
kd> dx -id 0,0,89c47a68 -r1 (*((KDCSVC!PKERB_AUTHORIZATION_DATA_Seq *)0x332f9d4))
(*((KDCSVC!PKERB_AUTHORIZATION_DATA_Seq *)0x332f9d4))                 [Type: PKERB_AUTHORIZATION_DATA_Seq]
    [+0x000] auth_data_type   : 128 [Type: long]
    [+0x004] auth_data        [Type: tagASN1octetstring_t]
kd> dx -id 0,0,89c47a68 -r1 (*((KDCSVC!tagASN1octetstring_t *)0x332f9d8))
(*((KDCSVC!tagASN1octetstring_t *)0x332f9d8))                 [Type: tagASN1octetstring_t]
    [+0x000] length           : 0x260 [Type: unsigned long]
    [+0x004] value            : 0x16c828 : 0x4 [Type: unsigned char *]
kd> db 0x16c828 l 260
0016c828  04 00 00 00 00 00 00 00-01 00 00 00 c0 01 00 00  ................
0016c838  48 00 00 00 00 00 00 00-0a 00 00 00 22 00 00 00  H..........."...
0016c848  08 02 00 00 00 00 00 00-06 00 00 00 14 00 00 00  ................
0016c858  30 02 00 00 00 00 00 00-07 00 00 00 14 00 00 00  0...............
0016c868  48 02 00 00 00 00 00 00-01 10 08 00 cc cc cc cc  H...............
0016c878  b0 01 00 00 00 00 00 00-00 00 02 00 c2 dd c3 d9  ................
0016c888  0f f7 d7 01 ff ff ff ff-ff ff ff 7f ff ff ff ff  ................
0016c898  ff ff ff 7f 56 b9 d8 d7-0f f7 d7 01 56 79 42 02  ....V.......VyB.
0016c8a8  d9 f7 d7 01 ff ff ff ff-ff ff ff 7f 18 00 18 00  ................
0016c8b8  04 00 02 00 00 00 00 00-08 00 02 00 00 00 00 00  ................
0016c8c8  0c 00 02 00 00 00 00 00-10 00 02 00 00 00 00 00  ................
0016c8d8  14 00 02 00 00 00 00 00-18 00 02 00 01 00 00 00  ................
0016c8e8  72 04 00 00 03 02 00 00-01 00 00 00 1c 00 02 00  r...............
0016c8f8  20 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00   ...............
0016c908  00 00 00 00 18 00 1a 00-20 00 02 00 16 00 18 00  ........ .......
0016c918  24 00 02 00 28 00 02 00-00 00 00 00 00 00 00 00  $...(...........
0016c928  80 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0016c938  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0016c948  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0016c958  00 00 00 00 0c 00 00 00-00 00 00 00 0c 00 00 00  ................
0016c968  57 00 49 00 4e 00 53 00-52 00 56 00 53 00 45 00  W.I.N.S.R.V.S.E.
0016c978  52 00 56 00 45 00 52 00-00 00 00 00 00 00 00 00  R.V.E.R.........
0016c988  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0016c998  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0016c9a8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0016c9b8  00 00 00 00 01 00 00 00-03 02 00 00 07 00 00 00  ................
0016c9c8  0d 00 00 00 00 00 00 00-0c 00 00 00 57 00 49 00  ............W.I.
0016c9d8  4e 00 53 00 52 00 56 00-53 00 45 00 52 00 56 00  N.S.R.V.S.E.R.V.
0016c9e8  45 00 52 00 0c 00 00 00-00 00 00 00 0b 00 00 00  E.R.............
0016c9f8  52 00 45 00 4e 00 50 00-45 00 4e 00 47 00 59 00  R.E.N.P.E.N.G.Y.
0016ca08  55 00 30 00 33 00 00 00-04 00 00 00 01 04 00 00  U.0.3...........
0016ca18  00 00 00 05 15 00 00 00-db ac e2 f8 a5 b2 f3 d1  ................
0016ca28  a1 c4 3e 10 00 00 00 00-00 b4 a3 e5 0f f7 d7 01  ..>.............
0016ca38  18 00 57 00 49 00 4e 00-53 00 52 00 56 00 53 00  ..W.I.N.S.R.V.S.
0016ca48  45 00 52 00 56 00 45 00-52 00 00 00 00 00 00 00  E.R.V.E.R.......
0016ca58  76 ff ff ff c1 fc e6 ad-46 30 3f 05 5e ed 74 c0  v.......F0?.^.t.
0016ca68  20 7d c9 54 00 00 00 00-76 ff ff ff 42 e1 22 e3   }.T....v...B.".
0016ca78  3b 44 cd ee b7 d7 50 5f-2d f9 44 ab 00 00 00 00  ;D....P_-.D.....
```

之后便是将PAC放入TGT中，将其打包并使用`krbtgt`密钥进行加密，通过`AS_REP`消息传递回Client  
关键代码如下，不再展开分析

``` cpp
KerbErr = BuildReply(
            &ClientTicketInfo,
            (Nonce != 0) ? Nonce : RequestBody->nonce,
            &Ticket.server_name,
            Ticket.realm,
            ((RequestBody->bit_mask & addresses_present) != 0) ? RequestBody->addresses : NULL,
            &Ticket,
            &ReplyBody
            );
...  
KerbErr = KerbPackTicket(
            &Ticket,
            ServerKey,
            ServiceTicketInfo.PasswordVersion,
            &Reply.ticket
            );
...
KerbErr = KerbPackKdcReplyBody(
        &ReplyBody,
        (EncryptionKey.keyvalue.value != NULL) ? &EncryptionKey : ClientKey,
        (EncryptionKey.keyvalue.value != NULL) ? KERB_NO_KEY_VERSION : ClientTicketInfo.PasswordVersion,
        KERB_TGS_REP_SALT,
        KERB_ENCRYPTED_AS_REPLY_PDU,
        &Reply.encrypted_part
        );
```

### 还原机器账户名

还原机器账户名的目的是使得域控处理`TGS_REQ`请求的时候，找不到账户从而是用自己的Key加密

``` c#
//undo samaccountname change
SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, "samaccountname", argMachineAccount, argMachineAccount, false, false, argVerbose, credential);
```

### 申请ST

Client向域控申请`WINSRVSERVER`的服务票据，域控在`HandleTGSRequest`函数中处理`TGS_REQ`请求。  

首先通过`KerbFindPreAuthDataEntry`获取`TGS_REQ`中包含的`ApRequest`  

``` cpp
ApRequest = KerbFindPreAuthDataEntry(
                KRB5_PADATA_TGS_REQ,
                RequestMessage->KERB_KDC_REQUEST_preauth_data
                );
```

之后便是解析获得的`APRequest`获得解密后的`TGT`

``` cpp
//验证请求。这包括对AP请求进行解码，找到合适的密钥来解密票据，并检查票据。
KerbErr = KdcVerifyKdcRequest(
            ApRequest->preauth_data.value,
            ApRequest->preauth_data.length,
            ClientAddress,
            TRUE,                           // this is a kdc request
            &UnmarshalledApRequest,
            &UnmarshalledAuthenticator,
            &SourceEncryptPart,
            &ReplyKey,
            &SourceTicketKey,
            &ServerTicketInfo,
            &UseSubKey,
            pExtendedError
            );
```

KdcVerifyKdcRequest做了以下几件事情

- KdcVerifyKdcRequest
  - 解包ApRequest ---- KerbUnpackApRequest
  - 根据其中的服务名（kbrtgt）获取服务的相关信息 ---- KdcNormalize
  - 通过相关信息找到服务的Hash ---- KerbGetKeyFromList
  - 解密TGT --- KerbCheckTicket
    - 获得解密后的TGT --- KerbVerifyTicket
    - 用TGT中的Key（key为Client与KDC通信所需要的LogonSessionKey）解密获得Authenticator --- KerbUnpackAuthenticator
  - ……（校验检查之类的）

查看这个函数的结果，获得了传过来的明文`TGT`和`krbtgt`的相关服务信息

``` text
kd> dt ServerTicketInfo
Local var @ 0x327fc48 Type _KDC_TICKET_INFO
   +0x000 AccountName      : _UNICODE_STRING "krbtgt"
   +0x008 TrustedForest    : _UNICODE_STRING ""
   +0x010 PasswordExpires  : _LARGE_INTEGER 0x7fffffff`ffffffff
   +0x018 fTicketOpts      : 0x7b
   +0x01c UserAccountControl : 0x11
   +0x020 UserId           : 0x1f6
   +0x024 TrustType        : 0
   +0x028 TrustAttributes  : 0
   +0x02c Passwords        : 0x00084bf0 _KERB_STORED_CREDENTIAL
   +0x030 OldPasswords     : 0x000c4010 _KERB_STORED_CREDENTIAL
   +0x034 TrustSid         : (null) 
   +0x038 PasswordVersion  : 2
   +0x03c LockoutThreshold : 0

kd> dt SourceEncryptPart
Local var @ 0x327fdd0 Type KERB_ENCRYPTED_TICKET*
0x000fcf90 
   +0x000 bit_mask         : 0xd0
   +0x000 o                : [1]  "???"
   +0x004 flags            : tagASN1bitstring_t
   +0x00c key              : KERB_ENCRYPTION_KEY
   +0x018 client_realm     : 0x00106a18  "RENPENGYU03.COM"
   +0x01c client_name      : KERB_PRINCIPAL_NAME
   +0x024 transited        : KERB_TRANSITED_ENCODING
   +0x030 authtime         : tagASN1generalizedtime_t
   +0x03e starttime        : tagASN1generalizedtime_t
   +0x04c endtime          : tagASN1generalizedtime_t
   +0x05a renew_until      : tagASN1generalizedtime_t
   +0x068 client_addresses : (null) 
   +0x06c authorization_data : 0x000c3370 PKERB_AUTHORIZATION_DATA_s

kd> db authorization_data l 276
0017f168  30 82 02 72 30 82 02 6e-a0 04 02 02 00 80 a1 82  0..r0..n........
0017f178  02 64 04 82 02 60 04 00-00 00 00 00 00 00 01 00  .d...`..........
0017f188  00 00 c0 01 00 00 48 00-00 00 00 00 00 00 0a 00  ......H.........
0017f198  00 00 22 00 00 00 08 02-00 00 00 00 00 00 06 00  ..".............
0017f1a8  00 00 14 00 00 00 30 02-00 00 00 00 00 00 07 00  ......0.........
0017f1b8  00 00 14 00 00 00 48 02-00 00 00 00 00 00 01 10  ......H.........
0017f1c8  08 00 cc cc cc cc b0 01-00 00 00 00 00 00 00 00  ................
0017f1d8  02 00 02 4e 81 c8 1c f7-d7 01 ff ff ff ff ff ff  ...N............
0017f1e8  ff 7f ff ff ff ff ff ff-ff 7f 56 b9 d8 d7 0f f7  ..........V.....
0017f1f8  d7 01 56 79 42 02 d9 f7-d7 01 ff ff ff ff ff ff  ..VyB...........
0017f208  ff 7f 18 00 18 00 04 00-02 00 00 00 00 00 08 00  ................
0017f218  02 00 00 00 00 00 0c 00-02 00 00 00 00 00 10 00  ................
0017f228  02 00 00 00 00 00 14 00-02 00 00 00 00 00 18 00  ................
0017f238  02 00 08 00 00 00 72 04-00 00 03 02 00 00 01 00  ......r.........
0017f248  00 00 1c 00 02 00 20 00-00 00 00 00 00 00 00 00  ...... .........
0017f258  00 00 00 00 00 00 00 00-00 00 18 00 1a 00 20 00  .............. .
0017f268  02 00 16 00 18 00 24 00-02 00 28 00 02 00 00 00  ......$...(.....
0017f278  00 00 00 00 00 00 80 00-00 00 00 00 00 00 00 00  ................
0017f288  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0017f298  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0017f2a8  00 00 00 00 00 00 00 00-00 00 0c 00 00 00 00 00  ................
0017f2b8  00 00 0c 00 00 00 57 00-49 00 4e 00 53 00 52 00  ......W.I.N.S.R.
0017f2c8  56 00 53 00 45 00 52 00-56 00 45 00 52 00 00 00  V.S.E.R.V.E.R...
0017f2d8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0017f2e8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0017f2f8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
0017f308  00 00 00 00 00 00 00 00-00 00 01 00 00 00 03 02  ................
0017f318  00 00 07 00 00 00 0d 00-00 00 00 00 00 00 0c 00  ................
0017f328  00 00 57 00 49 00 4e 00-53 00 52 00 56 00 53 00  ..W.I.N.S.R.V.S.
0017f338  45 00 52 00 56 00 45 00-52 00 0c 00 00 00 00 00  E.R.V.E.R.......
0017f348  00 00 0b 00 00 00 52 00-45 00 4e 00 50 00 45 00  ......R.E.N.P.E.
0017f358  4e 00 47 00 59 00 55 00-30 00 33 00 00 00 04 00  N.G.Y.U.0.3.....
0017f368  00 00 01 04 00 00 00 00-00 05 15 00 00 00 db ac  ................
0017f378  e2 f8 a5 b2 f3 d1 a1 c4-3e 10 00 00 00 00 00 06  ........>.......
0017f388  7d ec a5 f7 d7 01 18 00-57 00 49 00 4e 00 53 00  }.......W.I.N.S.
0017f398  52 00 56 00 53 00 45 00-52 00 56 00 45 00 52 00  R.V.S.E.R.V.E.R.
0017f3a8  00 00 00 00 00 00 76 ff-ff ff 51 30 b4 c6 f1 8c  ......v...Q0....
0017f3b8  bf 3d 01 2f 7c 3d 75 9b-9d 8d 00 00 00 00 76 ff  .=./|=u.......v.
0017f3c8  ff ff 5a 8c df 90 88 38-ec 5d 6c 61 b8 46 bd bf  ..Z....8.]la.F..
0017f3d8  99 5c 00 00 00 00                                .\....
```

之后会获取请求的相关信息

- 在REQUEST_BODY中获得ServerName
- 在TGT中获得cname和crealm

``` cpp
KerbErr = KerbConvertPrincipalNameToKdcName(
            &ServerName,
            &RequestBody->KERB_KDC_REQUEST_BODY_server_name
            );

KerbErr = KerbConvertPrincipalNameToKdcName(
               &SourceClientName,
               &SourceEncryptPart->client_name
               );

KerbErr = KerbConvertRealmToUnicodeString(
               &SourceClientRealm,
               &SourceEncryptPart->client_realm
               );           
```

内容分别如下

``` text
kd> dt ServerName
Local var @ 0x327fdd8 Type _KERB_INTERNAL_NAME*
0x00117610 
   +0x000 NameType         : 0n1
   +0x002 NameCount        : 1
   +0x004 Names            : [1] _UNICODE_STRING "WINSRVSERVER"

kd> dt SourceClientName
Local var @ 0x327fdd4 Type _KERB_INTERNAL_NAME*
0x0017f3e8 
   +0x000 NameType         : 0n1
   +0x002 NameCount        : 1
   +0x004 Names            : [1] _UNICODE_STRING "WINSRVSERVER"

kd> dt SourceClientRealm
Local var @ 0x327fdc4 Type _UNICODE_STRING
 "RENPENGYU03.COM"
   +0x000 Length           : 0x1e
   +0x002 MaximumLength    : 0x20
   +0x004 Buffer           : 0x00153578  "RENPENGYU03.COM"
```

之后会调用`KdcFindS4UClientAndRealm`来获取`PA_DATA_FOR_USER`这个结构中的内容  
`KdcFindS4UClientAndRealm`函数会解析`PaList`并将其转换成`KERB_PA_FOR_USER`结构，目前需要注意的便是其中的`userName`是我们要请求的高权限用户的用户名`Administrator`

``` text
kd> dt S4URequest
Local var @ 0x327f9b0 Type KERB_PA_FOR_USER*
0x0012aaa8 
   +0x000 bit_mask         : 0
   +0x000 o                : [1]  ""
   +0x004 userName         : KERB_PRINCIPAL_NAME
   +0x00c userRealm        : 0x0012abf0  "RENPENGYU03.COM"
   +0x010 cksum            : KERB_CHECKSUM
   +0x01c authentication_package : 0x000fca30  "Kerberos"
   +0x020 authorization_data : tagASN1octetstring_t
kd> dx -id 0,0,89de1678 -r1 (*((KDCSVC!KERB_PRINCIPAL_NAME *)0x12aaac))
(*((KDCSVC!KERB_PRINCIPAL_NAME *)0x12aaac))                 [Type: KERB_PRINCIPAL_NAME]
    [+0x000] name_type        : 10 [Type: long]
    [+0x004] name_string      : 0x82c98 [Type: KERB_PRINCIPAL_NAME_name_string_s *]
kd> dx -id 0,0,89de1678 -r1 ((KDCSVC!KERB_PRINCIPAL_NAME_name_string_s *)0x82c98)
((KDCSVC!KERB_PRINCIPAL_NAME_name_string_s *)0x82c98)                 : 0x82c98 [Type: KERB_PRINCIPAL_NAME_name_string_s *]
    [+0x000] next             : 0x0 [Type: KERB_PRINCIPAL_NAME_name_string_s *]
    [+0x004] value            : 0x159c88 : "renpengServer" [Type: char *]
```

之后会通过`KdcNormalize`获取我们自身`WINSRVSERVER`的相关信息  
其中的关键调用如下：

- KdcNormalize
  - KdcGetTicketInfo
    - SamIGetUserLogonInformation2  (WINSRVSERVER)
    - SamIGetUserLogonInformation2  (WINSRVSERVER$)

对于漏洞的利用便发生在这个函数中，并且利用了两次。  
第一次实现了将申请的用户转换为域控上的`Administrator`
第二次实现了将申请的服务转换成`WINSRVSERVER$`  
下面将详细分析漏洞点。  

``` cpp
KERBERR
KdcNormalize(
    IN PKERB_INTERNAL_NAME PrincipalName,
    IN OPTIONAL PUNICODE_STRING PrincipalRealm,
    IN OPTIONAL PUNICODE_STRING RequestRealm,
    IN OPTIONAL PUNICODE_STRING  TgtClientRealm,
    IN ULONG NameFlags,
    IN BOOLEAN bRestrictUserAccounts,
    OUT PBOOLEAN Referral,
    OUT PUNICODE_STRING RealmName,
    OUT PKDC_TICKET_INFO TicketInfo,
    OUT PKERB_EXT_ERROR  pExtendedError,
    OUT OPTIONAL SAMPR_HANDLE * UserHandle,
    IN OPTIONAL ULONG WhichFields,
    IN OPTIONAL ULONG ExtendedFields,
    OUT OPTIONAL PUSER_INTERNAL6_INFORMATION * UserInfo,
    OUT OPTIONAL PSID_AND_ATTRIBUTES_LIST GroupMembership
    )
```

调用`KdcNormalize`时的相关参数中最重要的就是`SourceCName`  
因为我们是在利用`S4U2Self`协议请求自身的ST，所以`SourceCName`也就是自身的名字`WINSRVSERVER`

``` text
kd> dt SourceCName
Local var @ 0x327f9e0 Type _KERB_INTERNAL_NAME*
0x0016e920 
   +0x000 NameType         : 0n1
   +0x002 NameCount        : 1
   +0x004 Names            : [1] _UNICODE_STRING "WINSRVSERVER"
```

~~此处还需要强调清理SPN的意义~~

之后在`CheckSam`条件中会调用到`KdcGetTicketInfo`来获取用户`WINSRVSERVER`的相关信息

``` cpp
KerbErr = KdcGetTicketInfo(
            &OutputPrincipal,
            0,                  // no lookup flags means sam name
            bRestrictUserAccounts,
            NULL,               // no principal name
            NULL,               // no realm name,
            TicketInfo,
            pExtendedError,
            UserHandle,
            WhichFields,
            ExtendedFields,
            UserInfo,
            GroupMembership
            );
```

此时`OutputPrincipal`的值为`WINSRVSERVER`，即我们自己的机器名`DC`，目前仍一切正常

``` text
kd> dt OutputPrincipal
Local var @ 0x327f928 Type _UNICODE_STRING
 "WINSRVSERVER"
   +0x000 Length           : 0x18
   +0x002 MaximumLength    : 0x1a
   +0x004 Buffer           : 0x0016e92c  "WINSRVSERVER"
```

之后会调用`SamIGetUserLogonInformation2`在SAM中查找对应的账户信息，但由于此时已经将创建的机器账号还原，所以并不能找到对应的账号，该函数会返回错误  
但是系统并不会直接提示找不到账号，而是会在其后面添加'$'符号，将其作为机器账号再次查找  

``` cpp
   Status = SamIGetUserLogonInformation2(
               GlobalAccountDomainHandle,
               LookupFlags,
               UserName,
               WhichFields,
               ExtendedFields,
               &UserInfo,
               &LocalMembership,
               &LocalUserHandle
               );

   //
   // WASBUG: For now, if we couldn't find the account try again
   // with a '$' at the end (if there wasn't one already)
   //

   if (((Status == STATUS_NOT_FOUND) ||
      (Status == STATUS_NO_SUCH_USER)) &&
      (!IsValidGuid) &&
      ((LookupFlags & ~SAM_NO_MEMBERSHIPS) == 0) &&
      (UserName->Length >= sizeof(WCHAR)) &&
      (UserName->Buffer[UserName->Length/sizeof(WCHAR)-1] != L'$'))
   {
      Status = KerbDuplicateString(
                  &TempString,
                  UserName
                  );
      if (!NT_SUCCESS(Status))
      {
            KerbErr = KRB_ERR_GENERIC;
            goto Cleanup;
      }
      DsysAssert(TempString.MaximumLength >= TempString.Length + sizeof(WCHAR));
      TempString.Buffer[TempString.Length/sizeof(WCHAR)] = L'$';
      TempString.Length += sizeof(WCHAR);

      D_DebugLog((DEB_TRACE, "Account not found ,trying machine account %wZ\n",
            &TempString ));

      Status = SamIGetUserLogonInformation2(
                  GlobalAccountDomainHandle,
                  LookupFlags,
                  &TempString,
                  WhichFields,
                  ExtendedFields,
                  &UserInfo,
                  &LocalMembership,
                  &LocalUserHandle
                  );
   }
```

通过调试信息可以清晰的看到查找到的用户信息不再是`WINSRVSERVER`而是变成了`WINSRVSERVER$`也就是域控对应的机器账号`UserId = 0x3ed`  
至此便完成了对于域控的欺骗，之后就是颁发ST的过程

``` text
kd> dt UserInfo
Local var @ 0x327f684 Type _USER_INTERNAL6_INFORMATION*
0x001602e0 
   +0x000 I1               : _USER_ALL_INFORMATION
   +0x0c8 LastBadPasswordTime : _LARGE_INTEGER 0x0
   +0x0d0 ExtendedFields   : 0x18
   +0x0d4 UPNDefaulted     : 0 ''
   +0x0d8 UPN              : _UNICODE_STRING ""
   +0x0e0 A2D2List         : (null) 
   +0x0e4 RegisteredSPNs   : (null) 
   +0x0e8 KeyVersionNumber : 5
   +0x0ec LockoutThreshold : 0
kd> dx -id 0,0,89de1678 -r1 (*((KDCSVC!_USER_ALL_INFORMATION *)0x1602e0))
(*((KDCSVC!_USER_ALL_INFORMATION *)0x1602e0))                 [Type: _USER_ALL_INFORMATION]
    [+0x000] LastLogon        : {0} [Type: _LARGE_INTEGER]
    [+0x008] LastLogoff       : {0} [Type: _LARGE_INTEGER]
    [+0x010] PasswordLastSet  : {0} [Type: _LARGE_INTEGER]
    [+0x018] AccountExpires   : {0} [Type: _LARGE_INTEGER]
    [+0x020] PasswordCanChange : {0} [Type: _LARGE_INTEGER]
    [+0x028] PasswordMustChange : {9223372036854775807} [Type: _LARGE_INTEGER]
    [+0x030] UserName         : "WINSRVSERVER$" [Type: _UNICODE_STRING]
    [+0x038] FullName         : "" [Type: _UNICODE_STRING]
    [+0x040] HomeDirectory    : "" [Type: _UNICODE_STRING]
    [+0x048] HomeDirectoryDrive : "" [Type: _UNICODE_STRING]
    [+0x050] ScriptPath       : "" [Type: _UNICODE_STRING]
    [+0x058] ProfilePath      : "" [Type: _UNICODE_STRING]
    [+0x060] AdminComment     : "" [Type: _UNICODE_STRING]
    [+0x068] WorkStations     : "" [Type: _UNICODE_STRING]
    [+0x070] UserComment      : "" [Type: _UNICODE_STRING]
    [+0x078] Parameters       : "" [Type: _UNICODE_STRING]
    [+0x080] LmPassword       : "" [Type: _UNICODE_STRING]
    [+0x088] NtPassword       : ".㑟废띶䎓樾쒕ꇒ" [Type: _UNICODE_STRING]
    [+0x090] PrivateData      : "." [Type: _UNICODE_STRING]
    [+0x098] SecurityDescriptor [Type: _SR_SECURITY_DESCRIPTOR]
    [+0x0a0] UserId           : 0x3ed [Type: unsigned long]
    [+0x0a4] PrimaryGroupId   : 0x0 [Type: unsigned long]
    [+0x0a8] UserAccountControl : 0x2100 [Type: unsigned long]
    [+0x0ac] WhichFields      : 0x27120005 [Type: unsigned long]
    [+0x0b0] LogonHours       [Type: _LOGON_HOURS]
    [+0x0b8] BadPasswordCount : 0x0 [Type: unsigned short]
    [+0x0ba] LogonCount       : 0x0 [Type: unsigned short]
    [+0x0bc] CountryCode      : 0x0 [Type: unsigned short]
    [+0x0be] CodePage         : 0x0 [Type: unsigned short]
    [+0x0c0] LmPasswordPresent : 0x0 [Type: unsigned char]
    [+0x0c1] NtPasswordPresent : 0x1 [Type: unsigned char]
    [+0x0c2] PasswordExpired  : 0x0 [Type: unsigned char]
    [+0x0c3] PrivateDataSensitive : 0x1 [Type: unsigned char]
```

至此，我们成功的请求的用户`WINSRVSERVER`伪装成了域控自身`WINSRVSERVER$`

之后再`I_GetTGSTicket`中，为了获得`WINSRVSERVER`这个服务的相关信息，又再次调用`KdcNormalize`，其中的流程与上述基本相同，这也就是漏洞的第二次利用。成功的将请求的服务从`WINSRVSERVER`伪装成`WINSRVSERVER$`

完成上述的两次利用后，其他过程都显得不再重要，但有一点仍然需要留意，便是关于PAC的问题。  
之前TGT中的PAC主体为`WINSRVSERVER`，又是如何切换为申请的`Administrator`的，对于之前的PAC又是如何处理的。  
下面将对这两点进行分析  

`S4U2self`协议的意义是 服务器模拟用户向域控申请针对自身的ST，即给予用户访问服务的权限，所以返回的ST中应该插入的是用户的PAC，即下图中的(2)(3)两个过程  
而上一步中我们申请的TGT中的PAC，是 不在下图中的Service1向KDC认证的过程 中颁发的PAC  
明白了这点也就明白了为什么PAC会被替换  

![Server-for-User-to-Self (S4U2self)](https://cdn.jsdelivr.net/gh/dre4merp/Drawing-bed@main/images/S4U2self.png)

以下堆栈及函数完成了生成ST并向其中添加了用户PAC

``` text
kd> kb
 # ChildEBP RetAddr      Args to Child              
00 0327f9ac 61ba4b9b     0327fb48 0327fea8 0327fea0 KDCSVC!I_GetTGSTicket+0x313   
01 0327fe44 61ba1901     00160958 000c5020 0327feb8 KDCSVC!HandleTGSRequest+0x77f   
02 0327fee0 61bae51e     0327ff30 00160958 00160968 KDCSVC!KdcGetTicket+0x25e    
03 0327ff34 70d173e6     00160940 00000562 00000000 KDCSVC!KdcAtqIoCompletion+0x15f  
04 0327ff58 70d18808     00000562 00000000 00084df4 NTDSATQ!ATQ_CONTEXT::IOCompletion+0x53 
05 0327ff84 70d189f2     00000000 00000562 00084df4 NTDSATQ!AtqpProcessContext+0x3c2  
06 0327ffb8 77e41be7     abcdef01 00000000 00000000 NTDSATQ!AtqPoolThread+0xbd    
07 0327ffec 00000000     70d18935 abcdef01 00000000 kernel32!BaseThreadStart+0x34   
```

``` cpp
KerbErr = KdcGetS4UTicketInfo(
                  S4UTicketInfo,
                  &OldServiceTicketInfo, // tgt's account info.
                  &S4UClientUserInfo,
                  &S4UClientGroupMembership,
                  pExtendedError
                  );
...
KerbErr = BuildTicketTGS(
            ServiceTicketInfo,
            RequestBody,
            SourceTicket,
            Referral,
            S4UTicketInfo,
            CommonEType,
            &NewTicket,
            pExtendedError
            );  
...         
KerbErr = KdcInsertInitialS4UAuthorizationData(
               &EncryptedTicket,
               pExtendedError,
               S4UTicketInfo,
               S4UClientUserInfo,
               &S4UClientGroupMembership,
               ((ServiceTicketInfo->UserId != DOMAIN_USER_RID_KRBTGT) &&
                     ((ServiceTicketInfo->UserAccountControl & USER_INTERDOMAIN_TRUST_ACCOUNT) == 0)),
               pKeyToUse
               );                                             
```

对于原本的TGT中的PAC并没有做任何处理，直接将其丢弃了。

## 总结

本文介绍了`CVE-2021-42278`和`CVE-2021-42287`的漏洞背景,并从系统层面详细分析了漏洞成因，其关键点在于`S4U2self`过程中的欺骗。  
对于任何技术的研究，都不要靠想当然。用苍白的文字来理解协议，远不如用可靠的代码和调试信息。

## 参考

<https://www.rfc-editor.org/rfc/rfc4120.txt>  
<https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/1fb9caca-449f-4183-8f7a-1a5fc7e7290a>  
<https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/aceb70de-40f0-4409-87fa-df00ca145f5a>  
<https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ae60c948-fda8-45c2-b1d1-a71b484dd1f7>  
<https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/c38cc307-f3e6-4ed4-8c81-dc550d96223c>  
