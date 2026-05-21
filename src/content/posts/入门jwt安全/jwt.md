---
title: 入门jwt安全（待完善
published: 2026-05-21
description: 待完善
image: "./8.jpg"
tags: ["CTF"]
category: CTF
draft: false
slug: jwt
---

碰到一个 jwt 绕过验证的题目，对这种绕过很感兴趣，遂学习了一下

但是这种类型往往是作为中间件的题目内容出现（像路径遍历

这里题目还没有碰到很多，碰到后再进行补充

## 简述

JWT：JSON web tokens

jwt 由三部分组成：header，payload，signature

每个部分使用 `.` 进行连接

其中，header 和 payload 都是使用 base64 编码过后的 json 数据

这里注意，这里和常见的标准 base64 编码不一样，这里使用的是 base64URL 编码

它是由 26 大写字母，26 小写字母，0-9，连字符 `-` 和下划线 `_` 所组成的

（标准的是26大，26小，0-9，`/` 和 `+` 和 `=`）

为什么要这样做呢？

在 url 中，标准 base64 的 `+` 会被解释为空格，而 `/` 会被解释为路径分隔符

并且，base64URL 不会拿 `=` 作为填充符，对于字节数不是三的倍数的它会直接省略

从这里也可以知道，header 和 payload 都是不进行加密的

所有加密都是依赖签名（signature

header：包含签名的算法和 token 的类型

```plain
{
"alg": "HS256",
"typ": "JWT"
}
```

常见的字段：

```plain
alg: 指定token加密使用的算法  
typ: 指定令牌的类型, 值基本为JWT  
kid: 指定使用的加密算法的密钥 在服务端的位置
```

注：只有 `alg` 标头参数是必须的，并且，若是 `alg` 的值是 `none`，则后面的签名为空，但是仍然需要加点号！！

payload：存放实际需要的数据

```plain
官方定义的 7 种字段
- iss (issuer)：签发人
- exp (expiration time)：过期时间
- sub (subject)：主题
- aud (audience)：受众
- nbf (Not Before)：生效时间
- iat (Issued At)：签发时间
- jti (JWT ID)：编号
  
当然，我们也可以自己定义私有字段
```

signature：首先，服务器有一个密钥（这里我们把它都叫做 secret），随后，服务器按照签名中的算法用以下公式对其进行加密（算法即是 header 中提到的

```plain
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

jwt 因为是在客户端，可以存在 Cookie 或者 localStorage 中

jwt 若是没有处理妥当，往往会导致 hacker 冒充其他用户或者提权

## 工具

写在前面：个人感觉 jwt 还是优先考虑使用一些其他工具比如 jwt_tool（命令行交互式伪造 jwt，或者一些交互网站 `jwt.io`（在线修改 jwt，验证 **签名** 正确性，jwt_cracker（爆破神器，hashcat（爆破神器；随后再考虑 burp 的工具

brup：
[链接戳这里](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/session-management/jwts)

这里我们抓包后在右边即可看到 burp inspector

选择不同的部分它将自动帮你解码

我们可以在这里对其进行修改

将数据发送到 repeater 后，我们点击跳转到 `JSON Web Token`

在这里我们可以修改其值

那么，如何添加 key 呢

这里我们用到插件 `JWT Editor`

选择跳转

这里我们可以选择要添加的 key，这里我们就假设选择一个 `New Symmetric Key`（有很多种，肯定根据实际情况来调整）

将其中的 key 换成我们之前得到的 key 的 base64url 编码后的结果（这里得先知道 key

随后返回到之前的地方，点击 `sign` 进行添加即可

## 未做签名校验

我们对于 header 和 payload 中的数据直接改就行

## 空加密

后端依赖于 `alg` 中的算法对签名进行加密

这时候我们可以直接将 `alg` 中的值改为 `none`

## 报错注入

这里我们直接上传篡改过的 jwt，服务器返回了它所期待的正确签名（要求 Auth0-WCF-Service-JWT NuGet 版本很低

## 爆破

利用工具可以爆破一些弱密钥

例如：hashcat，jwtcracker

## 修改非对称算法为对称算法



## jwt 头部参数注入

在 header 中，有这么几个标头需要我们格外注意：

```plain
jwk （JSON Web Key）- 提供一个表示密钥的嵌入式 JSON 对象

jku （JSON Web Key Set URL）- 提供一个 URL，服务器可以从中获取包含正确密钥的一组密钥

kid （密钥 ID）- 提供一个 ID，服务器可以使用该 ID 在有多个密钥可供选择的情况下识别正确的密钥。根据密钥的格式，此 ID 可能具有匹配的 `kid` 参数
```

### jwk 注入

JWK（JSON Web Key）是一种将键表示为 JSON 对象的标准化格式

JSON Web Signature (JWS) 规范描述了一个可选的 `jwk` 标头参数，服务器可以使用该参数以 JWK 格式将其公钥直接嵌入到令牌本身中

此漏洞原因是服务器没有使用有限的公钥白名单来验证 jwt 签名

（错误的配置有可能会使用嵌入 jwk 中的任何密钥）

因此我们可以尝试使用自己的私钥去伪造这么一个公钥，随后将其插入到 jwt 参数中

这里我们可以先在插件中生成一种算法的 jwt

随后我们返回 repeater，在 jwt 模块中选择左下角的 `Attack`

随后再选择 `Embedded JWK`，在谈出的面板中选择你想要的密钥

随后你的 jwt 参数就成功被添加了

### jku 注入

有些服务器不直接使用 `jwk` 请求头参数嵌入公钥，而是允许使用 `jku` （JWK 集 URL）请求头参数来引用包含密钥的 JWK 集。验证签名时，服务器会从该 URL 获取相关密钥

JWK 集是一个 JSON 对象，其中包含一个 JWK 数组，每个 JWK 代表一个不同的键。您可以在下方看到一个示例

有些 JWK 集是通过标准端点公开的

这里我们可以将对应的 jwk 集（可以使用插件 jwt editor 生成）插入到我们的服务器中（如果有

随后将其中的值和 header 中有的值进行互换

例如：我们生成的 jwk 集中有 kid 标头，而 header 中也有，那么此时我们就需要将 header 中的 kid 值改为 jwk 集中的值

随后，我们可以在 header 中生成一个 `jku` 标头，此标头应该填入之前服务器的 url

注：这里添加新的标头记得在上一个标头的末尾加上 `,`！！！

### kid 注入

服务器可能使用多个加密密钥来签署不同类型的数据，而不仅仅是 JWT。因此，JWT 的头部可能包含一个 `kid` （密钥 ID）参数，该参数可以帮助服务器在验证签名时确定要使用的密钥

验证密钥通常以 JWK 集的形式存储。在这种情况下，服务器可能只需查找与令牌具有相同 `kid` 的 JWK 即可。然而，JWS 规范并未定义此 ID 的具体结构——它只是开发者选择的任意字符串。例如，他们可以使用 `kid` 参数指向数据库中的特定条目，甚至是文件名

（即可能会导致比如路径遍历等问题）

如果服务器也支持使用 **对称算法** 签名的 JWT，这种情况尤其危险。攻击者可以将 `kid` 参数指向一个可预测的静态文件，然后使用与该文件内容匹配的密钥对 JWT 进行签名

理论上，任何文件都可以这样做，但最简单的方法之一是使用 `/dev/null` ，它存在于大多数 Linux 系统中。由于这是一个空文件，读取它会返回一个空字符串。因此，使用空字符串对令牌进行签名将得到有效的签名

若是密钥存储在数据库中，还可能导致 sql 注入等问题