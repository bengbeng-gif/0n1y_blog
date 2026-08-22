---
title: Moectf2026-misc全解
published: 2026-08-22
description: 比赛归档后公开
image: "./1779126199063.jpeg"
password: "6d4f67d3a2da14f816fc29873b98aabf"
passwordHint: "比赛归档后公开"
tags: ["CTF"]
category: CTF
slug: Moectf-misc
---

## Misc

### ez_BASE

rev 加 base64 即可

flag:moectf{Y0u_h@v3_kn0wn_b@sE64}

### ez_LSB

LSB 调整到 RGB：

```plain
flag:bW9lY3Rme2M
0N19rTjBXNV9MU0J
9
```

解码后得到 flag

flag:moectf{c47_kN0W5_LSB}

### 星走路的旅程-level1

根据图片中的 `美丽空港` 即可判断位置，搜索即可：

手机厂商在 exif 信息中可以看到：

flag:moectf{KWE_XIAOMI_0203}

### 星走路的旅程-level2

exif 没信息

### 空白文档

一般都是把文件打包成一个 `.zip` 文件，然后所有隐藏数据都在 `.zip` 包里面

这里看到：

```plain
<w:t>你知道异或吗？</w:t>

</w:r>

<w:r w:rsidR="009A302B" w:rsidRPr="007C7BCC">

<w:rPr>

<w:rFonts w:hint="eastAsia"/>

<w:color w:val="FFFFFF" w:themeColor="background1"/>

</w:rPr>

<w:t>key：offic</w:t>

</w:r>

<w:r w:rsidR="006C2B1C" w:rsidRPr="007C7BCC">

<w:rPr>

<w:rFonts w:hint="eastAsia"/>

<w:color w:val="FFFFFF" w:themeColor="background1"/>

</w:rPr>

<w:t>e</w:t>

</w:r>

</w:p>

<w:p w14:paraId="0EAB7A52" w14:textId="40D557FF" w:rsidR="009A302B" w:rsidRPr="003878C8" w:rsidRDefault="009A302B" w:rsidP="009A336E">

<w:pPr>

<w:rPr>

<w:rFonts w:hint="eastAsia"/>

<w:vanish/>

<w:color w:val="000000" w:themeColor="text1"/>

</w:rPr>

</w:pPr>

<w:r w:rsidRPr="003878C8">

<w:rPr>

<w:vanish/>

<w:color w:val="000000" w:themeColor="text1"/>

</w:rPr>

<w:t>AgkDChcDFBEOWhEAMFcVNg4cMABXXQQY</w:t>
```

这里 key 是 office

知道了 key 和密文，一次 base64 一次 xor 拿到

flag:moectf{wh3re_1s_my_f14g}

### Tomato

### ez_BASE_revenge

给了一堆表情：

```plain
👄👱👞👱👑👢🐨👤👍👥👚🐫👛👏🐹👫👙👎👁🐪👜👡👉👭👋🐽👟👎👉🐼👁👍👈👣👑👧👋👢👫🐾👐👥👁👠👍🐼👫🐭👊👢👅🐭👋👌👁👊👙👍🐹🐩👘🐻🐽🐼👈👍👧👣👌🐻🐽👅👘🐿👟👏👜👣🐽👉👆🐿👟👉👑🐪👑👘👄👏👛🐫👋👍👅🐧👙👢🐨👊👚🐾👚🐴
```

AI 解出来的

### 半部电台

一键梭了，sstv 隐写
