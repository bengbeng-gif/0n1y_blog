---
title: NewStar CTF 2025 WP Web部分
published: 2026-04-13
description: Week1
image: "./2.jpg"
tags: ["wp"]
category: CTF
draft: false
slug: NewStar CTF 2025 WP Web部分
---

## Week1 Web

### 宇宙的中心是 PHP

打开容器，可以发现 f12 被禁了

直接在 url 前加上 `view-source:` 去查看源码：

得到源码的有效信息为：

```plain
|<!-- 你还是找到了......这片黑暗的秘密 -->|
|<!-- s3kret.php -->|
```

访问 `/s3kret.php`，得到：

```php
<?php  
highlight_file(__FILE__);  
include "flag.php";  
if(isset($_POST['newstar2025'])){    $answer = $_POST['newstar2025'];  
    if(intval($answer)!=47&&intval($answer,0)==47){  
        echo $flag;  
    }else{  
        echo "你还未参透奥秘";  
    }  
}
```

解释下核心逻辑：

使用 POST 方式传入一个名为 `newstar2025` 的参数，并把它的值赋值给 `$answer` 这个变量。若 `$answer` 的值在 **10进制** 的时候不等于 47，且使用 `$answer` 变量进制的时候等于 47，则得到 flag

这里重点是要知道 `intvar()` 这个函数的用法：

[`intvar($value, $base = 10)`](https://www.php.net/manual/zh/function.intval.php)：获取变量的整数值

默认情况下 base = 10，即按照 **10进制** 获取变量的值

而当 base = 0 时，则通过检测 `value` 的格式来决定使用的进制：
- 如果字符串包括了 "0x" (或 "0X") 的前缀，使用 16 进制 (hex)；否则，
- 如果字符串以 "0b" (或 "0B") 开头，使用 2 进制 (binary)；否则，
- 如果字符串以 "0" 开始，使用 8 进制(octal)；否则，
- 将使用 10 进制 (decimal)。

这样目标就很明确了，不以10进制数传参使得 $answer = 47 即可

最终 payload：
```plain
newstar2025=0x2F
```

得到 flag：flag{a2928e78-7db3-8780-a368-9d6cbae9ecfb}

### multi-headach3

打开容器，得到：

```plain
# Hello!

Today is 2026/04/07

welcome to my first website!  
  
**ROBOTS** is protecting this website!  
But... Why my head is so **painful**???!!!  
And why you are here again and again?  
Trust me, hidden page is not as simple as you think.
```

这里提到 ==robots==，可以想到 ==robots.txt 协议==

> 若不了解 robots.txt 协议可以点击[这里](https://www.cloudflare.com/zh-cn/learning/bots/what-is-robots-txt/)

直接访问 `/robots.txt`，得到如下结果：

```plain
User-agent: *
Disallow: /hidden.php
```

都 Disallow 那肯定是要看看的 2333

访问 /hidden.php，得到：

```plain
# Hello!

Today is 2026/04/07

welcome to my first website!  
  
**ROBOTS** is protecting this website!  
But... Why my head is so **painful**???!!!  
And why you are here again and again?  
Trust me, hidden page is not as simple as you think.
```

和原网页一模一样，可见没什么用处（恼

这里还有个信息 ==head==，联想到 ==http请求头==（head）

抓包（访问 /hidden.php 的时候），得到：

flag{3057d5d3-fb7d-e4ef-01a6-27dd3f0527f9}

### strange_login

打开容器，看到一个登录界面：

考察的是简单的 SQL注入

构造：`admin' and 1=1-- ` 直接得到 flag：

（具体解释因为比较基础可以自己去网上找找基础的 SQL 注入学习）

flag{56119305-d5c4-1e35-c902-bc160b877645}

### 别笑，你也过不了第二关

z学姐出的题目说是（

打开容器，是一个接掉落物的游戏：

第一关拿到30分即可通过到第二关

第二关要1000000分才能过

看了下源码和实操了下，正常情况下绝对拿不到1000000分

这里修改了分数通关了：

脚本：

```javascript

```

### 我真得控制你了

打开容器，发现有个启动键（但被 ban 了

点击 f12 发现被 ban 了

（这里以 Chrome 浏览器为例）

这里我们可以点击右上角的三个点->更多工具->开发者工具

就可以看到源码了

但是此时的警告界面还是不断跳出来

查看源码，发现警告界面的元素为 `devToolsWarning`

直接把此元素删了即可，警告界面消失

但是启动键被 ban 的问题还没解决

这里有两种办法：

法1是直接将屏障启动键元素 `shieldOverlay` 删了即可

法2是使用控制台：

`document.getElementById('shieldOverlay').remove();`

其实质也是将 `shieldOverlay` 这个元素删除

删除后点击启动进入下一关

下一关有明显的提示为弱口令/弱密码爆破

这里直接使用 burpsuite 进行爆破：

爆破发现密码为 11111

（注：这里我们按理来将有两个元素需要爆破：用户名和密码，但实际的 ctf 题目一般都是在密码上下文章，因此这里是使用常见的用户名 admin）

输入密码后进入下一关

此关直接给出了源码：

```php
<?php
error_reporting(0);

function generate_dynamic_flag($secret) {
    return getenv("ICQ_FLAG") ?: 'default_flag';
}


if (isset($_GET['newstar'])) {
    $input = $_GET['newstar'];
    
    if (is_array($input)) {
        die("恭喜掌握新姿势");
    }
    

    if (preg_match('/[^\d*\/~()\s]/', $input)) {
        die("老套路了，行不行啊");
    }
    

    if (preg_match('/^[\d\s]+$/', $input)) {
        die("请输入有效的表达式");
    }
    
    $test = 0;
    try {
        @eval("\$test = $input;");
    } catch (Error $e) {
        die("表达式错误");
    }
    
    if ($test == 2025) {
        $flag = generate_dynamic_flag($flag_secret);
        echo "<div class='success'>拿下flag！</div>";
        echo "<div class='flag-container'><div class='flag'>FLAG: {$flag}</div></div>";
    } else {
        echo "<div class='error'>大哥哥泥把数字算错了: $test ≠ 2025</div>";
    }
} else {
    ?>
<?php } ?>
```

解释下逻辑：

此题先需要我们使用 GET 方法传入一个名为 newstar 的元素并将其赋值给 input 元素；input 不能是数组，其值必须在数字、\*和/和~和()和空白字符，且不能是纯数字或者纯空白；将 input 的值传给 test，若 test 传入的表达式有误，则会触发 try...catch 输出 “表达式错误”；在此后若 test 等于 2025，则给出 flag

解释下理解必要的用法：

getenv — 获取一个环境变量的值

is_array — 检测变量是否是数组

die：等于 exit()

exit — 输出一个消息并且退出当前脚本

preg_match — 执行匹配正则表达式

若对正则表达式不了解可以看看这篇文章：[菜鸟教程](https://www.runoob.com/regexp/regexp-syntax.html)

`?:`：三元运算符的缩写，用法如下：

```php
$result = $a ?: $b;
等同于
$result = $a ? $a : $b;
```

看到 **不能全是数字** 这一条件，可以想到使用乘除法等将2025算出来

刚好2025是一个完全平方数，所有最终 payload：

```plain
/?newstar=45*45
```

得到 flag：flag{c80c003f-1d66-8de7-e3fb-1575c0921d53}

### 黑客小 W 的故事（1）

进入容器，发现要我们点击中间的一个 chongzi，每次点击都会得到一定的分数，到

了 800 分就能通关（并非

这里如果一直尝试的话会发现在点击途中一定会被阻拦然后分数清零

题目提示抓包，我们试图抓包改数据：

```http
POST /hunt HTTP/1.1

Host: 192.168.42.1:60152

Accept: */*

Origin: http://192.168.42.1:60152

Accept-Encoding: gzip, deflate

Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiYjBmNzFmOGYtMGFlNy00NDRhLTg0MjAtMDVlMDllODYwNzIzIiwibGV2ZWwiOjF9.GGjj_uyDLSatsFEt4bA1aF4zLj3nbzdWLdmCYOtAMrE

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36

Accept-Language: zh-CN,zh;q=0.9

Content-Type: application/json

Referer: http://192.168.42.1:60152/hunt

Content-Length: 11

  

{"count":1}
```

这里可以看到，`{"count":1}` 就是我们的分数

直接将其改为 1000，到达第二关：

```http
HTTP/1.1 200 OK

Server: Werkzeug/3.1.3 Python/3.12.11

Date: Sat, 11 Apr 2026 12:28:43 GMT

Content-Type: application/json

Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiVHJ1ZSIsImxldmVsIjoyfQ.Xz7r0_c7lyf1E8iXWszsQBC1c43djRjjWLf5tzWnIok; Path=/

Connection: close

Content-Length: 29

  

{"NextLevel":"/Level2_mato"}
```

第二关首先提示要使用 GET 方式传入值为 mogubaozi 名为 shipin 的参数

```plain
?shipin=mogubaozi
```

随后提示要使用 POST 方式告诉它事情（即 guding

这里使用 hackbar 传参：

```plain
code=guding
```

进入下一步，说是要使用 DELETE 方式去掉所有的 chongzi

直接在 yakit 内发送数据包：

```http
DELETE /talkToMushroom?shipin=mogubaozi HTTP/1.1

Host: 192.168.42.1:60152

Cache-Control: max-age=0

Origin: http://192.168.42.1:60152

Upgrade-Insecure-Requests: 1

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Accept-Language: zh-CN,zh;q=0.9

Accept-Encoding: gzip, deflate

Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJOYW1lIjoiVHJ1ZSIsImxldmVsIjoyfQ.Xz7r0_c7lyf1E8iXWszsQBC1c43djRjjWLf5tzWnIok

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36

Content-Type: application/x-www-form-urlencoded

Referer: http://192.168.42.1:60152/talkToMushroom?shipin=mogubaozi

Content-Length: 11

  

chongzi
```

进入下一关，这里可以刷新下网页得到下一步指引：

```plain
你已经帮我把虫子弄掉了，我把骨钉给你吧，你可以回去找那个大家伙了（/Level2_END）
```

这里提示我们改 User-Agent

可以先了解下 [User-Agent](https://developer.mozilla.org/en-US/docs/Glossary/User_agent)

原 UA：

```plain
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
```

修改为：

```plain
CycloneSlash/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
```

再改为：

```plain
CycloneSlash/5.0 (Windows NT 10.0; Win64; x64) DashSlash/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
```

得到下一关方法 /Level4_Sly

进入下一关发现终于结束，得到 flag：

flag{4508d441-7a16-a379-c391-0905c60c0a1e}
