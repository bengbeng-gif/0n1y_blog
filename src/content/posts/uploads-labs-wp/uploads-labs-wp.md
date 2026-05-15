---
title: uploads-labs-wp
published: 2026-05-15
description: uploads-labs题解
image: "./4.jpg"
tags: ["CTF"]
category: CTF
draft: false
slug: uploads-labs-wp
---

（过程详细，基本都能够参照复现）
（针对 0n1y 当时感觉有趣/不会的点进行了解释）
（目标是名为 `phpinfo.php` 的文件成功执行）

## Pass-01 *前端 Javascript 检测*
前端检测，直接禁用 Javascript

## Pass-02 *MIME 检测*
第二关直接上传得到的响应：
`文件类型不正确，请重新上传！`

这里抓包修改 `content-type` 为 `image/jpeg` 后成功上传

## Pass-03 *特殊后缀解析绕过*
第三关直接上传得到的响应：
`不允许上传.asp,.aspx,.php,.jsp后缀文件！`

这里将后缀改为 `php3` 后成功上传

## Pass-04 *.htaccess 绕过*
第四关直接上传得到的响应：
`此文件不允许上传!`

这里尝试上传 `.htaccess` 文件后成功

`.htaccess` 文件内容如下：
`AddType application/x-httpd-php .jpeg`

随后再上传 `phpinfo.jpeg` 成功上传

## Pass-05 *大小写绕过*
第五关直接上传得到的响应：
`此文件类型不允许上传！`

这里直接大小写绕过即可：`phpinfo.phP`

## Pass-06 *空格绕过*
第六关直接上传得到的响应：
`此文件不允许上传`

这里上传一个后缀末尾带空格的即可：`phpinfo.php+`（这里的 + 是一个空格）

## Pass-07 *点号绕过*
第七关直接上传得到的响应：
`此文件类型不允许上传！`

在文件后缀加点号进行绕过：`phpinfo.php.`

## Pass-08 *::$DATA 绕过*
第八关直接上传得到的响应：
`此文件类型不允许上传！`

在后缀加上 `::$data` 去进行绕过：`phpinfo.php::$data`

## Pass-09 *双点号绕过*
源码如下：

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

第九关直接上传得到的响应：
`此文件类型不允许上传！`

这里后端对文件名前后的空格和点号均进行了删除，但只进行了一次

这里使用双点号进行绕过：`phpinfo.php. .`

删除过后的文件名为：`phpinfo.php. `，即可绕过

## Pass-10 *双写绕过*
出乎意料，这一关直接上传 `phpinfo.php` 竟然直接成功了

看抓包数据：

`/upload/info.`

这里很明显，将文件名中所有的 `php` 字眼的字符串全部删除了（即替换为空字符串

这里后面尝试双写绕过成功了：`phpinfo.pphphp`

但是其实在此之前我是先尝试的 `phpinfo.phphpp`，而这被后端改为 `/upload/info.hpp`

这里是因为后端进行匹配的是 `php`，而在我的字符串中 `.phphpp` 先出现了 `php`，导致前面的被删除（我的本意是中间的 `php` 被删除

（双写绕过也不能任意构造呀 23333

## Pass-11 *%00 截断绕过*
源码如下：

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

第十一关直接上传得到的响应：
`只允许上传.jpg|.png|.gif类型文件！`

这里将文件上传路径修改为 `/upload/phpinfo.php%00` 去截断后续字符使得文件被系统当成 `php` 文件执行

## Pass-12 *%00 截断绕过*
源码如下：

```php
$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif');
    $file_ext = substr($_FILES['upload_file']['name'],strrpos($_FILES['upload_file']['name'],".")+1);
    if(in_array($file_ext,$ext_arr)){
        $temp_file = $_FILES['upload_file']['tmp_name'];
        $img_path = $_POST['save_path']."/".rand(10, 99).date("YmdHis").".".$file_ext;

        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = "上传失败";
        }
    } else {
        $msg = "只允许上传.jpg|.png|.gif类型文件！";
    }
}
```

第十二关直接上传得到的响应：
`只允许上传.jpg|.png|.gif类型文件！`

初看这个响应，大概能猜到也是白名单过滤，这里看了下数据包的响应：（只截取了一部分关键的

```http
POST /Pass-12/index.php HTTP/1.1

................................

Content-Disposition: form-data; name="save_path"

  

../upload/

------WebKitFormBoundarybkdk3dzqmvcVLqkl

Content-Disposition: form-data; name="upload_file"; filename="phpinfo.php"

Content-Type: application/octet-stream

  

<?php eval("phpinfo();"); ?>

------WebKitFormBoundarybkdk3dzqmvcVLqkl

Content-Disposition: form-data; name="submit"

  

上传

------WebKitFormBoundarybkdk3dzqmvcVLqkl--
```

这里可以看到此次上传文件是采用 POST 方法，而且也有可控的上传路径

这里同样采取 `%00` 截断

但是要注意的一点是 POST 方法传递的参数是不会像 GET 方式一样进行自动解码的

这里手动在 Yakit 里面对 `%00` 进行解码

方法：选择 %00，右键选择 **URL 强制解码**

最终的上传路径变为：`/upload/phpinfo.php{{urldec(%00)}}`


Pass13~Pass16 的目标变为 **上传图片马到服务器**
## Pass-13 *图片马配合文件包含绕过*
源码如下：

```php
function getReailFileType($filename){
    $file = fopen($filename, "rb");
    $bin = fread($file, 2); //只读2字节
    fclose($file);
    $strInfo = @unpack("C2chars", $bin);    
    $typeCode = intval($strInfo['chars1'].$strInfo['chars2']);    
    $fileType = '';    
    switch($typeCode){      
        case 255216:            
            $fileType = 'jpg';
            break;
        case 13780:            
            $fileType = 'png';
            break;        
        case 7173:            
            $fileType = 'gif';
            break;
        default:            
            $fileType = 'unknown';
        }    
        return $fileType;
}

$is_upload = false;
$msg = null;
if(isset($_POST['submit'])){
    $temp_file = $_FILES['upload_file']['tmp_name'];
    $file_type = getReailFileType($temp_file);

    if($file_type == 'unknown'){
        $msg = "文件未知，上传失败！";
    }else{
        $img_path = UPLOAD_PATH."/".rand(10, 99).date("YmdHis").".".$file_type;
        if(move_uploaded_file($temp_file,$img_path)){
            $is_upload = true;
        } else {
            $msg = "上传出错！";
        }
    }
}
```

这里首先我们得知道题目目录下有这么个 php 文件：
`http://localhost/include.php`

该内容是：

```php
<?php  
/*  
本页面存在文件包含漏洞，用于测试图片马是否能正常运行！  
*/  
header("Content-Type:text/html;charset=utf-8");  
$file = $_GET['file'];  
if(isset($file)){  
    include $file;  
}else{    show_source(__file__);  
}  
?>
```

随后开始做题，这里我们几番尝试后发现后端会检测文件头

这里修改 `phpinfo.php` 文件内容为：

```php
GIF89a

<?php eval("phpinfo();"); ?>
```

但是光这样还不够，若我们尝试去访问上传成功给出的目录，会发现只是一张图片

原因是这道题还要我们使用文件包含去验证图片马是否能成功执行

这里构造 payload：

`http://localhost/include.php?file=./upload/9720260513162917.gif`

要求做出 `.gif`，`.png`，`.jpg` 三种的图片马

这里有三种做法：

1. 直接使用 GIF89a
2. `copy normal.jpg \a + eval.php \b webshell.jpg`
3. 使用 hex 编辑器（例如 01editor

## Pass-14 *图片马配合文件包含绕过*
我们这里可以使用上一关一模一样的流程进行通关

## Pass-15 *图片马配合文件包含绕过*
这里同样可以使用上一关一模一样的流程进行通关

## Pass-16 *二次渲染*
源码如下：

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

第十六关直接上传得到的响应：
`只允许上传后缀为.jpg|.png|.gif的图片文件！`

这里后端将我们传入的图片进行二次渲染，将我们的恶意代码可能删去了（当然也可能我们很幸运的位置它刚好没删

这里我们要将上传前和上传后的图片进行比对

这里使用 01editor，首先我们打开这两个文件

在 Tools 选项下面找到 Compare Files，进行比对

灰色部分的就是内容一致的部分，我们将恶意代码插入到灰色区域即可

## Pass-17 *条件竞争*
源码如下：

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

这里使用的是 Burpsuite 的 intruder 爆破模块

题目源码是先将文件保存在服务器上，再对其进行检测并且执行删除操作

这里我们要利用它的时间间隙，在它删除成功前访问到我们上传的文件

（即使后端将文件名变为了随机数也仍然可以使用此法，就是一个快！

这里先上传文件，抓包，随后发送到 intruder

将 intruder 界面的 `Payload type` 改为 `Null payloads`

选中下方的 `Continue indefinitely`

随后可以跳到同样该界面的 Resource pool 界面，调快进程（可选，比如调为 20 等等

随后开始攻击

另一边，再构造一个数据包，同样发送到 intruder 模块

这一次使用 GET 方法，路径就是我们上传的 `/upload/phpinfo.php`，其他和上述配置一样即可

开始攻击

随后在第二个数据包的攻击界面中找响应不同的即可

## Pass-18 *条件竞争配合解析漏洞*
这里利用了 Apache 的一个解析漏洞：

Apache 会从右往左地解析拓展名，遇到无法识别的则往左继续走

这道题目的 `.7z` 是在白名单内的，但是默认状态下 Apache 是无法识别该拓展名

因此我们可以这样构建文件名 `phpinfo.php.7z`

其余步骤与 Pass-17 均一致，都是考察条件竞争，这里不再解释

## Pass-19 *大小写绕过/%00截断*
源码如下：

```php
$is_upload = false;
$msg = null;
if (isset($_POST['submit'])) {
    if (file_exists(UPLOAD_PATH)) {
        $deny_ext = array("php","php5","php4","php3","php2","html","htm","phtml","pht","jsp","jspa","jspx","jsw","jsv","jspf","jtml","asp","aspx","asa","asax","ascx","ashx","asmx","cer","swf","htaccess");

        $file_name = $_POST['save_name'];
        $file_ext = pathinfo($file_name,PATHINFO_EXTENSION);

        if(!in_array($file_ext,$deny_ext)) {
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH . '/' .$file_name;
            if (move_uploaded_file($temp_file, $img_path)) { 
                $is_upload = true;
            }else{
                $msg = '上传出错！';
            }
        }else{
            $msg = '禁止保存为该类型文件！';
        }

    } else {
        $msg = UPLOAD_PATH . '文件夹不存在,请手工创建！';
    }
}
```

这里我们上传文件后会发现它对我们的文件进行了重命名

这里将 `.php` 后缀改为了 `.jpg`

但是我们仔细观察抓包数据即可发现，这个重命名的操作就在我们的数据包中

也就是说，此重命名是可控的

这里我们直接修改 `upload-19.jpg`（这里可能会不一样）为 `upload-19.PHP` 即可绕过

或者我们直接构造 `upload-19.php%00.jpg`，也能实现 %00 截断绕过

（这里同样要对 %00 进行 URL 解码，因为是使用 POST 请求）

## Pass-20 *数组绕过*
源码如下：

```php
$is_upload = false;
$msg = null;
if(!empty($_FILES['upload_file'])){
    //检查MIME
    $allow_type = array('image/jpeg','image/png','image/gif');
    if(!in_array($_FILES['upload_file']['type'],$allow_type)){
        $msg = "禁止上传该类型文件!";
    }else{
        //检查文件名
        $file = empty($_POST['save_name']) ? $_FILES['upload_file']['name'] : $_POST['save_name'];
        if (!is_array($file)) {
            $file = explode('.', strtolower($file));
        }

        $ext = end($file);
        $allow_suffix = array('jpg','png','gif');
        if (!in_array($ext, $allow_suffix)) {
            $msg = "禁止上传该后缀文件!";
        }else{
            $file_name = reset($file) . '.' . $file[count($file) - 1];
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH . '/' .$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $msg = "文件上传成功！";
                $is_upload = true;
            } else {
                $msg = "文件上传失败！";
            }
        }
    }
}else{
    $msg = "请选择要上传的文件！";
}
```

这里先改 MIME 为 `image/jpeg`

提示说文件上传成功，保存在 `"../upload/upload-20.jpg"`

这里重命名操作依然可控，我们尝试上一关一样的操作

得到：`提示：禁止上传该后缀文件!`

此关是对我们传入的文件名进行数组校验，若不是数组，则对文件名按照 `.` 进行分割

**若是数组，则不进行分割操作**

这里进行数组校验后会分别对文件名和拓展名进行校验（分割后

这里我们可以传入数组：

`save_name[0]=phpinfo.php` 和 `save_name[2]=jpg`

由于我们传入的是数组，因此不会受到分割处理

这里 `end($file)` 对数组最后一个元素进行校验，我们这里传入的 `jpg` 正在白名单内，通过校验

这里有个 `reset()` 函数获取我们传入数组的第一个元素，随后这个元素再和 `$file[count-1]` 进行拼接，这里因为我们上传的数组元素为2，因此这里的 `count-1` 的结果为1，于是服务器去寻找索引为1的数组元素

但是！我们上传的元素索引分别为 0 和 2，不存在索引为 1 的数组元素，因此这里会返回 NULL（即为空，因此，我们这里的 `$file_name` 最终的结果就是 `phpinfo.php`，成功上传