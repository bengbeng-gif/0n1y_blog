---
title: Web🐕入门Go
published: 2026-05-15
description: 一只Web狗因看不懂Go从而尝试入门
image: "./6.jpg"
tags: ["开发"]
category: 开发
draft: false
slug: let's_gooooooo!
---

https://go.dev/tour/welcome/1

https://github.com/securego/gosec

https://pkg.go.dev/

https://projectdiscovery.io/

以上是我学习中发现的优质学习资源！

该文章主要是根据 [Go](https://go.dev/tour/welcome/1) 这篇文章来进行的

去入门 Go 是因为参加一些比赛的题目都是 Go，但是自己没怎么对此有过了解

整篇文章是以审计为目的去进行的（（（后端✌别喷😭

## Package

package 声明包

当我们通过路径调用一个包的时候，在代码里调用它的时候写的一定是路径最末尾的那个

例如：

```go
package main

import "math/rand"

// 使用时
rand.Intn(10) 而不是 math_rand.Intn(10)
```

调用其他包的时候是要通过路径调用，而使用时直接用路径最末尾的

## Import

import 去导入包

使用 **分解式 import** ：（好习惯喵！

例如：

```go
import (
	"fmt"
	"math"
)
```

## Exported names

在 go 中，若是名称首字母是大写的，则可以被导出；

若是名称首字母是小写的，则不可以被导出，只能在包内部访问

似乎是封装的概念

例如：

```go
package main

import (
	"fmt"
	"math"
)

func main() {
	fmt.Println(math.Pi)
}

```

这里的 `Pi` 若是写成小写的 `pi` 则不能被成功导出

## Functions

很奇特的一点，声明函数的时候 **类型** 得在 **变量** 后面

例如：

```go
func add(x int, y int) int {
	return x + y
}
```

在括号后面的那个 `int` 指的是返回值类型

## Functions continued

当两个或多个命名函数参数共享一个类型的时候，可以省略前面的类型只留最后一个类型

例如：

```go
func add(x, y int) int {
	return x + y
}
```

## Multiple results

一个函数可以返回多个结果

例如：

```go
package main

import "fmt"

func swap(x, y string) (string, string) {
	return y, x
}

func main() {
	a, b := swap("hello", "world")
	fmt.Println(a, b)
}
```

这里的 `return y, x` 就是返回两个结果

## Named return values

返回值可以定义，如这样做，那么返回值可视为在函数顶部定义的变量

例如：

```go
package main

import "fmt"

func split(sum int) (x, y int) {
	x = sum * 4 / 9
	y = sum - x
	return
}

func main() {
	fmt.Println(split(17))
}

```

这里的 `split` 函数在 `(x, y int)` 处就定义了返回值分别为**整数类型的 x，y**

且 x 和 y 可以直接在函数内部使用（相当于先定义了

不带参数的 `return` 会返回指定的返回值，叫做 **裸返回**

*裸返回应当只用于较短函数，再较长函数中会降低代码的可读性*

## Variables

var 声明一个变量，和函数声明一样，也是先变量名再类型

var 可以用于包级别和函数级别声明

例如：

```go
package main

import "fmt"

var c, python, java bool

func main() {
	var i int
	fmt.Println(i, c, python, java)
}

```

`var c, python, java bool` 这就是包级别

`var i int` 这就是函数级别

## Variables with initializers

var 还可以初始化变量（即声明的时候进行变量赋值

若是初始化变量，则可以不用添加类型，变量会自动采用其值的类型

例如：

```go
package main

import "fmt"

var i, j int = 1, 2

func main() {
	var c, python, java = true, false, "no!"
	fmt.Println(i, j, c, python, java)
}
```

这里函数里面的 `var c, python, java = true, false, "no!"` 就没有声明变量类型

## Short variable declarations

在函数内部，可以使用 `:=` 替代带有隐式类型的 `var` 声明

这里的隐式声明就是刚刚的初始化变量（有了值，才能判断类型

但在函数外部，每个语句都以关键词（例如 `var`，`func` 等）开头，不可使用 `:=`

例如：

```go
package main

import "fmt"

func main() {
	var i, j int = 1, 2
	k := 3
	c, python, java := true, false, "no!"

	fmt.Println(i, j, k, c, python, java)
}

```

这里是在函数内部使用 `:=`

## Basic types

go 中的基本类型如下：

```plain
bool

string

int  int8  int16  int32  int64
uint uint8 uint16 uint32 uint64 uintptr

byte // alias for uint8

rune // alias for int32
     // represents a Unicode code point

float32 float64

complex64 complex128
```

对于整数类型，除非是特殊情况要使用大小限制的 `int`，其余一律使用 `int`

int8，int16，int32 这些数字表示了它们占的位数

uint8 的别名是 byte

int32 的别名是 rune

complex64，complex128 用于复数

变量的声明和 `import` 一样，都可以采用分解式声明：

例如：

```go
var (
	ToBe   bool       = false
	MaxInt uint64     = 1<<64 - 1
	z      complex128 = cmplx.Sqrt(-5 + 12i)
)
```

## Zero values

对于未赋值的变量会被自动赋予初始零值

数值类型为 0

布尔类型为 false

字符类型为 ""（空字符串

## Type conversions

对于不同类型的值之间进行赋值必须要 **显式声明**（go 不允许隐式声明

例如：

```go
var i int = 42
var f float64 = float64(i)
var u uint = uint(f)
```

对于 `var f float64 = float64(i)`，首先 `i` 被 `float64()` 转变为 float64 类型

其次再将其赋值给同样为 float64 的 `f`

若是这样操作 `var f float64 = i`，则 go 会进行报错（这个是错误的喵

## Type inference

若是没有显式声明，则变量的类型是从等号右边得出的

其实就是 ”看菜下碟“（前面提过

例如：

```go
var i int
j := i // j is an int

i := 42           // int
f := 3.142        // float64
g := 0.867 + 0.5i // complex128
```

## Constants

常量的声明要使用 `const` 关键词

常量的值可以为数值，字符，字符串，布尔值

常量不能使用 `:=` 进行声明

## Numeric Constants

数值常量是 **高精度值**

这意味着数值常量没有赋值给具体的变量之前，它们的大小是没有限制的

无类型常量会根据上下文采用相应的类型

## For

go 只有这一个循环结构，就是 `for`

基本形式：`for init; condition; post { ... }`

基本的 go 的 for 循环依旧由三部分组成，各部分依旧用 `;` 进行分隔：

1. 初始化语句：在第一次迭代之前执行
2. 条件表达式：在每次迭代之前进行评估
3. post 语句：在每次迭代结束时执行

例如：

```go
package main

import "fmt"

func main() {
	sum := 0
	for i := 0; i < 10; i++ {
		sum += i
	}
	fmt.Println(sum)
}

```

`i := 0` -- 初始化语句，init 的声明的变量仅在 for 的作用域可见

`i < 10` --条件表达式，condition

`i++` -- post 语句

当 for 循环结果为 `false` 的时候循环停止

与其他语言不同的点在于，第一个 `for` 它三个组成部分没有 `()`；第二个是它循环部分必须使用花括号 `{}`（哪怕一行代码也得要 `{}`

init 和 post 语句是可选的（即可以不用写

例如：

```go
func main() {
	sum := 1
	for ; sum < 1000; {
		sum += sum
	}
	fmt.Println(sum)
}
```

这个时候可以去掉 `;`：

```go
func main() {
	sum := 1
	for sum < 1000 {
		sum += sum
	}
	fmt.Println(sum)
}
```

## If

if 和 for 类似，表达式不需要使用括号 `()` 括起来，但是其中内容必须要使用 `{}` 括起来

if 也可以在条件执行前先执行一个简短代码（类似 for

例如：

```go
func pow(x, n, lim float64) float64 {
	if v := math.Pow(x, n); v < lim {
		return v
	}
	return lim
}
```

`v := math.Pow(x, n)` 就是那段简短代码

注意它的作用域只存在于 if 的花括号内（和 else 的花括号内

例如：

```go
func pow(x, n, lim float64) float64 {
	if v := math.Pow(x, n); v < lim {
		return v
	}
	return lim, v
}
```

这里的 `return lim, v` 就会出现 `undefined: v` 这个报错

函数调用先完成内部再完成外部的

例如：

```go
package main

import (
	"fmt"
	"math"
)

func pow(x, n, lim float64) float64 {
	if v := math.Pow(x, n); v < lim {
		return v
	} else {
		fmt.Printf("%g >= %g\n", v, lim)
	}
	// can't use v here, though
	return lim
}

func main() {
	fmt.Println(
		pow(3, 2, 10),
		pow(3, 3, 20),
	)
}

```

这里会先执行完 `pow(3, 2, 10)` 和 `pow(3, 3, 20)` 之后才会执行 `fmt.Println`

因此结果为：

```plain
27 >= 20
9 20
```

虽然是先得到了第一个式子 `pow(3, 2, 10)` 的结果 9，但是要等第二个 `pow(3, 3, 20)` 执行完才能输出 9；而第二个的结果中先执行了输出 `27 >= 20` 后又得到了 20，因此得到此结果
练习现在还没做（（（

## Switch

和 C 类似，运行第一个值等于 case 的条件表达式

其中的每个 `case` 中的内容会自带一个 `break`，即 `switch` 匹配到相应的 `case` 就会退出，不会再执行其中后续的代码

`switch` 中的 `case` 也不必是常量，涉及的值也不必是整数（@Java

例如：

```go
package main  
​  
import (  
    "fmt"  
    "runtime"  
)  
​  
func main() {  
    fmt.Print("Go runs on ")  
    switch os := runtime.GOOS; os {  
    case "darwin":  
        fmt.Println("macOS.")  
    case "linux":  
        fmt.Println("Linux.")  
    default:  
        // freebsd, openbsd,  
        // plan9, windows...  
        fmt.Printf("%s.\n", os)  
    }  
}  
​
```

若是 `switch` 在其中的所有 `case` 中都未匹配到，则采用 `default` 中预先设定的值

## Switch with no condition

若是写为 `switch {}`，则此时该语句等价于 `switch true {}`

该语句作用是：若是 `switch` 中的 `case` 执行结果为 `true` 则执行那个分支

例如：

```go
package main  
​  
import (  
    "fmt"  
    "time"  
)  
​  
func main() {  
    t := time.Now()  
    switch {  
    case t.Hour() < 12:  
        fmt.Println("Good morning!")  
    case t.Hour() < 17:  
        fmt.Println("Good afternoon.")  
    default:  
        fmt.Println("Good evening.")  
    }  
}  
```
​
这里若是成功匹配到了相应的 `case`，则直接执行其中的内容

## Defer

defer 语句将其后的函数推迟到周围函数执行返回为止

被推迟的调用参数会被立即求值，但是它的函数调用会直到周围的函数返回才会被执行

例如：

```go
package main  
​  
import "fmt"  
​  
func main() {  
    defer fmt.Println("world")  
​  
    fmt.Println("hello")  
}  
```
​
这里我们对 `fmt.Println("world")` 使用了 `defer` 后，该函数的输出被进行推迟，因此函数会优先执行 `fmt.Println("hello")`，等输出结果后再进行 `fmt.Println("world")`

## Stacking defers

这里拿一个最精髓的例子来解释：

```go
package main  
​  
import "fmt"  
​  
func main() {  
    fmt.Println("开始")  
​  
    // 依次压入3个延迟调用  
    defer fmt.Println("延迟 1：最先被defer，最后执行")  
    defer fmt.Println("延迟 2：中间被defer")  
    defer fmt.Println("延迟 3：最后被defer，最先执行")  
​  
    fmt.Println("结束")  
}
```

总结：延迟函数调用会被压入一个栈中。当一个函数返回时，它的延迟调用会按照 **后进先出** 的顺序执行（具体实现就是上述的例子

在上述的例子中，最后被延迟函数压入栈（后进）的会被最先执行（先出）

## Pointers

指针！

（因为这一章 0n1y 在学习 C 的时候跑去学习 Python 了 55555，所以可能有点详细）

指针保留一个值的内存地址

类型 `*T` 是实现 `T` 值的指针，它的零值是 `nil`（即空指针

例如：

`var p *int`

声明一个名为 `p` 的变量，它的类型是 **指向整数的指针**

此时这个 `p` 只是一个空指针

我们可以使用 `&` 去让它真正指向某个变量（在此处为 `int` 类型的变量

例如：

```go
var num int = 100  
var p *int  
p = &num
```

此番操作过后，`p` 便不再是 `nil`，它是存着 `num` 地址的指针

接着，我们可以接着使用 `*` 去进行指针内容的提取

例如：

```go
var num int = 100  
var p *int = &num  
​  
fmt.Println(p)   // 输出: 地址本身  
fmt.Println(*p)  // 输出: 100
```

由此可见：

在声明的时候，`*` 的作用是说明其为指针类型的变量

在表达式中，`*` 的作用是获取指针指向的 **真实值**

其中，`*p` 也被叫做 **解引用** 或者 **间接引用**

Go 没有指针计算（这里对 C 的指针计算不了解就不解释了233

## Structs

结构体，即一组字段的集合

例如：

```go
type Vertex struct {  
    X int  
    Y int  
}
```

结构体字段通过 `.` 进行访问（使用

例如：

```go
package main  
​  
import "fmt"  
​  
type Vertex struct {  
    X int  
    Y int  
}  
​  
func main() {  
    v := Vertex{1, 2}  
    v.X = 4  
    fmt.Println(v.X)  
}
```

这里先创建了一个 `v` 的实例，使其中的 `X, Y` 属性分别赋值为 `1, 2`

随后的 `v.X = 4` 通过点号取到 v 实例内部的 X 属性，并且赋值使其等于 4

## Pointers to structs

可以使用结构体指针去访问结构体字段

我们可以使用 `p.X` 去直接访问，而不需要写成 `(*p).X`

例如：

```go
package main

import "fmt"

type Vertex struct {
	X int
	Y int
}

func main() {
	v := Vertex{1, 2}
	p := &v
	p.X = 1e9
	fmt.Println(v)
}

```

这里先得到一个实例 v，随后初始化一个指向 v 的结构体指针 v

原本应该先解引用才能使我们访问得到指针指向的真实值

即 `(*p).X`，这里必须得加括号，因为 go 中点号的优先级大于 `*`

但是 go 就有很好的一点，它不需要加括号和 `*`，要提取指针中的真实值时直接使用 `p.X` 即可

## Struct Literals

正常来讲，我们为一个结构体实例赋值的时候是严格按照顺序去进行赋值

但是 go 提供了一种自定义的赋值，可以不依赖顺序

例如：

```go
package main

import "fmt"

type Vertex struct {
	X, Y int
}

var (
	v1 = Vertex{1, 2}  // has type Vertex
	v2 = Vertex{X: 1}  // Y:0 is implicit
	v3 = Vertex{}      // X:0 and Y:0
	p  = &Vertex{1, 2} // has type *Vertex
)

func main() {
	fmt.Println(v1, p, v2, v3)
}

```

这里的 `v2 = Vertex{X: 1}` 将 X 属性初始化为 1，而没有初始化 Y 属性，于是 Y 属性自动采用 **该类型的 0 值**

并且这个赋值和顺序无关

例如：

`v2 = Vertex{X: 1, Y: 2}` 和 `v2 = Vertex{Y: 2, X: 1}` 是完全等价的

还可以初始化结构体指针：

例如：

```go
var (
	v1 = Vertex{1, 2}  // has type Vertex
	v2 = Vertex{X: 1}  // Y:0 is implicit
	v3 = Vertex{}      // X:0 and Y:0
	p  = &Vertex{1, 2} // has type *Vertex
)
```

这里的 `p  = &Vertex{1, 2}` 将 p 初始化为指向 Vertex 这个结构体的指针

## Arrays

`[n]T` 是一个包含 `n` 类型为 `T` 的值的数组

例如：

```go
var a [10]int
```

注意，数组的长度是其类型的一部分，所以数组是不能直接调整大小

因此，我们也可以说，数组的大小是固定的

这里引入 **切片** 的概念：

它是一种动态调整大小、灵活地访问数组元素的视图（好用！

`[]T` 是一个切片，其中元素类型为 T

它是通过上下限和冒号组成的：

`a[low : high]`

这里的 `low` 是闭区间（没错，这不是数学，它将包含该位置的元素

`high` 则是开区间，不包含该位置元素

例如：

```go
package main

import "fmt"

func main() {
	primes := [6]int{2, 3, 5, 7, 11, 13}

	var s []int = primes[1:4]
	fmt.Println(s)
}
```

这里创建了 s 这个切片，类型为 int

结果为 `[3 5 7]`

切片不会存储任何数据，但是改变切片中的数据会同时影响原数组中的元素和共享该数组的其他切片数据

例如：

```go
package main

import "fmt"

func main() {
	names := [4]string{
		"John",
		"Paul",
		"George",
		"Ringo",
	}
	fmt.Println(names)

	a := names[0:2]
	b := names[1:3]
	fmt.Println(a, b)

	b[0] = "XXX"
	fmt.Println(a, b)
	fmt.Println(names)
}

```

这里的结果为：

```plain
[John Paul George Ringo]
[John Paul] [Paul George]
[John XXX] [XXX George]
[John XXX George Ringo]
```

## Slice literals

切片字面量相当于一个数组字面量（但是没有长度

例如：

这是一个数组字面量
`[3]bool{true, true, false}`

这是一个切片字面量
`[]bool{true, true, false}`

相较于数组字面量，切面字面量更方便，它能让我们直接计算好数组中的元素个数（不用去填、将元素填入数组中等等

使用切片时，我们可以忽略其上下限，而这会使得它改用默认值

下限默认值为 0，上限默认值为切片长度

例如，对于 `var a [10]int`，以下切片等价：

```go
a[0:10]
a[:10]
a[0:]
a[:]
```

## Slice length and capacity

切片是有长度和容量的

切片的长度指的是切片中所含的元素个数

切片的容量指的是其底层数组中所含的元素个数，从切片中的第一个元素开始数

例如：

```go
package main

import "fmt"

func main() {
	arr := [4]int{10, 20, 30, 40}

	sl1 := arr[0:4]
	sl2 := arr[0:2]
	sl3 := arr[1:3]
	sl4 := arr[1:4]

	fmt.Printf("sl1: %v, len: %d, cap: %d\n", sl1, len(sl1), cap(sl1))
	fmt.Printf("sl2: %v, len: %d, cap: %d\n", sl2, len(sl2), cap(sl2))
	fmt.Printf("sl3: %v, len: %d, cap: %d\n", sl3, len(sl3), cap(sl3))
	fmt.Printf("sl4: %v, len: %d, cap: %d\n", sl4, len(sl4), cap(sl4))
}
```

对于切片长度：（`len()`）

sl1 的值为 4

sl2 的值为 2

sl3 的值为 2

sl4 的值为 3

对于切片容量：（`cap()`）

sl1 的值为 4

sl2 的值为 4

sl3 的值为 3

sl4 的值为 3

对此，其实只有容量需要去进行理解

切片的容量是从它的下限开始一直到底层数组的最后一个元素为止元素的数量

（看到上面的 sl3 和 sl4 的容量值没有因为上限设置的不同而输出不同的结果

只要切片的容量够，就随时可以通过修改切片去延展切片的长度（若是切片长度超过了容量则会报错

## Nil slices

切片的零值是 `nil`

空切片的长度和容量都是 0，并且其没有底层数组

## Creating a slice with make

make 可以创建动态大小的数组（虽然创造的还是切片

make 函数会创造一个零数组（自动将这个数组中的所有值赋值为 0

并且返回一个指向该数组的切片

例如：

`a := make([]int, 5)  // len(a)=5`

make 接受三个参数，第一个参数为 **切片的类型**，第二个参数为 **切片的长度**，第三个参数为 **切片的容量**

## Slices of slices

切片可以包含任意类型的切片，包括其他的切片

例如：

```go
package main

import (
	"fmt"
	"strings"
)

func main() {
	// Create a tic-tac-toe board.
	board := [][]string{
		[]string{"_", "_", "_"},
		[]string{"_", "_", "_"},
		[]string{"_", "_", "_"},
	}

	// The players take turns.
	board[0][0] = "X"
	board[2][2] = "O"
	board[1][2] = "X"
	board[1][0] = "O"
	board[0][2] = "X"

	for i := 0; i < len(board); i++ {
		fmt.Printf("%s\n", strings.Join(board[i], " "))
	}
}
```

其实就是类似二维数组，通过二维的索引去访问其中元素

## Appending to a slice

go 中内置了一个 `append` 函数，可以像切片中添加新元素，基本形式如下：

`func append(s []T, vs ...T) []T`

`append` 函数中的第一个参数是一个类型为 T 的切片，其余参数是要添加到切片中的值

`append` 函数返回的结果是一个包含了完整原始切片加上新添加值的新切片

若是新添加的元素超过了原切片的容量，那么 go 会自动开出一片更大的新数组

并且将旧数组中的内容全部拷贝到新数组中并且加上新添加的元素

注意：此操作结束后新数组的内存地址将是一个全新的地址！（意味着若是我们在此之前使用过某个指向原数组的指针，当我们在添加了新元素后再次访问该指针得到的不是新的切片/数组；由此，我们也可以知道，若是发生了切片的扩容，这个 `append` 的动作将不会对原数组产生影响

## Range

`range` 形式的 `for` 循环遍历切片或者映射（即 `map`，后续会将

这里对 **切片** 进行 for 循环的时候不是必须使用 range，使用情况有很多种

例如：

```go
package main  
​  
import "fmt"  
​  
var pow = []int{1, 2, 4, 8, 16, 32, 64, 128}  
​  
func main() {  
    for i, v := range pow {  
        fmt.Printf("2**%d = %d\n", i, v)  
    }  
}  
​
```

这里的 i 是索引，v是对应索引位置的元素的副本（这里是用了两个参数 i 和 v

## Range continued

我们可以使用 `_` 去跳过索引或者值

例如：

```go
for i, _ := range pow //跳过值  
for _, value := range pow //跳过索引
```

如果只想要索引可以直接省略第二个变量：

`for i := range pow`

## Maps

实质就是键值对（

格式为：`map[KeyType]ValueType`

若是只声明一个变量而不做初始化，它的值为 `nil`

`nil` 没有键，也不能添加键

使用 `make` 去对 map 进行初始化

例如：

```go
package main

import "fmt"

type Vertex struct {
	Lat, Long float64
}

var m map[string]Vertex

func main() {
	m = make(map[string]Vertex)
	m["Bell Labs"] = Vertex{
		40.68433, -74.39967,
	}
	fmt.Println(m["Bell Labs"])
}

```

这里先使用 make 去初始化了一个映射

随后对其进行赋值

## Map literals continued

若是顶层类型只是一个类型名称，则可以省略

例如：

```go
package main

import "fmt"

type Vertex struct {
	Lat, Long float64
}

var m = map[string]Vertex{
	"Bell Labs": {40.68433, -74.39967},
	"Google":    {37.42202, -122.08408},
}

func main() {
	fmt.Println(m)
}

```

这里没有在 `map` 里面再纠结类型

因为在 map 定义的时候已经说过值是什么类型了，在填数据的时候直接填数据即可

## Mutating Maps

在映射中插入/更新元素：

`m[key] = elem`

获取元素：

`elem = m[key]`

删除元素：

`delete(m, key)`

可以使用双值赋值来测试 **键是否存在**：

`elem, ok = m[key]`

若是 key 在 m 中，则 ok 为 true；否则 ok 为 false

同时，如果 `key` 不在映射表中，则 `elem` 为映射表元素类型的零值

如果还没有声明 `elem` 或者 `ok` 可以如下使用：

`elem, ok := m[key]`

例如：

```go
package main

import "fmt"

func main() {
	m := make(map[string]int)

	m["Answer"] = 42
	fmt.Println("The value:", m["Answer"])

	m["Answer"] = 48
	fmt.Println("The value:", m["Answer"])

	delete(m, "Answer")
	fmt.Println("The value:", m["Answer"])

	v, ok := m["Answer"]
	fmt.Println("The value:", v, "Present?", ok)
}

```

这里的结果为：

```plain
The value: 42
The value: 48
The value: 0
The value: 0 Present? false
```

## Function values

函数也是值，也可以被传递

例如：

```go
package main

import (
	"fmt"
	"math"
)

func compute(fn func(float64, float64) float64) float64 {
	return fn(3, 4)
}

func main() {
	hypot := func(x, y float64) float64 {
		return math.Sqrt(x*x + y*y)
	}
	fmt.Println(hypot(5, 12))

	fmt.Println(compute(hypot))
	fmt.Println(compute(math.Pow))
}

```

这里的
```go
hypot := func(x, y float64) float64 {
		return math.Sqrt(x*x + y*y)
	}
```
就是把函数当成一个值去给变量进行赋值（随后变量 `hypot` 可以像普通函数一样被调用

这里的
```go
func compute(fn func(float64, float64) float64) float64 {
	return fn(3, 4)
}
```
`compute` 函数不用去管其中的 `fn` 函数是怎么个计算逻辑，它只需要知道 `fn` 函数收到两个 float64 类型的参数随后计算结果返回一个 float64 类型的参数

随后，我们只需要替换 fn 为其他函数（例如本例中的 hypot 和 math.Sqrt

即，若是我们向 compute 中传入的函数为 hypot，它的返回逻辑就会变为：

`return hypot(3, 4)`

若是 math.Sqrt 则同理，变为 `return math.Sqrt(3, 4)`

## Function closures

闭包是指函数值引用其外部变量。函数可以访问并赋值给被引用的变量

例如：

```go
package main

import "fmt"

func adder() func(int) int {
	sum := 0
	return func(x int) int {
		sum += x
		return sum
	}
}

func main() {
	pos, neg := adder(), adder()
	for i := 0; i < 10; i++ {
		fmt.Println(
			pos(i),
			neg(-2*i),
		)
	}
}

```

这里的 sum 即为闭包函数

在运行 adder() 后，sum并不会直接变为 0，而是继续着之前的 sum 值