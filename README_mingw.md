
# Windows MingW下编译

编译方式需要采用`MSYS2`，通过自带的`pacman`来添加`OpenSSL`库等。
编译workflow前需要先安装**MSYS2和依赖库**

## 安装MSYS2
通过[MSYS2官网](https://www.msys2.org/)下载msys2对应的安装包既可。
* 64位选x86_64
* 32位选i686

## 换源
打开`MSYS2`的`etc\pacman.d`目录，在对应的目录添加相应源`mirrorlist.mingw32`、`mirrorlist.mingw64`、`mirrorlist.msys`，镜像源请自行通过搜索引擎进行搜索。

## 安装依赖库
打开`MSYS2`终端，弹窗显示shell窗口。
更新依赖包
```powershell
pacman -Syuu
```

依次安装（自动安装openssl）
```powershell
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-extra-cmake-modules
pacman -S mingw-w64-x86_64-make
pacman -S mingw-w64-x86_64-gdb
pacman -S mingw-w64-x86_64-toolchain
pacman -S mingw-w64-x86_64-gcc
pacman -S make
pacman -S cmake

#(可选)
pacman -S mingw-w64-x86_64-gtest
```

# 编译
代码主要调整：
* 兼容原版Windows和MingW，编译时只需要添加`MingW=y`
* `MingW`编译，开启了编译`libworkflow.so`
* `MingW`编译，开启了返回异常。关闭请更改`-fexceptions` -> `-fno-exceptions`
* 新增基线`tutorial-00-helloworld.cc`，方便检查
* 支持`gtest`
* 修复编译检查报错

## 编译release
```
make -j MINGW=y

cd tutorial/
make -j MINGW=y

cd test/
make -j check MINGW=y
```

## 编译debug
```
make -j MINGW=y DEBUG=y

cd tutorial/
make -j MINGW=y DEBUG=y

cd test/
make -j check MINGW=y DEBUG=y
```

## 清理
```powershell
make clean
```