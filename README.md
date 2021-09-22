[Workflow Introduction](https://github.com/sogou/workflow/blob/master/README.md)

[Windows下Workflow编译指南](/README_cn.md)

[![license MIT](https://img.shields.io/badge/License-Apache-yellow.svg)](https://git.sogou-inc.com/wujiaxu/Filter/blob/master/LICENSE)
[![C++](https://img.shields.io/badge/language-c++-red.svg)](https://en.cppreference.com/)
[![platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](#%E9%A1%B9%E7%9B%AE%E7%9A%84%E4%B8%80%E4%BA%9B%E8%AE%BE%E8%AE%A1%E7%89%B9%E7%82%B9)
[![Build Status](https://travis-ci.com/sogou/workflow.svg?branch=windows)](https://travis-ci.com/sogou/workflow)

# Build Workflow On Windows

We use cmake to build the workflow project. It denpends one OpenSSL. It's essential to install **CMake and OpenSSL**.

## Install CMake

Visit [CMake Homepage](https://cmake.org/download/), and download the msi installer to install cmake.

## Install OpenSSL

### Ways to Install OpenSSL Library On Windos

* Download the source code to compile
* Donnload the bianary installer of OpenSSL
* Install by Chocolatey
* Install by VCPKG

### Compile OpenSSL by Source Code

Visit [OpenSSL Homepage](https://www.openssl.org/) or [Github repository](https://github.com/openssl/openssl) to download the source code.
Compile OpenSSL by its document.

### Install OpenSSL by binary installer

Google *OpenSSL binary installer* and download the installer to install. **Do not use light version**, because it doesn't contains *include and lib dictionary*.

[Here](https://slproweb.com/products/Win32OpenSSL.html) is a binary installer download website.


### Install OpenSSL by Chocolatey

[Chocolatey](https://community.chocolatey.org/) is a powerful package manager on windows. It's like apt-get or yum on some Linux distribution.

Use the command to install OpenSSL by Chocolatey.

```powershell
choco install openssl
```

### Install OpenSSL by VCPKG

[VCPKG](https://docs.microsoft.com/zh-cn/cpp/build/vcpkg?view=vs-2019) is a powerful CPP package manager across platforms.
It simplify the installation of some libraries.

Use the command to install OpenSSL by vcpkg.

```powershell
vcpkg install openssl
```

## Compile Workflow
### Compile OpenSSL by source code

Specify the **OPENSSL_ROOT_DIR** to generate Visual Studio Project, Such as

```powershell
cmake -B [build directory] -S . -DOPENSSL_ROOT_DIR=[openssl directory]
```

### Install OpenSSL by Installer or Chocolatey

Use Command to generate Visual Studio Project

```powershell
cmake -B [build directory] -S .
```

### Install OpenSSL by vcpkg
Specify **CMAKE_TOOLCHAIN_FILE** is essential to generate Visual Studio Project, Suche as

```powershell
 cmake -B [build directory] -S . -DCMAKE_TOOLCHAIN_FILE=[vcpkg.cmake directory]
# If the above command fails, try to specify VCPKG_TARGET_TRIPLET, use x86-windows or x64-windows
cmake -B [build directory] -S . -DVCPKG_TARGET_TRIPLET=x86-windows -DCMAKE_TOOLCHAIN_FILE=[vcpkg.cmake directory]
```

### Others
**[openssl directory]**: openssl directory of source code

**[vcpkg.cmake directory]** : [vcpkg-root]\scripts\buildsystems\vcpkg.cmake


The VS Project(workflo.sln) will be generated now. 

Use VS to open workflow.sln or use cmake command to compile workflow, Such as

```powershell
# Compile Debug Config
cmake --build [build directory] --config Debug
# Compile Release Config
cmake --build [build directory] --config Release
```

### Compile Tutorial of Workflow
```powershell

# Generate VS Project of tutorial
cmake -B build_tutorial tutorial

# Compile Debug Config
cmake --build build_tutorial --config Debug
# Compile Release Config
cmake --build build_tutorial --config Release

# compile result will be generated in tutorial\Debug or tutorial\Release directory
```

# Install Workflow by VCPKG

Workflow is already supported by VCPKG. If you don't care the source code of workflow, It's more easier to use vcpkg to install it.

[VCPKG Guide](https://docs.microsoft.com/zh-cn/cpp/build/vcpkg?view=msvc-160)

Install current version of workflow：`vcpkg install workflow`

Install HEAD version of workflow：`vcpkg install workflow --head`

Some examples:

## On Windows

```powershell
md D:\tmp
cd D:\tmp
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
# x86-windows is default, it means .\vcpkg.exe install workflow:x86-windows
.\vcpkg.exe install workflow
# Specify x64-windows to install X64 version
.\vcpkg.exe install workflow:x64-windows

cd D:\tmp
git clone https://github.com/dengjunplusplus/workflow-vcpkg-tutorial

cd D:\tmp\workflow-vcpkg-tutorial\workflow
cmake  -DCMAKE_TOOLCHAIN_FILE=D:/tmp/vcpkg/scripts/buildsystems/vcpkg.cmake -B build
# If the above command fails, try to specify VCPKG_TARGET_TRIPLET, use x86-windows or x64-windows
cmake  -DCMAKE_TOOLCHAIN_FILE=D:/tmp/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x86-windows -B build
cmake --build build --config Debug
cmake --build build --config Release

```

## On Linux & Mac

```bash
cd /tmp
rm -rf vcpkg
rm -rf workflow-vcpkg-tutorial
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg install workflow

cd ..
git clone https://github.com/dengjunplusplus/workflow-vcpkg-tutorial.git
cd workflow-vcpkg-tutorial/workflow
cmake -DCMAKE_TOOLCHAIN_FILE=/tmp/vcpkg/scripts/buildsystems/vcpkg.cmake -B build
# If the above command fails, try to specify VCPKG_TARGET_TRIPLET, x64-linux or x86-linux or x64-osx
cmake -DCMAKE_TOOLCHAIN_FILE=/tmp/vcpkg/scripts/buildsystems/vcpkg.cmake  -DVCPKG_TARGET_TRIPLET=x64-linux -B build
cmake --build build --config Debug
cmake --build build --config Release

```

# Contact Us

If you have some problems about use Workflow or compile it. Welcome to commit Issue or Email us.

## Problems about Use Workflow

* **Xie Han** - *[xiehan@sogou-inc.com](mailto:xiehan@sogou-inc.com)*
* **Li Yingxin** - *[liyingxin@sogou-inc.com](mailto:liyingxin@sogou-inc.com)*

## Problems about Compile Workflow On Windows Or VCPKG

* **Deng Jun** - *[dengjun@sogou-inc.com](mailto:dengjun@sogou-inc.com)*
