[English version](README.md)

## Sogou C++ Workflow
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://github.com/sogou/workflow/blob/master/LICENSE)
[![Language](https://img.shields.io/badge/language-c++-red.svg)](https://en.cppreference.com/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://img.shields.io/badge/platform-linux%20%7C%20macos20%7C%20windows-lightgrey.svg)
[![Build Status](https://img.shields.io/github/actions/workflow/status/sogou/workflow/ci.yml?branch=master)](https://github.com/sogou/workflow/actions?query=workflow%3A%22ci+build%22++)

搜狗公司C++服务器引擎，编程范式。支撑搜狗几乎所有后端C++在线服务，包括所有搜索服务，云输入法，在线广告等，每日处理数百亿请求。这是一个设计轻盈优雅的企业级程序引擎，可以满足大多数后端与嵌入式开发需求。  
#### 你可以用来：
* 快速搭建http服务器：
~~~cpp
#include <stdio.h>
#include "workflow/WFHttpServer.h"

int main()
{
    WFHttpServer server([](WFHttpTask *task) {
        task->get_resp()->append_output_body("<html>Hello World!</html>");
    });

    if (server.start(8888) == 0) {  // start server on port 8888
        getchar(); // press "Enter" to end.
        server.stop();
    }

    return 0;
}
~~~
* 作为万能异步客户端。目前支持``http``，``redis``，``mysql``和``kafka``协议。
  * 轻松构建效率极高的spider。
* 实现自定义协议client/server，构建自己的RPC系统。
  * [srpc](https://github.com/sogou/srpc)就是以它为基础，作为独立项目开源。支持``srpc``，``brpc``，``trpc``和``thrift``等协议。
* 构建异步任务流，支持常用的串并联，也支持更加复杂的DAG结构。
* 作为并行计算工具使用。除了网络任务，我们也包含计算任务的调度。所有类型的任务都可以放入同一个流中。
* 在``Linux``系统下作为文件异步IO工具使用，性能超过任何标准调用。磁盘IO也是一种任务。
* 实现任何计算与通讯关系非常复杂的高性能高并发的后端服务。
* 构建微服务系统。
  * 项目内置服务治理与负载均衡等功能。
* Wiki链接 : [PaaS 架构图](https://github.com/sogou/workflow/wiki)

#### 编译和运行环境
* 项目支持``Linux``，``macOS``，``Windows``，``Android``等操作系统。
  *  ``Windows``版以[windows](https://github.com/sogou/workflow/tree/windows)分支发布，使用``iocp``实现异步网络。用户接口与``Linux``版一致。
* 支持所有CPU平台，包括32或64位``x86``处理器，大端或小端``arm``处理器，国产``loongson``龙芯处理器实测支持。
* 需要依赖于``OpenSSL``，推荐``OpenSSL 1.1``及以上版本。
  * 不喜欢SSL的用户可以使用[nossl](https://github.com/sogou/workflow/tree/nossl)分支，代码更简洁。
* 项目使用了``C++11``标准，需要用支持``C++11``的编译器编译。但不依赖``boost``或``asio``。
* 项目无其它依赖。如需使用``kafka``协议，需自行安装``lz4``，``zstd``和``snappy``几个压缩库。

#### 快速开始（Linux, macOS）：
~~~sh
git clone https://github.com/sogou/workflow # From gitee: git clone https://gitee.com/sogou/workflow
cd workflow
make
cd tutorial
make
~~~
#### 使用SRPC工具（NEW!）
SRPC工具可以生成完整的workflow工程，根据用户命令生成对应的server，client或proxy框架，以及CMake工程文件和JSON格式的配置文件。  
并且，工具会下载最小的必要的依赖。例如在用户指定产生RPC项目时，自动下载并配置好protobuf等依赖。  
SRPC工具的使用方法可以参考：https://github.com/sogou/srpc/blob/master/tools/README_cn.md

#### Debian Linux或ubuntu上使用[apt-get](https://launchpad.net/ubuntu/+source/workflow)安装：
作为是Debian Linux与Ubuntu Linux 22.04版自带软件，可以通过``apt-get``命令直接安装开发包：
~~~sh
sudo apt-get install libworkflow-dev
~~~
或部署运行环境：
~~~sh
sudo apt-get install workflow1
~~~
注意ubuntu只有最新22.04版或以上自带workflow。更推荐用git直接下载最新源代码编译。
#### Fedora Linux上使用[dnf](https://packages.fedoraproject.org/pkgs/workflow)安装：
Workflow也是Fedora Linux的自带软件，可以使用最新的rpm包管理工具``dnf``直接安装开发包：
~~~~sh
sudo dnf install workflow-devel
~~~~
或部署运行环境：
~~~~sh
sudo dnf install workflow
~~~~
#### 使用xmake
如果你想用xmake去构建 workflow, 你可以看 [xmake build document](docs/xmake.md)

# 示例教程
  * Client基础
    * [创建第一个任务：wget](docs/tutorial-01-wget.md)
    * [实现一次redis写入与读出：redis_cli](docs/tutorial-02-redis_cli.md)
    * [任务序列的更多功能：wget_to_redis](docs/tutorial-03-wget_to_redis.md)
  * Server基础
    * [第一个server：http_echo_server](docs/tutorial-04-http_echo_server.md)
    * [异步server的示例：http_proxy](docs/tutorial-05-http_proxy.md)
  * 并行任务与工作流　
    * [一个简单的并行抓取：parallel_wget](docs/tutorial-06-parallel_wget.md)
  * 几个重要的话题
    * [关于错误处理](docs/about-error.md)
    * [关于超时](docs/about-timeout.md)
	* [关于全局配置](docs/about-config.md)
    * [关于DNS](docs/about-dns.md)
    * [关于程序退出](docs/about-exit.md)
  * 计算任务
    * [使用内置算法工厂：sort_task](docs/tutorial-07-sort_task.md)
    * [自定义计算任务：matrix_multiply](docs/tutorial-08-matrix_multiply.md)
    * [更加简单的使用计算任务：go_task](docs/about-go-task.md)【推荐】
  * 文件异步IO任务
    * [异步IO的http server：http_file_server](docs/tutorial-09-http_file_server.md)
  * 用户定义协议基础
    * [简单的用户自定义协议client/server](docs/tutorial-10-user_defined_protocol.md)
    * [使用TLV格式消息](docs/about-tlv-message.md)
  * 其它一些重要任务与组件
    * [关于定时器](docs/about-timer.md)
    * [关于计数器](docs/about-counter.md)
    * [模块任务](docs/about-module.md)
    * [DAG图任务](docs/tutorial-11-graph_task.md)
    * [Selector任务](docs/about-selector.md)
  * 任务间通信
    * [条件任务与观察者模式](docs/about-conditional.md)
    * [资源池与消息队列](docs/about-resource-pool.md)
  * 服务治理
    * [关于服务治理](docs/about-service-governance.md)
    * [Upstream更多文档](docs/about-upstream.md)
    * [自定义名称服务策略](docs/tutorial-15-name_service.md)
  * 连接上下文的使用
    * [关于连接上下文](docs/about-connection-context.md)
  * 内置客户端
    * [异步MySQL客户端：mysql_cli](docs/tutorial-12-mysql_cli.md)
    * [异步kafka客户端：kafka_cli](docs/tutorial-13-kafka_cli.md)
    * [异步DNS客户端：dns_cli](docs/tutorial-17-dns_cli.md)
    * [Redis订阅客户端：redis_subscriber](docs/tutorial-18-redis_subscriber.md)

#### 编程范式

程序 = 协议 + 算法 + 任务流
* 协议
  * 大多数情况下，用户使用的是内置的通用网络协议，例如http，redis或各种rpc。
  * 用户可以方便的自定义网络协议，只需提供序列化和反序列化函数，就可以定义出自己的client/server。
* 算法
  * 在我们的设计里，算法是与协议对称的概念。
    * 如果说协议的调用是rpc，算法的调用就是一次apc（Async Procedure Call）。
  * 我们提供了一些通用算法，例如sort，merge，psort，reduce，可以直接使用。
  * 与自定义协议相比，自定义算法的使用要常见得多。任何一次边界清晰的复杂计算，都应该包装成算法。
* 任务流
  * 任务流就是实际的业务逻辑，就是把开发好的协议与算法放在流程图里使用起来。
  * 典型的任务流是一个闭合的串并联图。复杂的业务逻辑，可能是一个非闭合的DAG。
  * 任务流图可以直接构建，也可以根据每一步的结果动态生成。所有任务都是异步执行的。

结构化并发与任务隐藏
* 我们系统中包含五种基础任务：通讯，计算，文件IO，定时器，计数器。
* 一切任务都由任务工厂产生，用户通过调用接口组织并发结构。例如串联并联，DAG等。
* 大多数情况下，用户通过任务工厂产生的任务，都隐藏了多个异步过程，但用户并不感知。
  * 例如，一次http请求，可能包含许多次异步过程（DNS，重定向），但对用户来讲，就是一次通信任务。
  * 文件排序，看起来就是一个算法，但其实包括复杂的文件IO与CPU计算的交互过程。
  * 如果把业务逻辑想象成用设计好的电子元件搭建电路，那么每个电子元件内部可能又是一个复杂电路。
  * 任务隐藏机制大幅减少了用户需要创建的任务数量和回调深度。
* 任何任务都运行在某个串行流（series）里，共享series上下文，让异步任务之间数据传递变得简单。

回调与内存回收机制
* 一切调用都是异步执行，几乎不存在占着线程等待的操作。
* 显式的回调机制。用户清楚自己在写异步程序。
* **通过一套对象生命周期机制，大幅简化异步程序的内存管理**
  * 任何框架创建的任务，生命周期都是从创建到callback函数运行结束为止。没有泄漏风险。
    * 如果创建了任务之后不想运行，则需要通过dismiss()接口删除。
  * 任务中的数据，例如网络请求的resp，也会随着任务被回收。此时用户可通过``std::move()``把需要的数据移走。
  * 项目中不使用任何智能指针来管理内存。代码观感清新。
* 尽量避免用户级别派生，以``std::function``封装用户行为，包括：
  * 任何任务的callback。
  * 任何server的process。符合``FaaS``（Function as a Service）思想。
  * 一个算法的实现，简单来讲也是一个``std::function``。
  * 如果深入使用，又会发现一切皆可派生。

# 使用中有疑问？
可以先查看[FAQ](https://github.com/sogou/workflow/issues/170)和[issues](https://github.com/sogou/workflow/issues)列表，看看是否能找到答案。  
非常欢迎将您使用中遇到的问题发送到[issues](https://github.com/sogou/workflow/issues)，我们将第一时间进行解答。同时更多的issue对新用户也会带来帮助。  
也可以通过QQ群：**618773193** 联系我们。

<img src="https://user-images.githubusercontent.com/1880011/92300953-e9cc5400-ef91-11ea-82f5-4cf3174cd851.jpeg" align=center width = "200" alt="qq_qrcode" />

#### Gitee仓库
用户可以在访问GitHub遇到困难时，使用我们的Gitee官方仓库：https://gitee.com/sogou/workflow  
**另外也麻烦在Gitee上star了项目的用户，尽量同步star一下[GitHub仓库](https://github.com/sogou/workflow)。谢谢！**
