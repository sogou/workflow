[English version](README_en.md)

## Sogou C++ Workflow
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://github.com/sogou/workflow/blob/master/LICENSE)
[![Language](https://img.shields.io/badge/language-c++-red.svg)](https://en.cppreference.com/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg)](#%E9%A1%B9%E7%9B%AE%E7%9A%84%E4%B8%80%E4%BA%9B%E8%AE%BE%E8%AE%A1%E7%89%B9%E7%82%B9)

搜狗公司C++服务器引擎，支撑搜狗几乎所有后端C++在线服务，包括所有搜索服务，云输入法，在线广告等，每日处理超百亿请求。这是一个设计轻盈优雅的企业级程序引擎，可以满足大多数C++后端开发需求。  
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
* 实现自定义协议client/server，构建自己的RPC系统。
  * [srpc](https://github.com/sogou/srpc)就是以它为基础，作为独立项目开源。支持``srpc``，``brpc``和``thrift``等协议。
* 构建异步任务流，支持常用的串并联，也支持更加复杂的DAG结构。
* 作为并行编程工具使用。除了网络任务，我们也包含计算任务的调度。所有类型的任务都可以放入同一个流中。
* 在``Linux``系统下作为文件异步IO工具使用，性能超过任何标准调用。磁盘IO也是一种任务。
* 实现任何计算与通讯关系非常复杂的高性能高并发的后端服务。
* 构建服务网格（service mesh）系统。
  * 项目内置服务治理与负载均衡等功能。

#### 编译和运行环境
* 项目支持``Linux``，``macOS``，``Windows``等操作系统。
  *  ``Windows``版以[windows](https://github.com/sogou/workflow/tree/windows)分支发布，使用``iocp``实现异步网络。用户接口与``Linux``版一致。
* 支持所有CPU平台，包括32或64位``x86``处理器，大端或小端``arm``处理器。
* 需要依赖于``OpenSSL``，推荐``OpenSSL 1.1``及以上版本。
  * 不喜欢SSL的用户可以使用[nossl](https://github.com/sogou/workflow/tree/nossl)分支或[study](https://github.com/sogou/workflow/tree/study)分支（无upstream），代码更简洁。但仍需链接``crypto``。
* 项目使用了``C++11``标准，需要用支持``C++11``的编译器编译。但不依赖``boost``或``asio``。
* 项目无其它依赖。如需使用``kafka``协议，需自行安装``lz4``，``zstd``和``snappy``几个压缩库。

# 试一下！
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
    * [更加简单的使用计算任务：go_task](docs/about-go-task.md)
  * 文件异步IO任务
    * [异步IO的http server：http_file_server](docs/tutorial-09-http_file_server.md)
  * 用户定义协议基础
    * [简单的用户自定义协议client/server](docs/tutorial-10-user_defined_protocol.md)
  * 定时与计数任务
    * [关于定时器](docs/about-timer.md)
    * [关于计数器](docs/about-counter.md)
  * 服务治理
    * [关于服务治理](docs/about-service-management.md)
    * [Upstream更多文档](docs/about-upstream.md)
  * 连接上下文的使用
    * [关于连接上下文](docs/about-connection-context.md)
  * 内置协议用法
    * [异步MySQL客户端：mysql_cli](docs/tutorial-12-mysql_cli.md)

#### 系统设计特点

我们认为，一个典型的后端程序由三个部分组成，并且完全独立开发。即：程序=协议+算法+任务流。
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

基础任务，任务工厂与复合任务
* 我们系统中包含六种基础任务：通讯，文件IO，CPU，GPU，定时器，计数器。
* 一切任务都由任务工厂产生，并且在callback之后自动回收。
  * server任务是一种特殊的通讯任务，由框架调用任务工厂产生，通过process函数交给用户。
* 大多数情况下，用户通过任务工厂产生的任务，都是一个复合任务，但用户并不感知。
  * 例如，一次http请求，可能包含许多次异步过程（DNS，重定向），但对用户来讲，就是一次通信任务。
  * 文件排序，看起来就是一个算法，但其实包括复杂的文件IO与CPU计算的交互过程。
  * 如果把业务逻辑想象成用设计好的电子元件搭建电路，那么每个电子元件内部可能又是一个复杂电路。

异步性和基于``C++11 std::function``的封装
* 不是基于用户态协程。使用者需要知道自己在写异步程序。
* 一切调用都是异步执行，几乎不存在占着线程等待的操作。
  * 虽然我们也提供一些便利的半同步接口，但并不是核心的功能。
* 尽量避免派生，以``std::function``封装用户行为，包括：
  * 任何任务的callback。
  * 任何server的process。符合``FaaS``（Function as a Service）思想。
  * 一个算法的实现，简单来讲也是一个``std::function``。但算法也可以用派生实现。

内存回收机制
* 任何任务都会在callback之后被自动内存回收。如果创建的任务不想运行，则需要通过dismiss方法释放。
* 任务中的数据，例如网络请求的resp，也会随着任务被回收。此时用户可通过``std::move()``把需要的数据移走。
* SeriesWork和ParallelWork是两种框架对象，同样在callback之后被回收。
* 项目中不使用``std::shared_ptr``来管理内存。

#### 更多设计文档
持续更新中……


#### Authors

* **Xie Han** - *[xiehan@sogou-inc.com](mailto:xiehan@sogou-inc.com)*
* **Wu Jiaxu** - *[wujiaxu@sogou-inc.com](mailto:wujiaxu@sogou-inc.com)*
* **Li Yingxin** - *[liyingxin@sogou-inc.com](mailto:liyingxin@sogou-inc.com)*
