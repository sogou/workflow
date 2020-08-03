[English version](README_en.md)

[![license MIT](https://img.shields.io/badge/License-Apache-yellow.svg)](https://git.sogou-inc.com/wujiaxu/Filter/blob/master/LICENSE)
[![C++](https://img.shields.io/badge/language-c++-red.svg)](https://en.cppreference.com/)
[![platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg)](#%E9%A1%B9%E7%9B%AE%E7%9A%84%E4%B8%80%E4%BA%9B%E8%AE%BE%E8%AE%A1%E7%89%B9%E7%82%B9)

# Sogou C++ Workflow
#### 搜狗公司的后端C++编程标准，是一套企业级的程序引擎。主要功能和特点：
  * 这是一个基于C++11 ``std::function`` 的异步引擎。用于解决一切关于串行，并行和异步的问题。
  * 作为网络框架，完全协议无关，并且直接面向应用。
    * 可以当作一个异步redis客户端，也可以快速搭建一个Http服务器。
    * 自定义协议非常方便，你可以快速的建立一个自己的RPC系统。
      * Sogou RPC就是以它为基础开发，作为独立项目开源。该项目支持srpc，brpc和thrift等协议（[benchmark](https://github.com/holmes1412/sogou-rpc-benchmark)）。
    * 支持SSL(依赖openssl)。支持TCP, UDP，SCTP等常用传输层协议。可支持SCTP上的SSL。但不支持UDP server。
  * 原生包含了多种常有互联网协议的实现，并且以统一的方式使用。
    * 目前支持http，redis，mysql和kafka协议，可以直接访问这些资源或搭建这些协议的server。
    * 可能是目前市面上唯一C++全功能的mysql异步客户端。
    * DNS协议开发中，目前使用系统库访问dns。
  * 包含强大的计算任务调度功能。
    * 计算任务可以和通信任务一样都可以加入任务流，有各自的调度器实现调度。
    * 你可以不用网络功能，把它当并行编程工具来使用。
    * 我们最大的目的就是在计算和通信非常复杂的情况下，最大程度的发挥节点的性能。
    * 提供了一些常用算法实现，例如并行排序，MapReduce。
    * 实际上，一切异步过程（如磁盘IO，GPU任务，定时器等）都可以被协同调度。
      * 如果用户使用Linux系统，磁盘IO任务是是通过Linux底层aio实现，效率极高。
  * 支持任何DAG结构的任务流。但大多数情况下，用户只需要使用串并联结构。
  * 自带负载均衡和强大的服务治理等功能。
  * 可以方便的与其他异步引擎协同使用。
  * 支持streaming的通讯引擎开发中。
  * 作为server使用时，支持多进程模式，支持精确的优雅重启。

#### 相关的技术要点：
  * 目前项目支持Linux，macOS，FreeBSD，Windows等系统。需要安装cmake。
    * Windows版暂时以独立[branch](https://github.com/sogou/workflow/tree/windows)发布，以iocp为异步通讯基础，对外接口一致。
  * 该项目使用C/C++编写，使用者需要能比较熟练的使用C++编程。不依赖boost或asio，编译速度极快。
  * 用到少量的C++11特征，用户需要会使用 ``std::function`` 和 ``std::move()`` 。
  * 理论支持一切CPU架构，可以在32位或64位arm处理器上编译运行。Big endian CPU未测试。
  * 项目需要依赖openssl。如果用户对SSL性能要求高，强烈建议使用openssl 1.1以上版本。
  * 项目无其他依赖，但包含了snappy，lz4等几个压缩库的无改动源代码（kafka协议需要）。

#### 项目的一些设计特点：
  * 项目基础用法非常简单，极易上手。而我们的一些设计也大幅降低了一般C++项目的使用难度。
    * 尽量避免让用户派生，一切用户行为都用 ``std::function`` 来包装，例如：
      * 任何任务结束后的callback。
      * 计算任务里的算法。
      * 一个server，也对应一个 ``std::function`` 。
    * 尽量避免复杂的内存管理，一切任务和框架由工厂类产生，并自动内存回收。
      * 任何任务在callback之后被自动delete。
      * 任务中的数据（例如一个网络回复包，一个算法的结果），如果用户要保留，需要用 ``std::move()`` 把它移走。
      * 内存回收是使用一套严密又符合自然逻辑的机制，我们不使用任何share_ptr。
    * 尽量避免复杂的参数配置。
      * 我们可配置的参数非常多，但您可以在对参数完全无感的情况下使用我们的系统。
      * 如果您对程序行为，资源配比有特定需求，一定能找到对应配置项，以便发挥程序最高性能。
  * 项目采用全异步的设计，并且对用户不透明，用户需要知道自己在写异步程序。
    * 我们通过精心的设计的用户尽量简单的使用异步，得益于 ``std::function`` 带来的便利性，以及自动内存回收机制。
    * 没有采用用户态线程的方式，一方面是性能考虑，另一方面原因是我们有计算任务（线程任务）调度的概念。
      * 在我们的设计里，计算是一种异步任务，和通信并没有什么区别。
      * 计算任务由独立的线程组依照特定算法进行调度，并不一定实时被执行。
      * 因为有这种计算任务的存在，用户态线程似乎就没什么意义了，用户必然需要了解异步。
    * 因为全异步的原因，我们几乎所有的核心调用都是短操作，不会阻塞。
      * 我们也不鼓励用户在callback里阻塞程序，或做复杂的计算。但如果业务逻辑简单，这么做也无妨。
  * 项目使用方法的简单总结：
    * 用户如同搭建串并联电路一样搭建程序。电路可以一开始就生成好，也可以运行中动态产生。
    * 我们提供各种电子元件供用户使用，一次http请求，一次GPU矩阵乘法，一次并行排序，都可以理解成为一个元件。
    * 每个电子元件都有标准的输入输出。但每个电子元件内部，可能又是一个复杂电路，但用户并不感知。
      * 比如一个http请求，可能要经历DNS，redirect，retry等多次异步过程，但对用户来讲，只是一个元件。
    * 用户可以方便的定义自己的元件。比如一个算法，一次通信。
      * 无状态的协议实现起来极其简单。如果协议有登录，选库等过程，则会复杂一些，可参考redis实现。
    * 通过强大的Upstream系统，能实现非常复杂的服务治理，例如通信节点选择，负载均衡，熔断与恢复，主备等。
    * 总之这是一个企业级的，设计优雅的异步编程框架，几乎可以覆盖一切高性能的后端服务需求。

#### 使用教程：
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
    * [关于DNS](docs/about-dns.md)
    * [关于程序退出](docs/about-exit.md)
  * 计算任务
    * [使用内置算法工厂：sort_task](docs/tutorial-07-sort_task.md)
    * [自定义计算任务：matrix_multiply](docs/tutorial-08-matrix_multiply.md)
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

## Authors

* **Xie Han** - *[xiehan@sogou-inc.com](mailto:xiehan@sogou-inc.com)*
* **Wu Jiaxu** - *[wujiaxu@sogou-inc.com](mailto:wujiaxu@sogou-inc.com)*
* **Li Yingxin** - *[liyingxin@sogou-inc.com](mailto:liyingxin@sogou-inc.com)*


