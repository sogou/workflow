[中文版](README.md)

## Sogou C++ Workflow

[![C++](https://img.shields.io/badge/License-Apache-yellow.svg)](https://git.sogou-inc.com/wujiaxu/Filter/blob/master/LICENSE "license MIT") [![](https://img.shields.io/badge/language-c++-red.svg)](https://en.cppreference.com/ "platform") [![](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg)](#%E9%A1%B9%E7%9B%AE%E7%9A%84%E4%B8%80%E4%BA%9B%E8%AE%BE%E8%AE%A1%E7%89%B9%E7%82%B9)

As **Sogou\`s C++ server engine**, Sogou C++ Workflow supports almost all **back-end C++ online services** of Sogou, including all search services, cloud input method，online advertisements, etc., handling more than **10 billion** requests every day. This is an **enterprise-level programming engine** in light and elegant design which can satisfy most C++ back-end development requirements.

#### You can use it:

* To quickly build an **HTTP server**:

~~~cpp
#include <stdio.h>
#include "workflow/WFHttpServer.h"

int main()
{
    WFHttpServer server([](WFHttpTask *task) {
        task->get_resp()->append_output_body("<html>Hello World!</html>");
    });

    if (server.start(8888) == 0) { // start server on port 8888
        getchar(); // press "Enter" to end.
        server.stop();
    }

    return 0;
}
~~~

* As a **powerful asynchronous client**, it currently supports `HTTP`, `Redis`, `MySQL` and `Kafka` protocols.
* To implement **client/server on user-defined protocol** and build your own **RPC system**.
  * [srpc](https://github.com/sogou/srpc) is based on it and it is an independent open source project, which supports srpc, brpc and thrift protocol.
* To build **asynchronous task flow**; support common **series** and **parallel** structures, and also support more complex **DAG** structures.
* As a **parallel programming tool**. In addition to **network tasks**, Sogou C++ Workflow also includes **the scheduling of computing tasks**. All types of tasks can be put into **the same** task flow.
* As a **asynchronous file IO tool** in `Linux` system, with high performance exceeding any system call. Disk IO is also a task.
* To realize any **high-performance** and **high-concurrency** back-end service with a very complex relationship between computing and communication.
* To build a **service mesh** system.
  * This project has built-in **service governance** and **load balancing** features.

#### Compiling and running environment

* This project supports `Linux`, `macOS`, `Windows` and other operating systems.
  * `Windows` version is temporarily released as an independent branch, using `iocp` to implement asynchronous networking. All user interfaces are consistent with the `Linux` version.
* Supports all CPU platforms, including 32 or 64-bit `x86` processors, big-endian or little-endian `arm` processors.
* Relies on `OpenSSL`; `OpenSSL 1.1` and above is recommended.
* Uses the `C++11` standard and therefore, it should be compiled with a compiler which supports `C++11`. Does not rely on `boost` or `asio`.
* No other dependencies. However, if you need `Kafka` protocol, some compression libraries should be installed, including `lz4`, `zstd` and `snappy`.

# Try it!

* Client
  * [Creating your first task：wget](docs/en/tutorial-01-wget.md)
  * [Implementing Redis set and get：redis\_cli](docs/en/tutorial-02-redis_cli.md)
  * [More features about series：wget\_to\_redis](docs/en/tutorial-03-wget_to_redis.md)
* Server
  * [First server：http\_echo\_server](docs/en/tutorial-04-http_echo_server.md)
  * [Asynchronous server：http\_proxy](docs/en/tutorial-05-http_proxy.md)
* Parallel tasks and Series　
  * [A simple parallel wget：parallel\_wget](docs/en/tutorial-06-parallel_wget.md)
* Important topics
  * [About error](docs/en/about-error.md)
  * [About timeout](docs/en/about-timeout.md)
  * [About global configuration](docs/en/about-config.md)
  * [About DNS](docs/en/about-dns.md)
  * [About exit](docs/en/about-exit.md)
* Computing tasks
  * [Using the build-in algorithm factory：sort\_task](docs/en/tutorial-07-sort_task.md)
  * [User-defined computing task：matrix\_multiply](docs/en/tutorial-08-matrix_multiply.md)
* Asynchronous File IO tasks
  * [Http server with file IO：http\_file\_server](docs/en/tutorial-09-http_file_server.md)
* User-defined protocol
  * [A simple user-defined portocol: client/server](docs/en/tutorial-10-user_defined_protocol.md)
* Timing tasks and counting tasks
  * [About timer](docs/en/about-timer.md)
  * [About counter](docs/en/about-counter.md)
* Service governance
  * [About service governance](docs/en/about-service-management.md)
  * [More documents about upstream](docs/en/about-upstream.md)
* Connection context
  * [About connection context](docs/en/about-connection-context.md)
* Built-in protocols
  * [Asynchronous MySQL client：mysql\_cli](docs/en/tutorial-12-mysql_cli.md)

#### System design features

We believe that a typical back-end program consists of the following three parts and should be developed completely independently.

* Protocol
  * In most cases, users use built-in common network protocols, such as HTTP, Redis or various rpc.
  * Users can also easily customize user-defined network protocol. In the customization, they only need to provide serialization and deserialization functions to define their own client/server.
* Algorithm
  * In our design, the algorithm is a concept symmetrical to the protocol.
    * If protocol call is rpc, then algorithm call is an apc (Async Procedure Call).
  * We have provided some general algorithms, such as sort, merge, psort, reduce, which can be used directly.
  * Compared with a user-defined protocol, a user-defined algorithm is much more common. Any complex calculation with clear boundaries should be packaged into an algorithm.
* Task flow
  * Task flow is the actual bussiness logic, which is to put the protocols and algorithms into the flow graph for use.
  * The typical task flow is a closed series-parallel graph. Complex business logic may be a non-closed DAG.
  * The task flow graph can be constructed directly or dynamically generated based on the results of each step. All tasks are executed asynchronously.

Basic task, task factory and complex task

* Our system contains six basic tasks: communication, file IO, CPU, GPU, timer, and counter.
* All tasks are generated by the task factory and automatically recycled after callback.
  * Server task is one kind of special communication task, generated by the framework which calls the task factory, and handed over to the user through the process function.
  * In most cases, the task generated by the user through the task factory is a complex task, which is transparent to the user.
  * For example, an HTTP request may include many asynchronous processes (DNS, redirection), but for user, it is just a communication task.
  * File sorting seems to be an algorithm, but it actually includes many complex interaction processes between file IO and CPU calculation.
  * If you think of business logic as building circuits with well-designed electronic components, then each electronic component may be a complex circuit.

Asynchrony and encapsulation based on `C++11 std::function`

* Not based on user mode coroutines. Users need to know that they are writing asynchronous programs.
* All calls are executed asynchronously, and there are almost no operations to wait for threads.
  * Although we also provide some convenient semi-synchronous interfaces, they are not core features.
* Please avoid derivation. Try to encapsulate user behavior with `std::function` instead, including:
  * The callback of any task.
  * Any server process. This conforms to the `FaaS` (Function as a Service) idea.
  * The realization of an algorithm is simply a `std::function`. But the algorithm can also be implemented by derivation.

Memory reclamation mechanism

* Every task will be automatically reclaimed after the callback. If a task is created but a user does not want to run it, the user needs to release it through the dismiss method.
* Any data in the task, such as the response of the network request, will also be recycled with the task. At this time, the user can use `std::move()` to move the required data.
* SeriesWork and ParallelWork are two kinds of framework objects, which are also recycled after their callback.
* This project doesn’t use `std::shared_ptr` to manage memory.

#### More design documents

To be continued...

## Authors

* **Xie Han** - *[xiehan@sogou-inc.com](mailto:xiehan@sogou-inc.com)*
* **Wu Jiaxu** - *[wujiaxu@sogou-inc.com](mailto:wujiaxu@sogou-inc.com)*
* **Li Yingxin** - *[liyingxin@sogou-inc.com](mailto:liyingxin@sogou-inc.com)*
