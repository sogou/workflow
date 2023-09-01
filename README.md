[简体中文版（推荐）](README_cn.md)

## Sogou C++ Workflow

[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://github.com/sogou/workflow/blob/master/LICENSE)
[![Language](https://img.shields.io/badge/language-c++-red.svg)](https://en.cppreference.com/) 
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://img.shields.io/badge/platform-linux%20%7C%20macos20%7C%20windows-lightgrey.svg)
[![Build Status](https://img.shields.io/github/actions/workflow/status/sogou/workflow/ci.yml?branch=master)](https://github.com/sogou/workflow/actions?query=workflow%3A%22ci+build%22++)

As **Sogou\`s C++ server engine**, Sogou C++ Workflow supports almost all **back-end C++ online services** of Sogou, including all search services, cloud input method, online advertisements, etc., handling more than **10 billion** requests every day. This is an **enterprise-level programming engine** in light and elegant design which can satisfy most C++ back-end development requirements.

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

* As a **multifunctional asynchronous client**, it currently supports `HTTP`, `Redis`, `MySQL` and `Kafka` protocols.
* To implement **client/server on user-defined protocol** and build your own **RPC system**.
  * [srpc](https://github.com/sogou/srpc) is based on it and it is an independent open source project, which supports srpc, brpc, trpc and thrift protocols.
* To build **asynchronous workflow**; support common **series** and **parallel** structures, and also support any **DAG** structures.
* As a **parallel computing tool**. In addition to **networking tasks**, Sogou C++ Workflow also includes **the scheduling of computing tasks**. All types of tasks can be put into **the same** flow.
* As an **asynchronous file IO tool** in `Linux` system, with high performance exceeding any system call. Disk file IO is also a task.
* To realize any **high-performance** and **high-concurrency** back-end service with a very complex relationship between computing and networking.
* To build a **micro service** system.
  * This project has built-in **service governance** and **load balancing** features.
* Wiki link : [PaaS Architecture](https://github.com/sogou/workflow/wiki)

#### Compiling and running environment

* This project supports `Linux`, `macOS`, `Windows`, `Android` and other operating systems.
  * `Windows` version is currently released as an independent [branch](https://github.com/sogou/workflow/tree/windows), using `iocp` to implement asynchronous networking. All user interfaces are consistent with the `Linux` version.
* Supports all CPU platforms, including 32 or 64-bit `x86` processors, big-endian or little-endian `arm` processors, `loongson` processors.
* Master branch requires SSL and `OpenSSL 1.1` or above is recommended. Fully compatible with BoringSSL. If you don't like SSL, you may checkout the [nossl](https://github.com/sogou/workflow/tree/nossl) branch.
* Uses the `C++11` standard and therefore, it should be compiled with a compiler which supports `C++11`. Does not rely on `boost` or `asio`.
* No other dependencies. However, if you need `Kafka` protocol, some compression libraries should be installed, including `lz4`, `zstd` and `snappy`.

### Get started (Linux, macOS):
~~~sh
git clone https://github.com/sogou/workflow
cd workflow
make
cd tutorial
make
~~~~

#### With SRPC Tool (NEW!)：
https://github.com/sogou/srpc/blob/master/tools/README.md

#### With [apt-get](https://launchpad.net/ubuntu/+source/workflow) on Debian Linux, ubuntu:
Sogou C++ Workflow has been packaged for Debian Linux and ubuntu 22.04.  
To install the Workflow library for development purposes:
~~~~sh
sudo apt-get install libworkflow-dev
~~~~

To install the Workflow library for deployment:
~~~~sh
sudo apt-get install libworkflow1
~~~~

#### With [dnf](https://packages.fedoraproject.org/pkgs/workflow) on Fedora Linux:
Sogou C++ Workflow has been packaged for Fedora Linux.  
To install the Workflow library for development purposes:
~~~~sh
sudo dnf install workflow-devel
~~~~

To install the Workflow library for deployment:
~~~~sh
sudo dnf install workflow
~~~~

#### With xmake

If you want to use xmake to build workflow, you can see [xmake build document](docs/en/xmake.md)

# Tutorials

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
  * [Use computing task in a simple way: go task](docs/en/about-go-task.md)
* Asynchronous File IO tasks
  * [Http server with file IO：http\_file\_server](docs/en/tutorial-09-http_file_server.md)
* User-defined protocol
  * [A simple user-defined protocol: client/server](docs/en/tutorial-10-user_defined_protocol.md)
  * [Use TLV message](docs/en/about-tlv-message.md)
* Other important tasks/components
  * [About timer](docs/en/about-timer.md)
  * [About counter](docs/en/about-counter.md)
  * [About resource pool](docs/en/about-resource-pool.md)
  * [About module](docs/en/about-module.md)
  * [About DAG](docs/en/tutorial-11-graph_task.md)
* Service governance
  * [About service governance](docs/en/about-service-governance.md)
  * [More documents about upstream](docs/en/about-upstream.md)
* Connection context
  * [About connection context](docs/en/about-connection-context.md)
* Built-in clients
  * [Asynchronous MySQL client：mysql\_cli](docs/en/tutorial-12-mysql_cli.md)
  * [Asynchronous Kafka client: kafka\_cli](docs/en/tutorial-13-kafka_cli.md)

#### Programming paradigm

We believe that a typical back-end program=protocol+algorithm+workflow and should be developed completely independently.

* Protocol
  * In most cases, users use built-in common network protocols, such as HTTP, Redis or various rpc.
  * Users can also easily customize user-defined network protocol. In the customization, they only need to provide serialization and deserialization functions to define their own client/server.
* Algorithm
  * In our design, the algorithm is a concept symmetrical to the protocol.
    * If protocol call is rpc, then algorithm call is an apc (Async Procedure Call).
  * We have provided some general algorithms, such as sort, merge, psort, reduce, which can be used directly.
  * Compared with a user-defined protocol, a user-defined algorithm is much more common. Any complicated computation with clear boundaries should be packaged into an algorithm.
* Workflow
  * Workflow is the actual business logic, which is to put the protocols and algorithms into the flow graph for use.
  * The typical workflow is a closed series-parallel graph. Complex business logic may be a non-closed DAG.
  * The workflow graph can be constructed directly or dynamically generated based on the results of each step. All tasks are executed asynchronously.

Basic task, task factory and complex task

* Our system contains six basic tasks: networking, file IO, CPU, GPU, timer, and counter.
* All tasks are generated by the task factory and automatically recycled after callback.
  * Server task is one kind of special networking task, generated by the framework which calls the task factory, and handed over to the user through the process function.
* In most cases, the task generated by the user through the task factory is a complex task, which is transparent to the user.
  * For example, an HTTP request may include many asynchronous processes (DNS, redirection), but for user, it is just a networking task.
  * File sorting seems to be an algorithm, but it actually includes many complex interaction processes between file IO and CPU computation.
  * If you think of business logic as building circuits with well-designed electronic components, then each electronic component may be a complex circuit.

Asynchrony and encapsulation based on `C++11 std::function`

* Not based on user mode coroutines. Users need to know that they are writing asynchronous programs.
* All calls are executed asynchronously, and there is almost no operation that occupies a thread.
  * Although we also provide some facilities with semi-synchronous interfaces, they are not core features.
* We try to avoid user's derivations, and encapsulate user behavior with `std::function` instead, including:
  * The callback of any task.
  * Any server's process. This conforms to the `FaaS` (Function as a Service) idea.
  * The realization of an algorithm is simply a `std::function`. But the algorithm can also be implemented by derivation.

Memory reclamation mechanism

* Every task will be automatically reclaimed after the callback. If a task is created but a user does not want to run it, the user needs to release it through the dismiss method.
* Any data in the task, such as the response of the network request, will also be recycled with the task. At this time, the user can use `std::move()` to move the required data.
* SeriesWork and ParallelWork are two kinds of framework objects, which are also recycled after their callback.
  * When a series is a branch of a parallel, it will be recycled after the callback of the parallel that it belongs to.
* This project doesn’t use `std::shared_ptr` to manage memory.

#### Any other questions?

You may check the [FAQ](https://github.com/sogou/workflow/issues/406) and [issues](https://github.com/sogou/workflow/issues) list first to see if you can find the answer.

You are very welcome to send the problems you encounter in use to [issues](https://github.com/sogou/workflow/issues), and we will answer them as soon as possible. At the same time, more issues will also help new users.

