# 性能测试

Sogou C++ Workflow是一款性能优异的网络框架，本文介绍我们进行的性能测试，
包括方案、代码、结果，以及与其他同类产品的对比。

更多场景下的实验正在进行中，本文将持续更新。

## HTTP Server

HTTP Client/Server是Sogou C++ Workflow常见的应用场景，
我们首先对Server端进行实验。

### 环境

我们部署了两台相同机器作为Server和Client，软硬件配置如下：

| 软硬件 | 配置 |
|:---:|:---|
| CPU | 40 Cores, x86_64, Intel(R) Xeon(R) CPU E5-2630 v4 @ 2.20GHz |
| Memory | 192GB |
| NIC | 25000Mbps |
| OS | CentOS 7.8.2003 |
| Kernel | Linux version 3.10.0-1127.el7.x86_64 |
| GCC | 4.8.5 |

两者间`ping`测得的RTT为0.1ms左右。

### 对照组

我们选择nginx和brpc作为对照组。
选择前者是因为它在生产中部署十分广泛，性能不俗；
对于后者，我们在本次实验中只关注HTTP Server方面的能力，
其他的特性已有[单独的实验][Sogou RPC Benchmark]进行更为详尽的测试。

事实上，我们也对此二者之外的其他某些框架同时进行了实验，
但结果其性能表现相差较远，因此未在本文中体现。

后续我们将选取更多合适的框架加入对比测试中。

### Client工具

本次实验我们使用的压测工具为[wrk][wrk]和[wrk2][wrk2]。
前者适合测试特定并发下的QPS极限和延时，
后者适合在特定QPS下测试延时分布。

我们也尝试过使用其他测试工具，例如[ab][ab]等，但无法打出足够的压力。
有鉴于此，我们也在着手开发基于Sogou C++ Workflow的benchmark工具。

### 变量和指标

一般而言，对网络框架的性能测试，切入的角度可谓纷繁多样。
通过控制不同的变量、观测不同的指标，可以探究程序在不同场景下的适应能力。

本次实验，我们选择其中最普遍常见的变量和指标：
通过控制Client并发度和承载数据的大小，来测试QPS和延时的变化情况。
另外，我们还测试了在掺杂慢请求的正常请求的延时分布。

下面依次介绍两个测试场景。

### 测试方法

#### 启动http server
1. 编译benchmark
2. 进入到benchmark目录，执行 

```
./http_server 12 9000 11
```

说明: 启动参数分别为线程数、端口和响应的随机字符串长度。

### wrk测试

```
wrk --latency -d10 -c200 --timeout 8 -t 6 http://127.0.0.1:9000
```
**命令行解释**

-c200: 启动200个连接

-t6: 开启6个线程做压力测试

-d10: 压测持续10s

--timeout 8: 连接超时时间8s

### 不同并发度和数据长度下的QPS和延时

#### 代码和配置

我们搭建了一个极其简约的HTTP服务器，
忽略掉所有的业务逻辑，
将测试点聚焦在纯粹的网络框架性能上。

代码片段如下，
完整代码移步[这里][benchmark-01 Code]。

```cpp
// ...

auto * resp = task->get_resp();
resp->add_header_pair("Date", timestamp);
resp->add_header_pair("Content-Type", "text/plain; charset=UTF-8");
resp->append_output_body_nocopy(content.data(), content.size());

// ...
```

可以从上述代码中看到，
对于到来的任何HTTP请求，
我们都会返回一段固定的内容作为Body，
并设置必要的Header，
包括代码中指明的`content-type`、`date`，
以及自动填充的`connection`和`content-length`。

HTTP Body的固定内容是在Server启动时随机生成的ASCII字符串，
其长度可以通过启动参数配置。
同时可以配置的还有使用的poller线程数和监听的端口号。
前者我们在本次测试中固定为16，
因此Sogou C++ Workflow将使用16个poller线程和20个handler线程（默认配置）。

对于nginx和brpc，
我们也构建了相同的返回内容，
并为nginx配置了40个进程、
brpc配置了40个线程。


#### 变量

我们控制并发度在`[1, 2K]`之间翻倍增长，
数据长度在`[16B, 64KB]`之间翻倍增长，
两者正交。

#### 指标

鉴于并发度和数据长度组合之后数量较多，
我们选择其中部分数据绘制为曲线。

##### 固定数据长度下QPS与并发度关系

![Concurrency and QPS][Con-QPS]

上图可以看出，当数据长度保持不变，
QPS随着并发度提高而增大，后趋于平稳。
此过程中Sogou C++ Workflow一直有明显优势，
高于brpc和nginx。
特别是数据长度为64和512的两条曲线，
并发度足够的时候，可以保持500K的QPS。

注意上图中nginx-64与nginx-512的曲线重叠度很高，
不易辨识。

##### 固定并发度下QPS与数据长度关系

![Body Length and QPS][Len-QPS]

上图可以看出，当并发度保持不变，
随着数据长度的增长，
QPS保持平稳至4K时下降。
此过程中，Sogou C++ Workflow也一直保持优势。

##### 固定数据长度下延时与并发度关系

![Concurrency and Latency][Con-Lat]

上图可以看出，保持数据长度不变，
延时随并发度提高而有所上升。
此过程中，Sogou C++ Workflow略好于brpc，
大好于nginx。

##### 固定并发度下延时与数据长度关系

![Body Length and Latency][Len-Lat]

上图可以看出，并发度保持不变时，
增大数据长度，造成延时上升。
此过程中，Sogou C++ Workflow好于nginx，
好于brpc。

### 掺杂慢请求的延时分布

#### 代码

我们在上一个测试的基础上，简单添加了一个慢请求的逻辑，
模拟业务场景中可能出现的特殊情况。

代码片段如下，
完整代码请移步[这里][benchmark-02 Code]。

```cpp
// ...

if (std::strcmp(uri, "/long_req/") == 0)
{
    auto timer_task = WFTaskFactory::create_timer_task(microseconds, nullptr);
    series_of(task)->push_back(timer_task);
}
// ...
```

我们在Server的process里进行判断，
如果访问的是特定的路径，
则添加一个`WFTimerTask`到Series的末尾，
能够模拟一个异步耗时处理过程。
类似地，对brpc使用`bthread_usleep()`函数进行异步睡眠。

#### 配置

在本次实验中，我们固定并发度为1024，数据长度为1024字节，
分别以QPS为20K、100K和200K进行正常请求测试，
测绘延时；
与此同时，有另一路压力，进行慢请求，
QPS是上述QPS的1%，
数据不计入统计。
慢请求的时长固定为5ms。

#### 延时CDF图

![Latency CDF][Lat CDF]

从上图可以看出，当QPS为20K时，
Sogou C++ Workflow略次于brpc；
当QPS为100K时，两者几乎相当；
当QPS为200K时，Sogou C++ Workflow略好于brpc。
总之，可以认为两者在这方面旗鼓相当。


[Sogou RPC Benchmark]: https://github.com/holmes1412/sogou-rpc-benchmark
[wrk]: https://github.com/wg/wrk
[wrk2]: https://github.com/giltene/wrk2
[ab]: https://httpd.apache.org/docs/2.4/programs/ab.html
[benchmark-01 Code]: benchmark-01-http_server.cc
[benchmark-02 Code]: benchmark-02-http_server_long_req.cc
[Con-QPS]: https://raw.githubusercontent.com/wiki/sogou/workflow/img/benchmark-01.png
[Len-QPS]: https://raw.githubusercontent.com/wiki/sogou/workflow/img/benchmark-02.png
[Con-Lat]: https://raw.githubusercontent.com/wiki/sogou/workflow/img/benchmark-03.png
[Len-Lat]: https://raw.githubusercontent.com/wiki/sogou/workflow/img/benchmark-04.png
[Lat CDF]: https://raw.githubusercontent.com/wiki/sogou/workflow/img/benchmark-05.png
