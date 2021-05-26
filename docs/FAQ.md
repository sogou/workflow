### 项目背景以及解决的问题
C++ Workflow项目起源于搜狗公司的分布式存储项目的通讯引擎，并且发展成为搜狗公司级C++标准，应用于搜狗大多数C++后端服务。项目将通讯与计算和谐统一，帮助用户建立通讯与计算关系非常复杂的高性能服务。但同时用户也可以只把它当成简易的异步网络引擎或并行计算框架来使用。
### 如何开始使用
以Linux系统为例：
~~~sh
$ git clone https://github.com/sogou/workflow
$ cd workflow
$ make
$ cd tutorial
$ make
~~~
然后就可以愉快的运行示例了。每个示例都有对应的文档讲解。如果需要用到kafka协议，请预先安装snappy和lz4，并且：
~~~sh
$ make KAFKA=y
$ cd tutorial
$ make KAFKA=y
~~~
另外，make DEBUG=y，可以编译调试版。
### 与其它的网络引擎，RPC项目相比，有什么优势
* 简单易上手，无依赖
* 性能和稳定性优异[benchmark](https://github.com/sogou/workflow/tree/master/benchmark)
* 丰富的通用协议实现
* 通讯与计算统一
* 任务流管理
### 与其它并行计算框架相比，有什么优势
* 使用简单
* 有网络
### 项目目前不支持的特征
* pipeline服务器
* streaming通讯（底层模块支持，需要设计上层接口）
* udp服务器（支持udp客户端）
* websocket
### 项目原生包含哪些网络协议
目前我们实现了HTTP，Redis，MySQL和kafka协议。除kafka目前只支持客户端以外，其他协议都是client+server。也就是说，用户可以用于构建Redis或MySQL协议的代理服务器。kafka模块是插件，默认不编译。
### 为什么用callback
我们用C++11 std::function类型的callback和process来包装用户行为，因此用户需要知道自己是在编写异步程序。我们认为callback方式比future或用户态协程能给程序带来更高的效率，并且能很好的实现通信与计算的统一。由于我们的任务封装方式以及std::function带来的便利，在我们的框架里使用callback并没有太多心智负担，反而非常简单明了。
### callback在什么线程里调用
项目的一个特点是由框架来管理线程，除了一些很特殊情况，callback的调用线程必然是处理网络收发和文件IO结果的handler线程（默认数量20）或者计算线程（默认数量等于CPU总核数）。但无论在哪个线程里执行，都不建议在callback里等待或执行特别复杂的计算。需要等待可以用counter任务进行不占线程的wait，复杂计算则应该包装成计算任务。
需要说明的是，框架里的一切资源都是使用时分配。如果用户没有用到网络通信，那么所有和通信相关的线程都不会被创建。
### 为什么我的任务启动之后没有反应
~~~cpp
int main(void)
{
    ...
    task->start();
    return 0;
}
~~~
这是很多新用户都会遇到的问题。框架中几乎所有调用都是非阻塞的，上面的代码在task启动之后main函数立刻return，并不会等待task的执行结束。正确的做法应该是通过某种方式在唤醒主进程，例如：
~~~cpp
WFFaciliies::WaitGroup wait_group(1);

void callback(WFHttpTask *task)
{
    ....
    wait_group.done();
}

int main(void)
{
    WFHttpTask *task = WFTaskFactory::create_http_task(url, 0, 0, callback);
    task->start();
    wait_group.wait();
    return 0;
}
~~~
### 任务对象的生命周期是什么 
框架中任何任务（以及SeriesWork），都是以裸指针形式交给用户。所有任务对象的生命周期，是从对象被创建，到对象的callback完成。也就是说callback之后task指针也就失效了，同时被销毁的也包括task里的数据。如果你需要保留数据，可以用std::move()把数据移走，例如我们需要保留http任务中的resp：
~~~cpp
void http_callback(WFHttpTask *task)
{
    protocol::HttpResponse *resp = task->get_resp();
    protocol::HttpResponse *my_resp = new protocol::HttpResponse(std::move(*resp));
    /* or
    protocol::HttpResponse *my_resp = new protocol::HttpResponse;
    *my_resp = std::move(*resp);
    */
}
~~~
某些情况下，如果用户创建完任务又不想启动了，那么需要调用task->dismiss()直接销毁任务。
需要特别强调，server的process函数不是callback，server任务的callback发生在回复完成之后，而且默认为nullptr。
### 为什么SeriesWork（串行）不是一种任务
我们关于串并联的定义是：
* 串行由任务组成
* 并行由串行组成
* 并行是一种任务

显然通过这三句话的定义我们可以递归出任意复杂的串并联结构。如果把串行也定义为一种任务，串行就可以由多个子串行组成，那么使用起来就很容易陷入混乱。同样并行只能是若干串行的并，也是为了避免混乱。其实使用中你会发现，串行本质上就是我们的协程。
### 我需要更一般的有向无环图怎么办
可以使用WFGraphTask，或自己用WFCounterTask来构造。
### server是在process函数结束后回复请求吗
不是。server是在server task所在series没有别的任务之后回复请求。如果你不向这个series里添加任何任务，就相当于process结束之后回复。注意不要在process里等待任务的完成，而应该把这个任务添加到series里。
### 如何让server在收到请求后等一小段时间再回复
错误的方法是在process里直接sleep。正确做法，向server所在的series里添加一个timer任务。以http server为例:
~~~cpp
void process(WFHttpTask *server_task)
{
    WFTimerTask *timer = WFTaskFactory::create_timer_task(100000, nullptr);
    server_task->get_resp()->append_output_body("hello");
    series_of(server_task)->push_back(timer);
}
~~~
以上代码实现一个100毫秒延迟的http server。一切都是异步执行，等待过程没有线程被占用。
### 怎么知道回复成功没有
首先回复成功的定义是成功把数据写入tcp缓冲，所以如果回复包很小而且client端没有因为超时等原因关闭了连接，几乎可以认为一定回复成功。需要查看回复结果，只需给server task设置一个callback，callback里状态码和错误码的定义与client task是一样的，但server task不会出现dns错误。
### 能不能不回复
可以。任何时候调用server task的noreply()方法，那么在原本回复的时机，连接直接关闭。
### 计算任务的调度规则是什么
我们发现包括WFGoTask在内的所有计算任务，在创建时都需要指定一个计算队列名，这个计算队列名可用于指导我们内部的调度策略。首先，只要有空闲计算线程可用，任务将实时调起，计算队列名不起作用。当计算线程无法实时调起每个任务的时候，那么同一队列名下的任务将按FIFO的顺序被调起，而队列与队列之间则是平等对待。例如，先连续启动n个队列名为A的任务，再连续启动n个队列名为B的任务。那么无论每个任务的cpu耗时分别是多少，也无论计算线程数多少，这两个队列将近倾向于同时执行完毕。这个规律可以扩展到任意队列数量以及任意启动顺序。
### 为什么使用redis client时无需先建立连接
首先看一下redis client任务的创建接口：
~~~cpp
class WFTaskFactory
{
public:
    WFRedisTask *create_redis_task(const std::string& url, int retry_max, redis_callback_t callback);
}
~~~
其中url的格式为：redis://:password@host:port/dbnum。port默认值为6379，dbnum默认值为0。
workflow的一个重要特点是由框架来管理连接，使用户接口可以极致的精简，并实现最有效的连接复用。框架根据任务的用户名密码以及dbnum，来查找一个可以复用的连接。如果找不到则发起新连接并进行用户登陆，数据库选择等操作。如果是一个新的host，还要进行DNS解析。请求出错还可能retry。这每一个步骤都是异步并且透明的，用户只需要填写自己的request，将任务启动，就可以在callback里得到请求的结果。唯一需要注意的是，每次任务的创建都需要带着password，因为可能随时有登陆的需要。
同样的方法我们可以用来创建mysql任务。但对于有事务需求的mysql，则需要通过我们的WFMySQLConnection来创建任务了，否则无法保证整个事务都在同一个连接上进行。WFMySQLConnection依然能做到连接和认证过程的异步性。
### 连接的复用规则是什么
大多数情况下，用户使用框架产生的client任务都是无法指定具体连接。框架会有连接的复用策略：
* 如果同一地址端口有满足条件的空闲连接，从中选择最近一个被释放的那个。即空闲连接的复用是先进后出的。
* 当前地址端口没有满足条件的空闲连接时：
  * 如果当前并发连接数小于最大值（默认200），立刻发起新连接。
  * 并发连接数已经达到最大值，任务将得到系统错误EAGAIN。
* 并不是所有相同目标地址和端口上的连接都满足复用条件。例如不同用户名或密码下的数据库连接，就不能复用。

虽然我们的框架无法指定任务要使用的连接，但是我们支持连接上下文的功能。这个功能对于实现有连接状态的server非常重要。相关的内容可以参考[关于连接上下文](https://github.com/sogou/workflow/blob/master/docs/about-connection-context.md)相关文档。
 ### 同一域名下如果有多个IP地址，是否有负载均衡
是的，我们会认为同一域名下的所有目标IP对等，服务能力也相同。因此任何一个请求都会寻找一个从本地看起来负载最轻的目标进行通信，同时也内置了熔断与恢复策略。同一域名下的负载均衡，目标都必须服务在同一端口，而且无法配置不同权重。负载均衡的优先级高于连接复用，也就是说会先选择好通信地址再考虑复用连接问题。
### 如何实现带权重或不同端口上的负载均衡
可以参考upstream相关文档。upstream还可以实现很多更复杂的服务管理需求。
### chunked编码的http body如何最高效访问
很多情况下我们使用HttpMessage::get_parsed_body()来获得http消息体。但从效率角度上考虑，我们并不自动为用户解码chunked编码，而是返回原始body。解码chunked编码可以用HttpChunkCursor，例如：
~~~cpp
#include "workflow/HttpUtil.h"

void http_callback(WFHttpTask *task)
{
    protocol::HttpResponse *resp = task->get_resp();
    protocol::HttpChunkCursor cursor(resp);
    const void *chunk;
    size_t size;

    while (cursor.next(&chunk, &size))
    {
        ...
    }
}
~~~
cursor.next操作每次返回一个chunk的起始位置指针和chunk大小，不进行内存拷贝。使用HttpChunkCursor之前无需判断消息是不是chunk编码，因为非chunk编码也可以认为整体就是一个chunk。
### 能不能在callback或process里同步等待一个任务完成
我们不推荐这个做法，因为任何任务都可以串进任务流，无需占用线程等待。如果一定要这样做，可以用我们提供的WFFuture来实现。请不要直接使用std::future，因为我们所有通信的callback和process都在一组线程里完成，使用std::future可能会导致所有线程都陷入等待，引发整体死锁。WFFuture通过动态增加线程的方式来解决这个问题。使用WFFuture还需要注意在任务的callback里把要保留的数据（一般是resp）通过std::move移动到结果里，否则callback之后数据会随着任务一起被销毁。
### 数据如何在task之间传递
最常见的，同一个series里的任务共享series上下文，通过series的get_context()和set_context()的方法来读取和修改。而parallel在它的callback里，也可以通过series_at()获到它所包含的各个series（这些series的callback已经被调用，但会在parallel callback之后才被销毁），从而获取它们的上下文。由于parallel也是一种任务，所以它可以把汇总的结果通过它所在的series context继续传递。
总之，series是协程，series context就是协程的局部变量。parallel是协程的并行，可汇总所有协程的运行结果。
### Workflow和rpc的关系
在我们的架构里，rpc是workflow上的应用，或者说rpc是workflow上的一组协议实现。如果你有接口描述，远程接口调用的需求，一定要试用一下srpc，这是一个把workflow的功能发挥到极致又和workflow完美融合的rpc系统，同时兼容brpc和thrift协议且更快更易用，满足你的任何rpc需求。地址：[https://github.com/sogou/srpc](https://github.com/sogou/srpc)
### Server的stop()操作完成时机
Server的stop()操作是优雅关闭，程序结束之前必须关闭所有server。stop()由shutdown()和wait_finish()组成，wait_finish会等待所有运行中server task所在series结束。也就是说，你可以在server task回复完成的callback里，继续向series追加任务。stop()操作会等待这些任务的结束。另外，如果你同时开多个server，最好的关闭方法是：
~~~cpp
int main()
{
    // 一个server对象不能start多次，所以多端口服务需要定义多个server对象
    WFRedisServer server1(process);
    WFRedisServer server2(process);
    server1.start(8080);
    server2.start(8888);
    getchar(); // 输入回车结束
    // 先全部关闭，再等待。
    server1.shutdown();
    server2.shutdown();
    server1.wait_finish();
    server2.wait_finish();
    return 0;
}
~~~
### 如何在收到某个特定请求时，结束server
因为server的结束由shutdown()和wait_finish()组成，显然就可以在process里shutdown，在main()里wait_finish，例如：
~~~cpp
#include <string.h>
#include <atomic>
#include “workflow/WFHttpServer.h”

extern void process(WFHttpTask *task);
WFHttpServer server(process);

void process(WFHttpTask *task) {
    if (strcmp(task->get_req()->get_request_uri(), “/stop”) == 0) {
        static std::atomic<int> flag;
        if (flag++ == 0)
            server.shutdown();
        task->get_resp()->append_output_body(“<html>server stop</html>”);
        return;
    }

    /* Server’s logic */
    //  ....
}

int main() {
    if (server.start(8888) == 0)
        server.wait_finish();

    return 0;
}
~~~
以上代码实现一个http server，在收到/stop的请求时结束程序。process中的flag是必须的，因为process并发执行，只能有一个线程来调用shutdown操作。
### Server里需要调用非Workflow框架的异步操作怎么办
还是使用counter。在其它异步框架的回调里，对counter进行count操作。
~~~cpp
void other_callback(server_task, counter, ...)
{
    server_task->get_resp()->append_output_body(result);
    counter->count();
}

void process(WFHttpTask *server_task)
{
    WFCounterTask *counter = WFTaskFactory::create_counter_task(1, nullptr);
    OtherAsyncTask *other_task = create_other_task(other_callback, server_task, counter);//非workflow框架的任务
    other_task->run();
    series_of(server_task)->push_back(counter);
}
~~~
注意以上代码里，counter->count()的调用可能先于counter的启动。但无论什么时序，程序都是完全正确的。
### 个别https站点抓取失败是什么原因
如果浏览器可以访问，但用workflow抓取失败，很大概率是因为站点使用了TLS扩展功能的SNI。可以通过全局配置打开workflow的客户端SNI功能：
~~~cpp
    struct WFGlobalSettings settings = GLOBAL_SETTINGS_DEFAULT;
    settings.endpoint_params.use_tls_sni = true;
    WORKFLOW_library_init(&settings);
~~~
开启这个功能是有一定代价的，所有https站点都会启动SNI，相同IP地址但不同域名的访问，将无法复用SSL连接。
因此用户也可以通过upstream功能，只打开对某个确定域名的SNI功能：
~~~cpp
#Include <workflow/UpstreamManager.h>

int main()
{
    UpstreamManager::upstream_create_weighted_random("www.sogou.com", false);
    struct AddressParams params = ADDRESS_PARAMS_DEFAULT;
    params.endpoint_params.use_tls_sni = true;
    UpstreamManager::upstream_add_server("www.sogou.com", "www.sogou.com", &params);
    ...
}
~~~
上面的代码把www.sogou.com设置为upstream名，并且加入一个同名的server，同时打开SNI功能。

### 怎么通过代理服务器访问http资源
方法一（只适用于http任务且无法重定向）：
可以通过代理服务器的地址创建http任务，并重新设置request_uri和Host头。假设我们想通过代理服务器www.proxy.com:8080访问http://www.sogou.com/ ，方法如下：
~~~cpp
task = WFTaskFactory::create_http_task("http://www.proxy.com:8080", 0, 0, callback);
task->set_request_uri("http://www.sogou.com/");
task->set_header_pair("Host", "www.sogou.com");
~~~
方法二（通用）：
通过带proxy_url的接口创建http任务：
~~~cpp
class WFTaskFactory
{
public:
    static WFHttpTask *create_http_task(const std::string& url,
                                        const std::string& proxy_url,
                                        int redirect_max, int retry_max,
                                        http_callback_t callback);
};
~~~
其中proxy_url的格式为：http://user:passwd@your.proxy.com:port/
proxy只能是"http://"开头，而不能是"https://"。port默认值为80。
这个方法适用于http和https URL的代理，可以重定向，重定向时继续使用该代理服务器。
