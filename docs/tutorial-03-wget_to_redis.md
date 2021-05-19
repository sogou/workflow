# 任务序列的更多功能：wget_to_redis
# 示例代码

[tutorial-03-wget_to_redis.cc](/tutorial/tutorial-03-wget_to_redis.cc)

# 关于wget_to_redis

程序从命令行读入一条http URL和一条redis URL，把抓取下来的Http页面（以http URL为key）存入redis。  
与之前两个示例不同，我们加入唤醒机制，让程序可以自动退出，无需Ctrl-C。

# 创建Http任务并设置参数

和上一个示例类似，本示例也是串行执行两个请求。最大的区别是，我们要通知主线程任务已经执行结束，并正常退出。  
另外，我们多加入两个调用，限制一下http抓取返回内容的大小，以及接收回复的最大时间。
~~~cpp
WFHttpTask *http_task = WFTaskFactory::create_http_task(...);
...
http_task->get_resp()->set_size_limit(20 * 1024 * 1024);
http_task->set_receive_timeout(30 * 1000);
~~~
set_size_limit()是HttpMessage的调用，用于限制接收http消息时包的大小。事实上所有的协议消息都要求提供这个接口。  
set_receive_timeout()是接收数据的超时，单位为ms。  
上述代码限制http消息不超过20M，完整接收时间不超过30秒。我们还有更多更丰富的超时配置，后述文档中再介绍。  

# 创建并启动SeriesWork

之前两组示例中，我们直接调用task->start()启动第一个任务。task->start()操作实际的工作方法是，  
先创建一个以task为首任务的SeriesWork，再启动这个series。在[WFTask.h](../src/factory/WFTask.h)里，可以看到start的实现：
~~~cpp
template<class REQ, class RESP>
class WFNetWorkTask : public CommRequest
{
public:
    void start()
    {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }
    ...
};
~~~
我们想给series设置一个callback，并加入一些上下文。所以我们不使用任务的start接口，而是自己创建一个series。  
SeriesWork不能new，delete，也不能派生。只能通过Workflow::create_series_work()接口产生。在[Workflow.h](../src/factory/Workflow.h)中，  
通常是用这个调用：
~~~cpp
using series_callback_t = std::function<void (const SeriesWork *)>;

class Workflow
{
public:
    static SeriesWork *create_series_work(SubTask *first, series_callback_t callback);
};
~~~
在示例代码中，我们的用法是：
~~~cpp
struct tutorial_series_context
{
    std::string http_url;
    std::string redis_url;
    size_t body_len;
    bool success;
};
...
struct tutorial_series_context context;
...
SeriesWork *series = Workflow::create_series_work(http_task, series_callback);
series->set_context(&context);
series->start();
~~~
之前的示例，我们用task里的void *user_data指针保存上下文信息。但这个示例中，我们把上文信息放在series里，  
这么做显然更合理一些，series是完整的任务链，所有任务都能得到并修改上下文。  
series的callback函数在series所有任务被执行完之后调用，在这里，我们简单的用一个lamda函数，打印运行结果并唤醒主线程。  

# 其余的工作

剩下的事情就没有什么特别的了，http抓取成功之后启动一个redis任务写库。如果抓取失败或http body长度为0，则不再启动redis任务。  
无论是什么情况，程序都能在所有任务结束之后正常退出，因为任务都在同一个series里。
