# 实现一次redis写入与读出：redis_cli
# 示例代码

[tutorial-02-redis_cli.cc](/tutorial/tutorial-02-redis_cli.cc)

# 关于redis_cli

程序从命令行读入一个redis服务器地址，以及以一对key，value。执行SET命令写入这对KV，之后再读出验证写入是否成功。  
程序运行方法：./redis_cli \<redis URL\> \<key\> \<value\>  
为简单起见，程序需要用Ctrl-C结束。

# Redis URL的格式

redis://:password@host:port/dbnum?query#fragment  
如果是SSL，则为：  
rediss://:password@host:port/dbnum?query#fragment  
password是可选项。port的缺省值是6379，dbnum缺省值0，范围0-15。  
query和fragment部分工厂里不作解释，用户可自行定义。比如，用户有upstream选取需求，可以自定义query和fragment。相关内容参考upstream文档。  
redis URL示例：  
redis://127.0.0.1/  
redis://:12345678@redis.some-host.com/1

# 创建并启动Redis任务

创建Redis任务与创建http任务并没有什么区别，少了redirect_max参数。
~~~cpp
using redis_callback_t = std::function<void (WFRedisTask *)>;

WFRedisTask *create_redis_task(const std::string& url,
                               int retry_max,
                               redis_callback_t callback);
~~~
在这个示例里，我们想在redis task里存一些用户信息，包括url和key，以便在callback里使用。  
当然，我们可利用std::function来绑定参数，但在这里我们利用了task里的void *user_data指针。这是task的一个public成员。
~~~cpp
struct tutorial_task_data
{
    std::sring url;
    std::string key;
};
...
struct tutorial_task_data data;
data.url = argv[1];
data.key = argv[2];

WFRedisTask *task = WFTaskFactory::create_redis_task(data.url, RETRY_MAX, redis_callback);

protocol::RedisRequest *req = task->get_req();
req->set_request("SET", { data.key, argv[3] });

task->user_data = &data;
task->start();
pause();
~~~
与http task的get_req()类似，redis task的get_req()返回任务对应的redis request。  
RedisRequest提供的功能可以在[RedisMessage.h](../src/protocol/RedisMessage.h)查看。
其中，set_request接口用于设置redis命令。  
~~~cpp
void set_request(const std::string& command, const std::vector<std::string>& params);
~~~
相信经常使用redis的人，对这个接口不会有什么疑问。但必须注意，我们的请求是禁止SELECT命令和AUTH命令的。  
因为用户每次请求并不能指定具体连接，SELECT之后下一次请求并不能保证在同一个连接上发起，那么这个命令对用户来讲没有任何意义。  
对数据库选择和密码的指定，请在redis URL里完成。并且，必须是每次请求的URL都带着这些信息。  
另外，我们的redis client是支持cluster模式的，可以自动处理MOVED和ASK回复并重定向。用户不能自己发送ASKING命令。  

# 处理请求结果

程序在SET命令成功之后，再发起一次GET命令，验证写入的结果。GET命令也用同一个callback。所以，函数里会判断这是哪个命令的结果。  
同样，我们先忽略错误处理部分。
~~~cpp
void redis_callback(WFRedisTask *task)
{
    protocol::RedisRequest *req = task->get_req();
    protocol::RedisResponse *resp = task->get_resp();
    int state = task->get_state();
    int error = task->get_error();
    protocol::RedisValue val;

    ...
    resp->get_result(val);
    std::string cmd;
    req->get_command(cmd);
    if (cmd == "SET")
    {
        tutorial_task_data *data = (tutorial_task_data *)task->user_data;
        WFRedisTask *next = WFTaskFactory::create_redis_task(data->url, RETRY_MAX, redis_callback);

        next->get_req()->set_request("GET", { data->key });
        series_of(task)->push_back(next);
        fprintf(stderr, "Redis SET request success. Trying to GET...\n");
    }
    else /* if (cmd == 'GET') */
    {
        // print the GET result
        ...
        fprintf(stderr, "Finished. Press Ctrl-C to exit.\n");
    }
}
~~~
RedisValue是一次redis request得到的结果，同样在[RedisMessage.h](../src/protocol/RedisMessage.h)里可以看到其接口。  
callback需要特别解释的，是series_of(task)->push_back(next)这个语句。因为这是我们第一次使用到Workflow的功能。  
在这里next是我们下一个要发起的redis task，执行GET操作。我们并不是执行next->start()来启动任务，而是把next任务push_back到当前任务序列的末尾。  
这两种方法的区别在于：
  * 用start来启动任务，任务是被立刻启动的，而push_back的方法，next任务是在callback结束之后被启动。
    * 最起码的好处是，push_back方法可以保证log打印不会乱。否则，用next->start()的话，示例中"Finished."这个log可能会被先打印。
  * 用start来启动下一个任务的话，当前任务序列（series）就结束了，next任务会新启动一个新的series。
    * series是可以设置callback的，虽然在示例中没有用到。
    * 在并行任务里，series是并行任务的一个分枝，series结束就会认为分枝结束。并行相关内容在后续教程中讲解。

总之，如果你想在一个任务之后启动下一个任务，一般是使用push_back操作来完成（还有些情况可能要用到push_front）。  
而series_of()则是一个非常重要的调用，是一个不属于任何类的全局函数。其定义和实现在[Workflow.h](../src/factory/Workflow.h#L140)里：
~~~cpp
static inline SeriesWork *series_of(const SubTask *task)
{
    return (SeriesWork *)task->get_pointer();
}
~~~
任何task都是SubTask类型的派生。而任何运行中的task，一定属于某个series。通过series_of调用，得到了任务所在的series。  
而push_back是SeriesWork类的一个调用，其功能是将一个task放到series的末尾。类似调用还有push_front。本示例中，用哪个调用并没有区别。
~~~cpp
class SeriesWork
{
    ...
public:
    void push_back(SubTask *task);
    void push_front(SubTask *task);
    ...
}
~~~
SeriesWork类在我们整个体系中，扮演重要的角色。在下一个示例中，我们将展现SeriesWork更多的功能。
