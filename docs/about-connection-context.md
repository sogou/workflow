# 关于连接上下文

连接上下文是使用本框架编程的一个高级课题。使用上会有一些复杂性。  
从之前的示例里可以看出，无论是client还是server任务，我们并没有手段指定使用的具体连接。  
但是有一些业务场景，特别是server端，可能是需要维护连接状态的。也就是说我们需要把一段上下文和连接绑定。  
我们的框架里，是提供了连接上下文机制给用户使用的。  

# 连接上下文的应用场景

http协议可以说是一种完全无连接状态的协议，http会话，是通过cookie来实现的。这种协议对于我们的框架最友好。类似的还有kafka。  
而redis和mysql的连接则是明显带状态，redis通过SELECT命令，指定当前连接上的数据库ID。mysql则是一个彻彻底底的有状态连接。  
使用框架的redis或非事务mysql client任务时，由于URL里已经包含了所有和连接选择有关的信息，包括：
* 用户名密码
* 数据库名或数据库号
* mysql的字符集

框架会根据这些信息自动登录和选择可复用的连接，用户无需关心连接上下文的问题。  
这也是为什么，框架里redis的SELECT命令和mysql的USE命令是禁止用户使用的，切换数据库需要用新的URL创建任务。  
事务型mysql，可以固定连接，这部分内容请参考mysql相关文档。  
但是，如果我们实现一个redis协议的server，那我们需要知道当前连接上的状态了。  

此外，我们还可以通过连接上下文件被释放的事件来感知连接被远端关闭。

# 使用连接上下文的方法

我们需要强调的是，一般情况下只有server任务需要使用连接上下文，并且只需要在process函数内部使用，这也是最安全最简单的用法。  
但是，任务在callback里也可以使用或修改连接上下文，只是使用的时候需要考虑并发的问题。我们会详细地讨论相关问题。    
任何网络任务都可以调用接口获得连接对象，进而获得或修改连接上下文。在[WFTask.h](../src/factory/WFTask.h)里，调用如下：
~~~cpp
template<class REQ, class, RESP>
class WFNetworkTask : public CommRequest
{
public:
    virtual WFConnection *get_connection() const = 0;
    ...
};
~~~
文件[WFConneciton.h](../src/factory/WFConnection.h)里，包含了对连接对象的操作接口：
~~~cpp
class WFConnection : public CommConnection
{
public:
    void *get_context() const;
    void set_context(void *context, std::function<void (void *)> deleter);
    void set_context(void *context);
    void *test_set_context(void *test_context, void *new_context,
                           std::function<void (void *)> deleter);
    void *test_set_context(void *test_context, void *new_context);
};
~~~
get_connection()只可在process或callback里调用，而且如果callback里调用，需要检查返回值是否为NULL。  
如果成功取得WFConnection对象，就可以操作连接上下文了。连接上下文是一个void *指针。  
设置连接上下文可以同时传入deleter函数，在连接被关闭时，deleter被自动调用。    
如果调用无deleter参数的接口，可以只设置新的上下文，保持原有的deleter不变。  

# 访问连接上下文的时机和并发问题

client task被创建的时候，连接对象没有确定，因此所有client task对连接上下文的使用只有在callback里。  
server task可能在两个地方使用连接上下文，process和callback。  
在callback里使用连接上下文时，需要考虑并发问题，因为同一个连接，会被多个task复用，并且同时运行到callback。  
所以，我们推荐只process函数里访问或修改连接上下文，process过程中连接不会被复用或释放，是最简单安全的方法。  
注意，我们指的process只包括process函数内部，在process函数结束后，callback之前，get_connection调用一律返回NULL。  
WFConnection的test_set_context()，就是为了解决callback里使用连接上下文是的并发问题，但我们不推荐使用。  
总之，如果你不是对系统实现非常了解，请只在server task的process函数里使用连接上下文。  

# 示例：减少Http/1.1的请求header传输

http协议可以说是一个连接无状态的协议，同一个连接上，每一次请求都必须发送完整的header。  
假设请求里的cookie非常大，那么这显然就增加了很大的数据传输量。我们可以通过server端连接上下文来解决这个问题。  
我们约定http request里的cookie，对本连接上所有后续请求有效，后续请求header里可以不再发送cookie。  
以下是server端代码：
~~~cpp
void process(WFHttpTask *server_task)
{
    protocol::HttpRequest *req = server_task->get_req();
    protocol::HttpHeaderCursor cursor(req);
    WFConnection *conn = server_task->get_connection();
    void *context = conn->get_context();
    std::string cookie;

    if (cursor.find("Cookie", cookie))
    {
        if (context)
            delete (std::string *)context;
        context = new std::string(cookie);
        conn->set_context(context, [](void *p) { delete (std::string *)p; });
    }
    else if (context)
        cookie = *(std::string *)context;

    ...
}
~~~
通过这种方式，与client端约定好每次只在连接的第一个请求传输cookie，就可以实现流量的节省。  
client端的实现需要用到一个新的回调函数，用法如下：  
~~~cpp

using namespace protocol;

void prepare_func(WFHttpTask *task)
{
    if (task->get_task_seq() == 0)
        task->get_req()->add_header_pair("Cookie", my_cookie);
}

int some_function()
{
    WFHttpTask *task = WFTaskFactory::create_http_task(...);
    task->set_prepare(prepare_func);
    ...
}
~~~
在这个示例中，当http task是连接上的首个请求时，我们设置了cookie。如果不是首个请求，根据约定，不再设置cookie。  
另外，prepare函数里，可以安全的使用连接上下文。同一个连接上，prepare不会并发。
