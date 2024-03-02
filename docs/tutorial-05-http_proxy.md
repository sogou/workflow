# 异步server的示例：http_proxy
# 示例代码

[tutorial-05-http_proxy.cc](/tutorial/tutorial-05-http_proxy.cc)

# 关于http_proxy

这是一个http代理服务器，可以配置在浏览器里使用。支持所有的http method。  
因为https代理的原理不同，这个示例并不支持https代理，你只能浏览http网站。  
这个proxy在实现上需要抓取下来完整的http页面再转发，下载/上传大文件会有延迟。

# 修改server配置

之前的示例我们使用了默认的http server参数。但这个例子里，我们做一点修改，限制请求的大小，防止被恶意攻击。
~~~cpp
int main(int argc, char *argv[])
{
    ...
    struct WFServerParams params = HTTP_SERVER_PARAMS_DEFAULT;
    params.request_size_limit = 8 * 1024 * 1024;

    WFHttpServer server(&params, process);
    if (server.start(port) == 0)
    {
        pause();
        server.stop();
    }
    else
    {
        perror("cannot start server");
        exit(1);
    }

    return 0;   
}
~~~
与上一个示例不同，我们在server构造，多传入一个参数结构。我们可以看看http server有哪些配置。  
在[WFHttpServer.h](../src/server/WFHttpServer.h)里，http server的默认参数如下：
~~~cpp
static constexpr struct WFServerParams HTTP_SERVER_PARAMS_DEFAULT =
{
    .transport_type         =    TT_TCP,
    .max_connections        =    2000,
    .peer_response_timeout  =    10 * 1000,
    .receive_timeout        =    -1,
    .keep_alive_timeout     =    60 * 1000,
    .request_size_limit     =    (size_t)-1,
    .ssl_accept_timeout     =    10 * 1000,
};
~~~
transport_type：传输层协议，默认为TCP。除了TT_TCP外，可选择的还有TT_UDP和Linux下支持的TT_SCTP。  
max_connections：最大连接数2000，达到上限之后会关闭最久未使用的keep-alive连接。没找到keep-alive连接，则拒绝新连接。  
peer_response_timeout：每读取到一块数据或发送出一块数据的超时时间为10秒。  
receive_timeout：接收一条完整的请求超时时间为-1，无限。  
keep_alive_timeout：连接保持1分钟。  
request_size_limit：请求包最大大小，无限制。  
ssl_accept_timeout：完成ssl握手超时，10秒。  
参数里没有send_timeout，即完整的回复超时。这个参数需要每次请求根据自己回复包的大小来确定。  

# 代理服务器业务逻辑

这个代理服务器本质上是将用户请求原封不动转发到对应的web server，再将web server的回复原封不动转发给用户。
浏览器发给proxy的请求里，request uri包含了scheme和host，port，转发时需要去除。  
例如，访问`http://www.sogou.com/`， 浏览器发送给proxy请求首行是：  
`GET` `http://www.sogou.com/` `HTTP/1.1`
需要改写为：  
`GET` `/` `HTTP/1.1`  
~~~cpp
void process(WFHttpTask *proxy_task)
{
    auto *req = proxy_task->get_req();
    SeriesWork *series = series_of(proxy_task);
    WFHttpTask *http_task; /* for requesting remote webserver. */

    tutorial_series_context *context = new tutorial_series_context;
    context->url = req->get_request_uri();
    context->proxy_task = proxy_task;

    series->set_context(context);
    series->set_callback([](const SeriesWork *series) {
        delete (tutorial_series_context *)series->get_context();
    });

    http_task = WFTaskFactory::create_http_task(req->get_request_uri(), 0, 0,
                                                http_callback);

    const void *body;
    size_t len;

    /* Copy user's request to the new task's reuqest using std::move() */
    req->set_request_uri(http_task->get_req()->get_request_uri());
    req->get_parsed_body(&body, &len);
    req->append_output_body_nocopy(body, len);
    *http_task->get_req() = std::move(*req);

    /* also, limit the remote webserver response size. */
    http_task->get_resp()->set_size_limit(200 * 1024 * 1024);

    *series << http_task;
}
~~~
以上是process的全部内容。先解析向web server发送的http请求的构造。  
req->get_request_uri()调用得到浏览器请求的完整URL，通过这个URL构建发往server的http任务。  
这个http任务重试与重定向次数都是0，因为重定向是由浏览器处理，遇到302等会重新发请求。  
~~~cpp
    req->set_request_uri(http_task->get_req()->get_request_uri());
    req->get_parsed_body(&body, &len);
    req->append_output_body_nocopy(body, len);
    *http_task->get_req() = std::move(*req);
~~~
上面4个语句，其实是在生成发往web server的http请求。req是我们收到的http请求，我们最终要通过std::move()把它直接移动到新请求上。  
第一行实际上就是将request_uri里的`http://host:port`部分去掉，只保留path之后的部分。  
第二第三行把解析下来的http body指定为向外输出的http body。需要做这个操作的原因是，我们的HttpMessage实现里，
解析得到的body和发送请求的body是两个域，所以这里需要简单的设置一下，无需复制内存。  
第四行，一次性把请求内容转移给向web server发送的请求。
构造好http请求后，将这个请求放到当前series末尾，process函数结束。

# 异步server的工作原理

显然process函数并不是proxy逻辑的全部，我们还需要处理从web server返回的http response，填写返回给浏览器的response。  
在echo server的示例里，我们并不需要进行网络通信，直接填写返回页面就好。但proxy我们需要等待web server的结果。  
我们当然可以占用这个process函数的线程，等待结果返回，但这种同步等待的方式明显不是我们想要的。  
那么，我们就需要在异步得到请求结果之后，再去回复用户请求，在等待结果期间，不能占用任何的线程。  
所以，在process的头部，我们给当前series设置了一个context，context里包含了proxy_task本身，以便我们异步填写结果。
~~~cpp
struct tutorial_series_context
{
    std::string url;
    WFHttpTask *proxy_task;
    bool is_keep_alive;
};

void process(WFHttpTask *proxy_task)
{
    SeriesWork *series = series_of(proxy_task);
    ...
    tutorial_series_context *context = new tutorial_series_context;
    context->url = req->get_request_uri();
    context->proxy_task = proxy_task;

    series->set_context(context);
    series->set_callback([](const SeriesWork *series) {
        delete (tutorial_series_context *)series->get_context();
    });
    ...
}
~~~
之前client的示例中我们说过，任何一个运行中的任务，都处在一个series里，server任务也不例外。  
所以，我们可以得到当前series，并设置context。其中url主要是后续打日志之用，proxy_task是主要内容，后续需要填写resp。  
接下来我们就可以看看处理web server响应的部分了。
~~~cpp
void http_callback(WFHttpTask *task)
{
    int state = task->get_state();
    auto *resp = task->get_resp();
    SeriesWork *series = series_of(task);
    tutorial_series_context *context =
        (tutorial_series_context *)series->get_context();
    auto *proxy_resp = context->proxy_task->get_resp();

    ...
    if (state == WFT_STATE_SUCCESS)
    {
        const void *body;
        size_t len;

        /* set a callback for getting reply status. */
        context->proxy_task->set_callback(reply_callback);

        /* Copy the remote webserver's response, to proxy response. */
        resp->get_parsed_body(&body, &len);
        resp->append_output_body_nocopy(body, len);
        *proxy_resp = std::move(*resp);
        ...
    }
    else
    {
        // return a "404 Not found" page
        ...
    }
}
~~~
我们只关注成功的情况。一切可以从web server得到一个完整http页面，不管什么返回码，都是成功。所有失败的情况，简单返回一个404页面。
因为返回给用户的数据可能很大，在我们这个示例里，设置为200MB上限。所以，和之前的示例不同，我们需要查看reply成功/失败状态。  
http server任务和我们自行创建的http client任务的类型是完全相同的，都是WFHttpTask。不同的是server任务是框架创建的，它的callback初始为空。  
server任务的callback和client一样，是在http交互完成之后被调用。所以，对server任务来讲，就是reply完成之后被调用。  
后面三行代码我们应该很熟悉了，无拷贝地将web server响应包转移到proxy响应包。  
在这个http_callback函数结束之后，对浏览器的回复被发送出，一切都是在异步的过程中进行。  
剩下的一个函数是reply_callback()，在这里只为了打印一些log。在这个callback执行结束后，proxy task会被自动delete。  
最后，series的callback里销毁context。

# Server回复的时机

这里需要说明一下，回复消息的时机是在series里所有其它任务被执行完后，自动回复，所以并没有task->reply()接口。  
但是，有task->noreply()调用，如果对server任务执行了这个调用，在原本回复的时刻，直接关闭连接。但callback依然会被调用（状态为NOREPLY）。  
在server任务的callback里，同样可以通过series_of()操作获得任务的series。那么，我们依然可以往这个series里追加新任务，虽然回复已经完成。  

# 另外一种实现异步Server的便利方法

由于很多用户会直观的觉得，server的process函数结束server处理流程就结束并回复了。所以，经常有用户在process里使用wait group进行等待：
~~~cpp
int process(WFHttpTask *server_task)
{
    WFFacilities::WaitGroup wait_group(1);
    WFHttpTask *task = WFTaskFactory::create_http_task(..., [&wait_group, server_task]{WFHttpTask *task) {
        *server_task->get_resp() = std::move(*task->get_resp());
        wait_group.done();
    });
    task->start();
    wait_group.wait();
}
~~~
我们需要强调，以上的代码是一种不高效的写法，因为这会让一个线程进入等待。等价的高效写法是：
~~~cpp
int process(WFHttpTask *server_task)
{
    WFHttpTask *task = WFTaskFactory::create_http_task(..., [server_task]{WFHttpTask *task) {
        *server_task->get_resp() = std::move(*task->get_resp());
    });
    series_of(server_task)->push_back(task);
}
~~~
但鉴于很多用户不想了解series用法，我们加入一个便利类ReplyGuard，让用户可以在任何时候回复请求，用法如下：
~~~cpp
int process(WFHttpTask *server_task)
{
    auto *guard = new WFFacilities::ReplyGuard(server_task);
    WFHttpTask *task = WFTaskFactory::create_http_task(..., [guard, server_task]{WFHttpTask *task) {
        *server_task->get_resp() = std::move(*task->get_resp());
        delete guard;  // 此时server才会回复。
    });
    task->start();
}
~~~
WFFacilities::ReplyGuard用于阻止一个server task的回复，只有这个guard被析构，才会触发回复。  
使用ReplyGuard一般不影响原server task series的使用，用户依然可以push_back任务。但**避免再调用series的cancel()**。
