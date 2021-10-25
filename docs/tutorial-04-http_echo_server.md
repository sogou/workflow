# 第一个server：http_echo_server
# 示例代码

[tutorial-04-http_echo_server.cc](/tutorial/tutorial-04-http_echo_server.cc)

# 关于http_echo_server

这是一个http server，返回一个html页面，显示浏览器发送的http请求的header信息。  
程序log里会打印出请求的client地址，请求序号（当前连接上的第几次请求）。当同一连接上完成10次请求，server主动关闭连接。  
程序通过Ctrl-C正常结束，一切资源完全回收。

# 创建与启动http server

本示例里，我们采用http server的默认参数。创建和启动过程非常简单。
~~~cpp
WFHttpServer server(process);
port = atoi(argv[1]);
if (server.start(port) == 0)
{
    pause();
    server.stop();
}
...
~~~
这个过程实在太简单，没有什么好讲。要注意start是非阻塞的，所以要pause住程序。显然你也可以启动多个server对象再pause。  
server启动之后，任何时刻都可以通过stop()接口关停server。关停是非暴力式的，会等待正在服务的请求执行完。  
所以，stop是一个阻塞操作。如果需要非阻塞的关闭，可使用shutdown+wait_finish接口。  
start()接口有好几个重载函数，在[WFServer.h](../src/server/WFServer.h)里，可以看到如下一些接口：
~~~cpp
class WFServerBase
{
public:
    /* To start TCP server. */
    int start(unsigned short port);
    int start(int family, unsigned short port);
    int start(const char *host, unsigned short port);
    int start(int family, const char *host, unsigned short port);
    int start(const struct sockaddr *bind_addr, socklen_t addrlen);

    /* To start an SSL server */
    int start(unsigned short port, const char *cert_file, const char *key_file);
    int start(int family, unsigned short port,
              const char *cert_file, const char *key_file);
    int start(const char *host, unsigned short port,
              const char *cert_file, const char *key_file);
    int start(int family, const char *host, unsigned short port,
              const char *cert_file, const char *key_file);
    int start(const struct sockaddr *bind_addr, socklen_t addrlen,
              const char *cert_file, const char *key_file);

    /* For graceful restart or multi-process server. */
    int serve(int listen_fd);
    int serve(int listen_fd, const char *cert_file, const char *key_file);

    /* Get the listening address. Used when started a server on a random port. */
    int get_listen_addr(struct sockaddr *addr, socklen_t *addrlen) const;
};
~~~
这些接口都比较好理解。任何一个start函数，当端口号为0时，将使用随机端口。此时用户可能需要在server启动完成之后通过get_listen_addr获得实际监听地址。  
启动SSL server时，cert_file和key_file为PEM格式。  
最后两个带listen_fd的serve()接口，主要用于优雅重启。或者简单建立一个非TCP协议（如SCTP）的server。  
需要特别提醒一下，我们一个server对象对应一个listen_fd，如果在IPv4和IPv6两个协议上都运行server，需要：
~~~cpp
{
    WFHttpServer server_v4(process);
    WFHttpServer server_v6(process);
    server_v4.start(AF_INET, port);
    server_v6.start(AF_INET6, port);
    ...
    // now stop...
    server_v4.shutdown();   /* shutdown() is nonblocking */
    server_v6.shutdown();
    server_v4.wait_finish();
    server_v6.wait_finish();
}
~~~
这种方式我们没有办法让两个server共享连接记数。所以推荐只启动IPv6 server，因为IPv6 server可以接受IPv4的连接。

# http echo server的业务逻辑

我们看到在构造http server的时候，传入了一个process参数，这也是一个std::function，定义如下：  
~~~cpp
using http_process_t = std::function<void (WFHttpTask *)>;
using WFHttpServer = WFServer<protocol::HttpRequest, protocol::HttpResponse>;

template<>
WFHttpServer::WFServer(http_process_t proc) :
    WFServerBase(&HTTP_SERVER_PARAMS_DEFAULT),
    process(std::move(proc))
{
}
~~~
其实这个http_proccess_t和的http_callback_t类型是完全一样的。都是处理一个WFHttpTask。  
对server来讲，我们的目标就是根据request，填写好response。  
同样我们用一个普通函数实现process。逐条读出request的http header写入html页面。
~~~cpp
void process(WFHttpTask *server_task)
{
    protocol::HttpRequest *req = server_task->get_req();
    protocol::HttpResponse *resp = server_task->get_resp();
    long seq = server_task->get_task_seq();
    protocol::HttpHeaderCursor cursor(req);
    std::string name;
    std::string value;
    char buf[8192];
    int len;

    /* Set response message body. */
    resp->append_output_body_nocopy("<html>", 6);
    len = snprintf(buf, 8192, "<p>%s %s %s</p>", req->get_method(),
                   req->get_request_uri(), req->get_http_version());
    resp->append_output_body(buf, len);

    while (cursor.next(name, value))
    {
        len = snprintf(buf, 8192, "<p>%s: %s</p>", name.c_str(), value.c_str());
        resp->append_output_body(buf, len);
    }

    resp->append_output_body_nocopy("</html>", 7);

    /* Set status line if you like. */
    resp->set_http_version("HTTP/1.1");
    resp->set_status_code("200");
    resp->set_reason_phrase("OK");

    resp->add_header_pair("Content-Type", "text/html");
    resp->add_header_pair("Server", "Sogou WFHttpServer");
    if (seq == 9) /* no more than 10 requests on the same connection. */
        resp->add_header_pair("Connection", "close");

    // print log
    ...
}
~~~
大多数HttpMessage相关操作之前已经介绍过了，在这里唯一的一个新操作是append_output_body()。  
显然让用户生成完整的http body再传给我们并不太高效。用户只需要调用append接口，把离散的数据一块块扩展到message里就可以了。  
append_output_body()操作会把数据复制走，另一个带_nocopy后缀的接口会直接引用指针，使用时需要注意不可以指向局部变量。  
相关几个调用在[HttpMessage.h](../src/protocol/HttpMessage.h)可以看到其声明：
~~~cpp
class HttpMessage
{
public:
    bool append_output_body(const void *buf, size_t size);
    bool append_output_body_nocopy(const void *buf, size_t size);
    ...
    bool append_output_body(const std::string& buf);
};
~~~
再次强调，使用append_output_body_nocopy()接口时，buf指向的数据的生命周期至少需要延续到task的callback。  
函数中另外一个变量seq，通过server_task->get_task_seq()得到，表示该请求是当前连接上的第几次请求，从0开始计。  
程序中，完成10次请求之后就强行关闭连接，于是：
~~~cpp
    if (seq == 9) /* no more than 10 requests on the same connection. */
        resp->add_header_pair("Connection", "close");
~~~
关闭连接还可以通过task->set_keep_alive()接口来完成，但对于http协议，还是推荐使用设置header的方式。  
这个示例中，因为返回的页面很小，我们没有关注回复成功与否。下一个示例http_proxy我们将看到如果获得回复的状态。

