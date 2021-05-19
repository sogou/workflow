# 创建第一个任务：wget
# 示例代码

[tutorial-01-wget.cc](/tutorial/tutorial-01-wget.cc)

# 关于wget
程序从stdin读取http/https URL，抓取网页并把内容打印到stdout，并将请求和响应的http header打印在stderr。  
为了简单起见，程序用Ctrl-C退出，但会保证所有资源先被完全释放。

# 创建并启动http任务
~~~cpp
WFHttpTask *task = WFTaskFactory::create_http_task(url, REDIRECT_MAX, RETRY_MAX, wget_callback);
protocol::HttpRequest *req = task->get_req();
req->add_header_pair("Accept", "*/*");
req->add_header_pair("User-Agent", "Wget/1.14 (gnu-linux)");
req->add_header_pair("Connection", "close");
task->start();
pause();
~~~
WFTaskFactory::create_http_task()产生一个http任务，在[WFTaskFactory.h](../src/factory/WFTaskFactory.h)文件里，原型定义如下：
~~~cpp
WFHttpTask *create_http_task(const std::string& url,
                             int redirect_max, int retry_max,
                             http_callback_t callback);
~~~
前几个参数不用过多解释，http_callback_t是http任务的callback，定义如下：
~~~cpp
using http_callback_t = std::function<void (WFHttpTask *)>;
~~~
说白了，就是一个参数为Task本身，没有返回值的函数。这个callback可以传NULL，表示无需callback。我们一切任务的callback都是这个风格。  
需要说明的是，所有工厂函数不会返回失败，所以不用担心task为空指针，哪怕是url不合法。一切错误都在callback再处理。  
task->get_req()函数得到任务的request，默认是GET方法，HTTP/1.1，长连接。框架会自动加上request_uri，Host等。  
框架会在发送前根据需要自动加上Content-Length或Connection这些http header。用户也可以通过add_header_pair()方法添加自己的header。  
关于http消息的更多接口，可以在[HttpMessage.h](../src/protocol/HttpMessage.h)中查看。  
task->start()启动任务，非阻塞，并且不会失败。之后callback必然会在被调用。因为异步的原因，start()以后显然不能再用task指针了。  
为了让示例尽量简单，start()之后调用pause()防止程序退出，用户需要Ctrl-C结束程序。

# 处理http抓取结果
在这个示例中，我们使用一个普遍的函数处理结果。当然，std::function支持更多的功能。
~~~cpp
void wget_callback(WFHttpTask *task)
{
    protocol::HttpRequest *req = task->get_req();
    protocol::HttpResponse *resp = task->get_resp();
    int state = task->get_state();
    int error = task->get_error();

    // handle error states
    ...

    std::string name;
    std::string value;
    // print request to stderr
    fprintf(stderr, "%s %s %s\r\n", req->get_method(), req->get_http_version(), req->get_request_uri());
    protocol::HttpHeaderCursor req_cursor(req);
    while (req_cursor.next(name, value))
        fprintf(stderr, "%s: %s\r\n", name.c_str(), value.c_str());
    fprintf(stderr, "\r\n");
    
    // print response header to stderr
    ...

    // print response body to stdin
    const void *body;
    size_t body_len;
    resp->get_parsed_body(&body, &body_len); // always success.
    fwrite(body, 1, body_len, stdout);
    fflush(stdout);
}
~~~
在这个callback里，task就是我们通过工厂产生的task。  
task->get_state()与task->get_error()分别获得任务的运行状态和错误码。我们先略过错误处理的部分。  
task->get_resp()得到任务的response，这个和request区别不大，都是HttpMessage的派生。  
之后通过HttpHeaderCursor对象，对request和response的header进行扫描。在[HttpUtil.h](../src/protocol/HttpUtil.h)可以看到Cursor的定义。

~~~cpp
class HttpHeaderCursor
{
public:
    HttpHeaderCursor(const HttpMessage *message);
    ...
    void rewind();
    ...
    bool next(std::string& name, std::string& value);
    bool find(const std::string& name, std::string& value);
    ...
};
~~~
相信这个cursor在使用上应该不会有什么疑惑。  
之后一行resp->get_parsed_body()获得response的http body。这个调用在任务成功的状态下，必然返回true，body指向数据区。  
这个调用得到的是原始的http body，不解码chunk编码。如需解码chunk编码，可使用[HttpUtil.h](../src/protocol/HttpUtil.h)里的HttpChunkCursor。
另外需要说明的是，find()接口会修改cursor内部的指针，即使用过find()过后如果仍然想对header进行遍历，需要通过rewind()接口回到cursor头部。

