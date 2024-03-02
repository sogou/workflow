# Asynchronous server: http\_proxy

# Sample code

[tutorial-05-http\_proxy.cc](/tutorial/tutorial-05-http_proxy.cc)

# About http\_proxy

It is an HTTP proxy server. You can use it in a browser after proper configuration. It supports all HTTP methods.   
As HTTPS proxy follows different principles, this example does not support HTTPS proxy. You can only browse HTTP websites.   
In the implementation, this proxy must crawl the entire HTTP page and then forward it. Therefore, there will be noticeable latency when you upload/download a large file.

# Changing server configuration

In the previous example, we use the default parameters of an HTTP server. In this tutorial, we will made some changes and limit the size of the request so as to prevent malicious attack.

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
Unlike the previous example, we pass an additional parameter to the server struct. Let’s see the configuration items in the HTTP server.   
In [WFHttpServer.h](/src/server/WFHttpServer.h), the default parameters for an HTTP server include:
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
**transport\_type**: the transport layer protocol. Besides the default type TT_TCP, you may specify TT_UDP, or TT_SCTP on Linux platform.  
**max\_connections**: the maximum number of connections is 2000. When it is exceeded, the least recently used keep-alive connection will be closed. If there is no keep-alive connection, the server will refuse new connections.  
**peer\_response\_timeout**: set the maximum duration for reading or sending out a block of data. The default setting is 10 seconds.   
**receive\_timeout**: set the maximum duration for receiving a complete request; -1 means unlimited time.   
**keep\_alive\_timeout**: set the maximum duration for maintaining a connection. The default setting is 1 minute.   
**request\_size\_limit**: set the maximum size of a request packet. The default setting is unlimited packet size.   
**ssl\_accept\_timeout**: set the maximum duration for an SSL handshake. The default setting is 10 seconds.   
There is no **send\_timeout** in the parameters. **send\_timeout** sets the timeout for sending a complete response. This parameter should be determined according to the size of the response packet.

# Business logic of a proxy server

Essentially, this proxy server forwards a user's request intactly to the corresponding web server, and then forwards the reply from the web server intactly to the user. 
In the request sent by a browser to the proxy, the Request URL contains scheme, host and port, which should be removed before forwarding.   
For example, when the browser visits `http://www.sogou.com/`, the first line of the request sent by the browser to the proxy is:
 `GET` `http://www.sogou.com/` `HTTP/1.1`  
which should be rewritten as:  
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

The above contains the entire content of the process. It first parses the struct of an HTTP request sent by a web server.   
**req->get\_request\_uri()** is used to get the complete URL of the request sent by a browser. And then build a HTTP task to the server based on this URL.   
Both the retry times and the redirection times of this HTTP task is 0, because the redirection is handled by the browser and the browser will be resend the request when it meets 302, etc.

~~~cpp
    req->set_request_uri(http_task->get_req()->get_request_uri());
    req->get_parsed_body(&body, &len);
    req->append_output_body_nocopy(body, len);
    *http_task->get_req() = std::move(*req);
~~~

In fact, the above four lines generates a HTTP request to the web server. req is the received HTTP request, and it will be moved directly to the new request via **std::move()**.   
The first line removes the `http://host:port` in the request\_uri and keeps the part after the path.   
The second line and the third line specify the parsed HTTP body as the HTTP body for output. The reason for this operation is that in the HttpMessage implementation, the http body obtained by parsing and the http body to send out are two fields, so we need to simply set it here, without copying the memory.   
The fourth line transfers the request content to the request sent to the web server at one time. After the HTTP request is constructed, the request is placed at the end of the current series, and the process function ends.

# Principles behind an asynchronous server

Obviously, the process function is only part of the proxy logic. We also need to handle the HTTP response returned from the web server and generates the response for the browser.   
In the example of echo server, we populate the response page directly without network communication. However, in the proxy server, we have to wait for the response from the web server.   
Of course, we can occupy the thread of this process function and wait for the returned result, but this synchronous waiting mode is obviously not desirable.   
Thus, it is better that we reply to the user's request asynchronously after receiving the results for the request, and no thread is occupied while we are waiting for the result.   
Therefore,  we set a context for the current series in the head of the process, which contains the proxy\_task itself. In this way, we can populate the results asynchronously.

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

In the previous client example, we said that any running task is in a series, and the server task is no exception.   
Thus, we can get the current series and set the context. In which the URL is mainly used for the subsequent logs, and the proxy\_task is the main content, which is used for resp later.   
Next, Let’s see how to handle the responses from the  web server.

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

Here we focus on the successful cases only. If the proxy gets a complete HTTP page from the web server, no matter what the return code is, it is considered a success. All failure will simply return a 404 page. 
Because the data returned to the user may be very large, the maximum size is set to 200MB in this example. Therefore, unlike the previous examples, we need to check the success/failure status of the reply.   
The type of an HTTP server task is identical to the type of an HTTP client task created by ourselves. Both are WFHttpTask. The difference is that a server task is created by the framework, and its callback is initially empty.   
The callback of a server task is the same as that of a client. Both are called after an HTTP interaction is completed. Therefore, for all server tasks, the callback is called after the reply is completed.   
The following three lines of code are explained before. They transfer the response packets from the web server to the proxy response packets without copying.   
After the **http\_callback** function is ended, the reply to the browser is sent out. Everything is done asynchronously.   
The remaining function **reply\_callback()**  is used just to print some logs here. The proxy task will be automatically deleted after this callback is finished.   
Finally, the context is destroyed in the callback of the series.

# Timing of a server reply

Please note that the reply message is sent automatically after all other tasks in the series are finished, so there is no **task->reply()** interface.   
However, there is a **task->noreply()**. If this interface is called for the server task, the connection will be closed directly at the original reply time. But the callback will still be called (its state is NOREPLY).   
In the callback of a server task, you can also call **series\_of()** to get the series of that server task. Then, you can still add new tasks to this series, although the reply has finished.   
