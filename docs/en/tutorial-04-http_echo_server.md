# First server: http\_echo\_server

# Sample code

[tutorial-04-http\_echo\_server.cc](/tutorial/tutorial-04-http_echo_server.cc)

# About http\_echo\_server

It is an HTTP server that returns an HTML page, which displays the header data in the HTTP request sent by the browser.   
The log of the program contains the client address and the sequence of the request (the number of requests on the current connection). When 10 requests are completed on the same connection, the server actively closes the connection.   
The program exits normally after users press Ctrl-C, and all resources are completely reclaimed.

# Creating and starting an HTTP server

In this example, we use the default parameters of an HTTP server. It is very simple to create and start an HTTP server.

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

The procedure is too simple to explain. Please note that the start process is non-blocking, so please pause the program. Obviously you can start several server objects and then pause.   
After a server is started, you can use **stop()** interface to shut down the server at any time. Stopping a server is non-violent and will be done until all the processing requests in the server are completed.   
Therefore, **stop** is a blocking operation. If non-blocking shutdown is required, please use **shutdown+wait\_finish** interface.   
There are several overloaded functions with **start()**. [WFServer.h](/src/server/WFServer.h) contains the following interfaces:

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
There interfaces are easy to understand. If the **port** number is zero, the server will be started on a random port, and you may need to call **get_listen_addr** to abtain the actual listening address (mainly for the actual port) after the server is started.  
When you start an SSL server, the cert\_file and key\_file should be in PEM format.  
The last two **serve()** interfaces have the parameter **listen\_fd**, which is used for graceful restart or for building a simple non-TCP (such as SCTP) server.   
Please note that one server object corresponds to one **listen\_fd**. If  the server is running on both IPv4 and IPv6 protocols, you should:

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

In the above code, the two servers cannot share the connection counter. Therefore, it is recommended to start the IPv6 server only, because the IPv6 server can accept IPv4 connection.

# Business logic of an HTTP echo server

When you build an HTTP server, you pass a process parameter, which is also an **std::function**, as defined below:

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

Actually, the type of **http\_proccess\_t** and the type of **http\_callback\_t** are exactly the same. Both are used to handle WFHttpTask.   
The job of the server is to populate the response based on the request.   
Similarly, we use an ordinary function to implement the process. The process iterates over the HTTP header of the request line by line and then writes them into an HTML page.

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

You have learned most of the HttpMessage related operations. The only new operation here is **append\_output\_body()**.   
Obviously, it is not very efficient for the users to generate a complete HTTP body and pass it to the framework. The user only needs to call the **append** interface to append the discrete data to the message block by block.   
**append\_output\_body()** operation will move the data, and another interface with the suffix **\_nocopy** will directly use the reference to the pointer. Please do not make it point to the local variables when you use it.   
[HttpMessage.h](../src/protocol/HttpMessage.h) contains the declaration of relevant calls. 

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

Once again, please note that when you use **append\_output\_body\_nocopy()**, the lifecycle of the data referenced by the buf must at least be extended to the callback of the task.   
Another variable seq in the function is obtained by **server\_task->get\_task\_seq()**, which indicates the number of requests on the current connection, starting from 0.   
In the program, the connection is forcibly closed after 10 requests are completed, thus:

~~~cpp
    if (seq == 9) /* no more than 10 requests on the same connection. */
        resp->add_header_pair("Connection", "close");
~~~

You can also use **task->set\_keep\_alive()** to close the connection. However, for the connection using HTTP protocol, it is recommended to set the “close” option in HTTP header.   
In this example, because the response page is very small, we didn't pay attention to the reply status. In the next tutorial **http\_proxy**, you will learn how to get the reply status.
