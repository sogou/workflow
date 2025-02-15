# About connection context

Connection context is an advanced programming topic in this framework.  
From the previous examples, we can see that we cannot assign one specific connection for a client task or a server task.   
However, in some business scenarios, especially for the server, we may need to maintain the connection status. In other words, we need to bind a context to a connection.   
In the framework, we provide a connection context for users.

# Application senarios for connection context

HTTP is a completely stateless protocol, and HTTP session is realized with cookies. HTTP, Kafka and other stateless protocols are most friendly with our framework.   
The connection used by Redis and MySQL is obviously stateful. Redis specifies the database ID on the current connection with the SELECT command. MySQL uses a completely stateful connection.   
When you use Redis or non-transactional MySQL client tasks in the framework, the URL already contains all the information related to the connection, including:

* username and password
* database name or database ID
* the character set for MySQL

The framework will automatically log in or select  a reusable connection based on the above information, and you do not need to care about the connection context.   
Due to this limitation, in the framework, you cannot use the SELECT command of Redis and the USE command of MySQL. If you want to switch databases, you should use a new URL to create the task.   
Transactional MySQL tasks can use fixed connections. Please see MySQL documentations for relevant details.   
However, if you implement a server based on Redis protocol, you need to know the current connection status.

By using the deleter function of connection context, users can also get notified when the connection was closed by the peer.

# How to use connection context

Note: generally, only the server tasks need to use the connection context, and the connection context is used only inside the process function, which is also the safest and simplest.   
You can also use or modify the connection context in the callback, but you should consider the concurrency problem. We’ll discuss the related issues in details.   
You can obtain the connection object in any network task through interfaces, and then obtain or modify the connection context. [WFTask.h](../src/factory/WFTask.h) contains a sample call:

~~~cpp
template<class REQ, class, RESP>
class WFNetworkTask : public CommRequest
{
public:
    virtual WFConnection *get_connection() const = 0;
    ...
};
~~~

[WFConneciton.h ](../src/factory/WFConnection.h)contains the interfaces for performing operations on the connection objects:

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

**get\_connection()** can only be called in a process or a callback. If you call it in the callback, please check whether the return value is NULL.   
If you get the WFConnection object successfully, you can perform operations on the connection context. A connection context is a void \* pointer. When the connection is closed, the deleter is automatically called. When using the setting context functions without ``deleter`` argument, the original deleter will be kept unchanged.

# Timing and concurrency for accessing connection context

When a client task is created, the connection object is not determined. Thus, for all client tasks, you can only use the connection context in the callback.   
For server tasks, you may use connection context in the process or the callback.   
When you use connection context in a callback, you need to consider concurrency, because the same connection may be reused by multiple tasks and reach the callbacks at the same time.   
Therefore, we recommend that the connection context should be accessed or modified only in the process function, because the connection will not be reused or released in the process, which is the simplest and safest.   
Note: the process in the above paragraphs means only the places inside the process function. In the places after the process function and before the callback, get\_connection() always returns NULL.   
**test\_set\_context()** in the WFConnection is used to solve the concurrency issues for using connection context in the callback, but it is not recommended.   
In a word, if you are not very familiar with the system implementation, please use the connection context only in the process function of the server tasks.

# Example: how to reduce the request header fields in HTTP/1.1

HTTP protocol is a stateless connection protocol, and a complete header must be sent for every request on the same connection.   
If the cookie in the request is very large, it will obviously increase the data transmission overload. You can use the server-side connection context to solve this issue.   
You can specify that the cookie in the HTTP request is valid for all subsequent requests on the same connection, and omit the cookie in the subsequent request headers.   
Please see the following codes on the server side:

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

In this way, if you arrange with the client that the cookie is transmitted only at the first request of the connection, the traffic can be reduced.   
The implementation in the client side needs to use a new **prepare** function. Please see the codes below:

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

In the example, when the HTTP task is the first request on the connection, the cookie is set. If it is not the first request, according to our arrangement, we do not set the cookie.   
In addition, you may use the connection context safely in the **prepare** function. **prepare** will not be concurrent on the same connection.  
