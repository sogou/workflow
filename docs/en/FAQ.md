# FAQs

### Project background and issues solved

C++ Workflow,  originating from the communication engine in the distributed storage project of Sogou, gradually become the C++ programming standard in Sogou. It is used to support most C++ back-end services in Sogou. The project incorporates both communication and computing harmoniously, and supports to build high-performance services with complex relations between communication and computing. It can also be used as a simple asynchronous network engine or parallel computing framework.

### Get started with C++ Workflow

To run it on Linux:

~~~sh
$ git clone https://github.com/sogou/workflow
$ cd workflow
$ make
$ cd tutorial
$ make
~~~

Then you can run the sample codes on Linux. Each sample is well-explained in separate documentation. If Kafka protocol is required, please install snappy and lz4 first, and:

~~~sh
$ make KAFKA=y
$ cd tutorial
$ make KAFKA=y
~~~

In addition, you can use ``make DEBUG=y`` to compile the debug version.

### Advantages over other network engines or RPC projects

* Simple and easy to use, with no dependences
* Excellent performance and stability benchmark
* General protocols implemented
* Integrating communication and computing
* Tasks flow management

### Advantages over other parallel computing frameworks

* Simple to use
* Network supported

### Features currently not supported

* Pipeline server
* streaming communication (supported in the foundation module; high-level interfaces design is required)
* UDP server (UDP clients supported)
* WebSocket (coming soon...)

### What protocols are natively supported?

Currently we have implemented ``HTTP``, ``Redis``, ``MySQL`` and ``Kafka`` protocols. For Kafka, only clients are supported currently; for other protocols, client+server are supported. In other words, you can use the project to build Redis or MySQL proxy servers. Kafka module is a plug-in and is not compiled by default.

### Why do we use callback?

We encapsulate user behaviors with the **callback** and **process** in C++11 **std::function**. You should know that you are writing asynchronous programs. We believe that **callback** is more efficient than **future** or user-mode coroutines in the program and better at combining communication with calculation. Due to the convenience brought by the task encapsulation and **std::function**, the **callback** in our framework is not too cumbersome, but very simple and clear.

### In what thread is the callback called?

In the project, the threads are managed by the framework. Except for some special cases, the thread that calls the **callback** must be one of the handler threads that handle the results of the network transmission and file IO (20 threads by default) or one of the computing threads (the total number of CPU cores by default). However, it is not recommended to wait for or run particularly complex calculations in the **callback**, no matter in which type of threads mentioned above. The waiting should be implemented with a **counter task**, which waits without occupying a thread. The complex calculation should be encapsulated in the **thread task**. 

It should be noted that all resources in the framework are allocated at runtime. If you do not use network communication, all communication-related threads will not be created.

### Why is there no response after I started the task?

~~~cpp
int main(void)
{
    ...
    task->start();
    return 0;
}
~~~

Many new users will encounter this issue. Almost all calls in the framework are non-blocking. In the code above, the **main** function returns immediately after the task starts, and does not wait for the end of the task. You must wake up the main process in some way. For example:

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

### What is the life cycle of a task object?

Each task in the framework (as well as **SeriesWork**) is given to you in the form of a bare pointer. The life cycle of each task object starts from the creation of the object and ends in the completion of the callback of that object. In other words, the task pointer is invalid after the callback, and all the data in that task are also destroyed. If you want to keep the data, you can use **std::move()** to move them. For example, the code below keeps **resp** in the HTTP task:

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

In some cases, if you create the task and then do not want to start it, you can call **task->dismiss()** to destroy the task directly. 
It should be emphasized that the **process** function in the server is not a callback. The callback of a server task runs after the reply is completed, and it is **nullptr** by default.

### Why SeriesWork is not a task?

We define **SeriesWork** and **ParallelWork** as follows:

* **SeriesWork** consists of tasks
* **ParallelWork** consists of **SeriesWorks**
* **ParallelWork** is one type of tasks

Obviously, we can recursively derive any complex **SeriesWork-ParallelWork** structure based on the above three definitions. If the **SeriesWork** were also defined as a task, then the **SeriesWork** might consists of several sub-series, and it is easy to get confused. Similarly, **ParallelWork** can only be the union of several **SeriesWorks**, which also avoids confusion. In fact, you will find that the **SeriesWork** is essentially the **coroutine**.

### What should I do if I want a more general DAG?

You can use **WFGraphTask**, or build your own DAG with the **WFCounterTask**.

### Does a server reply after the process function ends?

No. The server replies to a request if the **series** of that server task contains no other tasks. If you don't add any tasks to this **series**, the server will reply after the **process** ends. Please note that you should not wait for the completion of any task in the **process**. Add this task to the **series** instead.

### How to implement the server reply after waiting for a short time?

It is incorrect to sleep directly in the **process**. The correct way is to add a **timer** task to the series of the server task. Take the HTTP server as an example:

~~~cpp
void process(WFHttpTask *server_task)
{
    WFTimerTask *timer = WFTaskFactory::create_timer_task(100000, nullptr);
    server_task->get_resp()->append_output_body("hello");
    series_of(server_task)->push_back(timer);
}
~~~

The above code implements an HTTP server with 100ms delay. Everything is executed asynchronously, and no thread is occupied during the waiting process.

### How do I know if the reply is successful?

First of all, a successful reply means successfully written data into the TCP buffer. If the reply packet is small and the client does not close the connection after timeout or due to other reasons, you can almost consider that the reply is successful. To view the reply results, you can set a callback for the server task. The status code and error code in the callback are the same as those of the client task, but the server task will not have DNS errors.

### Can I cancel the reply?

Yes. You can call the **noreply()** method of a server task at any time, and then the connection will be closed directly at the original reply time.

### What are the scheduling rules for computing tasks?

For all computing tasks, including **WFGoTask**, you should specify a computing queue name when you create such tasks. The computing queue name is used to guide our internal scheduling strategy. First, as long as there are idle computing threads available, the task will be started in real time, and the computing queue name will not be used. When there are not enough computing threads for calling every task in real time, the tasks under the same queue name will be called in FIFO order, and the queues are treated equally. For example, if you start n tasks with queue name A consecutively, and then start n tasks with queue name B consecutively, then no matter how much CPU time each task takes, and no matter how many computing threads are required, the execution of these two queues tends to complete at the same time. This rule can be extended to any number of queues and any startup orders of these queues.

### Why there is not necessary to establish a connection before using Redis client?

Let's take a look at the interface for creating a Redis client task first:

~~~cpp
class WFTaskFactory
{
public:
    WFRedisTask *create_redis_task(const std::string& url, int retry_max, redis_callback_t callback);
}
~~~

The format of the url is **redis://:password@host:port/dbnum**. The default port is **6379** and the default dbnum is **0**. 
An important feature of the **Workflow** is that the connection is managed by the framework, so that the user interface can be extremely simplified and the connection can be reused most effectively. The framework finds a reusable connection by the username, password and dbnum of the task. If the framework cannot find a connection, it will initiate a new connection and perform user login, database selection and other operations. If it is a new host, DNS resolution will be carried out. If an error occurs in the request, a retry may be needed. Each step is asynchronous and transparent. You only need to populate your request and start the task, and then you can get the results in callback. The only thing to note is that every task should be created with a password, because it may be necessary to login at any time. 

We can create MySQL tasks in the same way. However, for the MySQL tasks with transaction requirements, it is necessary to create tasks through the **WFMySQLConnection**. Otherwise, we cannot guarantee that the whole transaction is executed on the same connection. With **WFMySQLConnection**, the connection and authentication process can also be done asynchronously.

### What are the connection multiplexing rules?

In most cases, you cannot specify specific connections for the client tasks generated in the framework. The framework defines the following multiplexing strategies for such connections:
* If the idle connections on the same port meet the requirements, select the last released one. In other words, FILO is used for reusing idle connections.
* If the idle connections on the same port cannot meet the requirements:
  * If the current number of concurrent connections is less than the maximum value (200 by default), start a new connection immediately.
  * If the number of concurrent connections has reached the maximum value, the task will get a system error **EAGAIN**.
* Not all connections on the same destination address and port meet the multiplexing conditions. For example, the database connections created with different user names or passwords cannot be reused.

Although our framework does not support to specify the connection to be used by a task, it support to specify connection context. This function is very important for implementing a stateful server. 

### Is there load balancing if there are multiple IP addresses under the same domain name?

Yes. In the framework, we think that all target IPs under the same domain name are equal and have the same service capabilities. Therefore, the framework will find a target with the lightest local load to handle the request, and it also has built-in fuse and recovery strategy. For load balancing under the same domain name, all targets must serve on the same port, and you cannot configure different weights. The priority of load balance is higher than connection multiplexing. In other words, the communication address will be selected first, and then the connection reuse will be considered.

### How to realize load balancing or weighted selecting on different ports

Please read **Upstream** documentation. **Upstream** can be used to meet many complex service management requirements.

### How to access chunked HTTP body most efficiently

In many cases, we use **HttpMessage::get\_parsed\_body()** to get the HTTP body. However, to ensure efficiency, the framework does not automatically decode chunked message for users, but returns the original body instead. You can use **HttpChunkCursor** to decode the chunked message. For example:

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

The **cursor.next** operation returns the pointer indicating the starting position and the chunk size of one chunk each time, and does not copy the memory. Before you use **HttpChunkCursor**, it is not necessary to check whether the message is chunked or not, because non-chunked message can also be handled as one chunk.

### Can I wait for the completion of a task synchronously in the callback or the process?

We don't recommend such practice, because you can add any task into the **SeriesWork**, without occupying the thread for waiting. If you must do it, you can use the **WFFuture** in the framework. Please don't use **std::future** directly, because the callback and the process of all our communications are completed in a group of threads, and **std::future** may causes all threads to fall into the waiting status and produces overall deadlock. **WFFuture** solves this problem by dynamically adding threads. When you use **WFFuture**, please note that the data to be kept (usually resp) should be moved to the result with **std::move**. Otherwise, the data will be destroyed along with the task after the callback.

### How to transfer data between tasks?

Ordinarily the tasks in the same series share the series context. You can read and modify it with **get\_context()** and **set\_context()** for the series. For ParallelWork, you can access one speficic series with **series\_at()** in the callback of that ParallelWork(even if the callbacks of these series have been called, they will not be destroyed until the callback of the ParallelWork is completed), and then get its context. The ParallelWork is also one type of task. Therefore, you can pass the summarized results continuously through its series context. In a word, a series is a coroutine, and the series context is a local variable of that coroutine. ParallelWork is the parallel execution of the coroutines, which can summarize the execution results of all coroutines.

### What’s the relationship between the Workflow and RPC?

In our architecture, RPC is an application on Workflow. In other words, RPC is a set of protocol implementations on Workflow. If you have interface description and want to use remote interface calls, you should try **srpc**. **srpc** is an RPC system that leverages all the functions of Workflow and perfectly integrates with Workflow. It is compatible with **brpc** and **thrift** protocols, and it is faster and easier to use. **srpc** can meet any RPC requirements. Please visit [https://github.com/sogou/srpc](https://github.com/sogou/srpc) for details.

### When does server's stop() operation finish?

The **stop()** operation of a server performs a graceful shutdown, and all servers must be shut down before the program ends. **stop()** consists of **shutdown()** and **wait\_finish()**. **wait\_finish()** will wait for the completion of the series that has running server tasks. In other words, you can continue to add tasks to the series in the callback where that server task report its completion. **stop()** operation will wait for the end of these tasks. In addition, if you run multiple servers at the same time, the best way to stop them is:

~~~cpp
int main()
{
    // A server cannot be started multiple times. You must define multiple servers if you want to provide the same services on multiple ports
    WFRedisServer server1(process);
    WFRedisServer server2(process);
    server1.start(8080);
    server2.start(8888);
    getchar(); // Press Enter to continue
    // Shutdown all and then wait
    server1.shutdown();
    server2.shutdown();
    server1.wait_finish();
    server2.wait_finish();
    return 0;
}
~~~

### How to stop the server when a specific request is received?

Because the shutdown of a server is composed of **shutdown()** and **wait\_finish()**, it is obvious that you can run shutdown in the **process** and run **wait\_finish** in **main()**, for example:

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

The above code implements an HTTP server, which ends the program when receiving the request of **/stop**. The flag in the process is required, because the process is executed concurrently, and only one thread can call the **shutdown** operation.

### What should I do if I want to call asynchronous operation of the non-Workflow framework in the server?

You can also use **counter**. In the callbacks of other asynchronous frameworks, count the **counter**.

~~~cpp
void other_callback(server_task, counter, ...)
{
    server_task->get_resp()->append_output_body(result);
    counter->count();
}

void process(WFHttpTask *server_task)
{
    WFCounterTask *counter = WFTaskFactory::create_counter_task(1, nullptr);
    OtherAsyncTask *other_task = create_other_task(other_callback, server_task, counter);//tasks in non-workflow frameworks
    other_task->run();
    series_of(server_task)->push_back(counter);
}
~~~

Note that in the above code the call of **counter->count()** may be started before the start of the **counter**. But no matter what time sequence is used, the program is completely correct.

### Why do I fail to crawl some individual https sites?

If you can access the site with a browser and you fail to crawl it with Workflow, it is very likely that the site uses SNI, a TLS extension. You can enable the client SNI in the Workflow in the global configuration:

~~~cpp
    struct WFGlobalSettings settings = GLOBAL_SETTINGS_DEFAULT;
    settings.endpoint_params.use_tls_sni = true;
    WORKFLOW_library_init(&settings);
~~~

There is a certain price when you enable this function. SNL will be enabled for all HTTPS sites, and you cannot reuse SSL connections when you access the site on the same IP address but with different domain names. To solve the problem, you can only enable the SNI function for a certain domain name through the **upstream** feature:

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

The above code sets www.sogou.com as the **upstream** name, adds a server with the same name, and enables the SNI function at the same time.

### How to access HTTP resources through a proxy server

Method 1 (only applicable to HTTP tasks and unable to redirect): you can create HTTP tasks with the address of the proxy server and set up the **request\_uri** and **Host** headers. For example, if you want to visit http://www.sogou.com/ through the proxy server www.proxy.com:8080 the method is described as follows:

~~~cpp
task = WFTaskFactory::create_http_task("http://www.proxy.com:8080", 0, 0, callback);
task->set_request_uri("http://www.sogou.com/");
task->set_header_pair("Host", "www.sogou.com");
~~~

Method 2 (universal): you can create HTTP tasks through the **proxy\_url** interface:

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

The format of a **proxy\_url** is http://user:passwd@your.proxy.com:port/. The proxy can only start with "http://", not "https://". The default port is 80. This method is applicable to both HTTP and HTTPS proxies, and it supports redirect. The redirect will continue to use the proxy server.
