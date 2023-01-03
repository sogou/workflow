# About timeout

In order to make all communication tasks run as accurately as expected by users, the framework provides a large number of timeout configuration functions and ensure the accuracy of these timeouts.   
Some of these timeout configurations are global, such as connection timeout, but you may configure your own connection timeout for a perticular domain name through the upstream.
Some timeouts are task-level, such as sending a message completely, because users needs to dynamically configure this value according to the message size.   
Of course, a server may have its own overall timeout configuration. In a word, timeout is a complicated matter, and the framework will do it accurately.   
All timeouts are in **poll** style. It is an **int** in milliseconds and -1 means infinite.   
In addition, as said in the project introduction, you can ignore all the configurations, and adjust them when you meet the actual requirements.

### Timeout configuration for basic communication

[EndpointParams.h](/src/manager/EndpointParams.h) contains the following items:

~~~cpp
struct EndpointParams
{
    size_t max_connections;
    int connect_timeout;
    int response_timeout;
    int ssl_connect_timeout;
};

static constexpr struct EndpointParams ENDPOINT_PARAMS_DEFAULT =
{
    .max_connections        = 200,
    .connect_timeout        = 10 * 1000,
    .response_timeout       = 10 * 1000,
    .ssl_connect_timeout    = 10 * 1000,
};
~~~

in which there are three DNS-related configuration items. Please ignore them right now. Items related to timeout:  

* connect\_timeout: timeout for establishing a connection with the target. The default value is 10 seconds.
* response\_timeout: timeout for waiting for the target response; the default value is 10 seconds. It is the timeout for sending a block of data to the target or reading a block of data from the target.
* ssl\_connect\_timeout: timeout for completing SSL handshakes with the target. The default value is 10 seconds.

This struct is the most basic configuration for  the communication connection, and almost all subsequent communication configurations contain this struct.

### Global timeout configuration

You can see the global settings in [WFGlobal.h](/src/manager/WFGlobal.h).

~~~cpp
struct WFGlobalSettings
{
    EndpointParams endpoint_params;
    unsigned int dns_ttl_default;
    unsigned int dns_ttl_min;
    int dns_threads;
    int poller_threads;
    int handler_threads;
    int compute_threads;
};

static constexpr struct WFGlobalSettings GLOBAL_SETTINGS_DEFAULT =
{
    .endpoint_params    =    ENDPOINT_PARAMS_DEFAULT,
    .dns_ttl_default    =    12 * 3600,    /* in seconds */
    .dns_ttl_min        =    180,          /* reacquire when communication error */
    .dns_threads        =    8,
    .poller_threads     =    2,
    .handler_threads    =    20,
    .compute_threads    =    -1
};
//compute_threads<=0 means auto-set by system cpu number
~~~

in which there is one timeout related configuration item: EndpointParams endpoint\_params

You can perform operations like the following to change the global configuration before calling any of our factory functions:

~~~cpp
int main()
{
    struct WFGlobalSettings settings = GLOBAL_SETTINGS_DEFAULT;
    settings.endpoint_params.connect_timeout = 2 * 1000;
    settings.endpoint_params.response_timeout = -1;
    WORKFLOW_library_init(&settings);
}
~~~

The above example changes the connection timeout to 2 seconds, and the server response timeout is infinite. In this configuration, the timeout for receiving complete messages must be configured in each task, otherwise it may fall into infinite waiting.   
The global configuration can be overridden by the configuration for an individual address in the upstream feature. For example, you can specify a connection timeout for a specific domain name.   
In Upstream, each AddressParams also has the EndpointParams endpoint\_params item, and you can configure it in the same way as you configure the Global item.   
For the detailed structures, please see [upstream documents.](/docs/en/tutorial-10-upstream.md#Address)

### Configuring server timeout

The [http\_proxy](/docs/en/tutorial-05-http_proxy.md) example demonstrates the server startup configuration. In which the timeout-related configuration items include:

* peer\_response\_timeout: its definition is the same as the global peer\_response\_timeout, which indicates the response timeout of the remote client, and the default value is 10 seconds.
* receive\_timeout: timeout for receiving a complete request. The default value is -1.
* keep\_alive\_timeout: timeout for keeping a connection. The default value is 1 minute. For a Redis server, the default value is 5 minutes.
* ssl\_accept\_timeout: timeout for completing SSL handshakes. The default value is 10 seconds.

Under this default configuration, the client can send one byte every 9 seconds, so that the server can always receive it and no timeout occurs. Therefore, if the service is used for public network, you need to configure receive\_timeout.

### Configuring task-level timeout

Task-level timeout configuration is accomplished through calling several interfaces in a network task:

~~~cpp
template <class REQ, class RESP>
class WFNetworkTask : public CommRequest
{
...
public:
    /* All in milliseconds. timeout == -1 for unlimited. */
    void set_send_timeout(int timeout) { this->send_timeo = timeout; }
    void set_receive_timeout(int timeout) { this->receive_timeo = timeout; }
    void set_keep_alive(int timeout) { this->keep_alive_timeo = timeout; }
...
}
~~~

In the above code, **set\_send\_timeout()** sets the timeout for sending a complete message, and the default value is -1.   
**set\_receive\_timeout()** is only valid for the client task, and it indicates the timeout for receiving a complete server reply. The default value is -1.

  * The receive\_timeout of a server task is in the server startup configuration. All server tasks handled by users have successfully received complete requests.

**set\_keep\_alive()** interface sets the timeout for keeping a connection. Generally, the framework can handle the connection maintenance well, and you do not need to call it.   
When an HTTP protocol is used, if a client or a server wants to use short connection, you can add an HTTP header to support it. Please do not modify it with this interface if you have other options.   
If a Redis client wants to close the connection after a request, you need to use this interface. Obviously, **set\_keep\_alive()** is invalid in the callback (the connection has been reused).

### Timeout for synchronous task waiting 

There is a very special timeout configuration, and it is the only global synchronous waiting timeout. It is not recommended,  but you can get good results with it in some application scenarios.   
In the current framework, the target server has a connection limit (you can set it in both global and upstream configurations). If the number of connections have  reached the upper limit,  the client task fails and returns an error by default.   
In the callback, **task->get\_state ()** gets WFT\_STATE\_SYS\_ERROR, and **task->get\_error()** gets EAGAIN. If the task is configured with retry, a retry will be automatically initiated.   
Here, it is allowed to configure a synchronous waiting timeout through the **task->set\_wait\_timeout()** interface. If a connection is released during this time period, the task can occupy this connection.   
If you sets wait\_timeout and does not get the connection before the timeout, the callback will get WFT\_STATE\_SYS\_ERROR status and ETIMEDOUT error.

~~~cpp
class CommRequest : public SubTask, public CommSession
{
public:
    ...
    void set_wait_timeout(int wait_timeout) { this->wait_timeout = wait_timeout; }
}
~~~

### Viewing the reasons for timeout

Communication tasks contain a **get\_timeout\_reason()** interface, which is used to return the timeout reason, but the reason is not very detailed. It includes the following return values:

* TOR\_NOT\_TIMEOUT: not a timeout.
* TOR\_WAIT\_TIMEOUT: timed out for synchronous waiting
* TOR\_CONNECT\_TIMEOUT: connection timed out. The connections on TCP, SCTP, SSL and other protocols all use this timeout.
* TOR\_TRANSMIT\_TIMEOUT: timed out for all transmissions. It is impossible to further distinguish whether it is in the sending stage or in the receiving stage. It may be refined later.
  * For a server task, if the timeout reason is TRANSMIT\_TIMEOUT, it must be in the stage of sending replies.

### Implementation of timeout functions

Within the framework, there are more types of timeouts than those we show here. Except for wait\_timeout, all of them depend on the timer\_fd on Linux or kqueue timer on BSD system, one for each poller thread.   
By default, the number of poller threads is 4, which can meet the requirements of most applications.   
The current timeout algorithm uses the data structure of linked list and red-black tree. Its time complexity is between O(1) and O(logn), where n is the fd number of the a poller thread.   
Currently timeout processing is not the bottleneck, because the time complexity of related calls of epoll in Linux kernel is also O(logn). If the time complexity of all timeouts in our framework reaches O(1), there is no much difference.
