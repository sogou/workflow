# 关于超时

为了让所有通信任务可以在用户的预期下精确运行，我们提供了大量的超时配置功能，并且确保这些超时的准确性。  
这些超时配置里，有些是全局的，比如连接超时，但你又可以通过upstream功能，给某个域名配置自己的连接超时。  
有一些超时是任务级的，比如完整发送一条消息的超时。因为用户需要根据消息大小，动态配置这个值。  
当然对server来讲，又有自己的超时整体配置。总之，超时是一件很复杂的事，我们会做得很精确。  
所有超时都采用poll风格，也就是int型，毫秒级，-1表示无限。  
另外，正如我们在项目介绍里说的，所有的配置你都可以忽略，可以等遇到实际需求了再进行调整。

### 基础通信超时配置

在[EndpointParams.h](../src/manager/EndpointParams.h)文件里，可以看到：
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
其中，与超时相关的配置包括以下3项。
  * connect_timeout: 与目标建立连接的超时。默认为10秒。
  * response_timeout: 等待目标响应的超时，默认为10秒。代表成功发送到目标、或从目标读取到一块数据的超时。
  * ssl_connect_timeout: 与目标完成SSL握手的超时。默认为10秒。

这个结构体是通信连接的最基础的配置，后续几乎所有的通信配置都会含有这个结构体。

### 全局超时配置

在[WFGlobal.h](../src/manager/WFGlobal.h)文件里，可以看到我们一个全局配置信息：
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
其中，与超时相关的配置就是EndpointParams endpoint_params这一项

修改全局配置的方法是，调用我们任何工厂函数之前，执行类似下面的操作：
~~~cpp
int main()
{
    struct WFGlobalSettings settings = GLOBAL_SETTINGS_DEFAULT;
    settings.endpoint_params.connect_timeout = 2 * 1000;
    settings.endpoint_params.response_timeout = -1;
    WORKFLOW_library_init(&settings);
}
~~~
上例把连接超时修改为2秒，远程服务器响应超时为无限。这种配置下，每次任务里都必须配置接收完整消息的超时，否则可能陷入无限的等待。  
全局的超时配置，可以通过upstream功能，被单独的地址配置覆盖，比如你可以指定某个域名的连接超时。  
Upstream每一个AddressParams也有一个EndpointParams endpoint_params项，使用方式与Global相仿。  
具体结构详见[upstream文档](tutorial-10-upstream.md#Address属性)

### Server超时配置

在[http_proxy](./tutorial-05-http_proxy.md)示例的里，我们介绍过server启动配置。其中超时相关的配置包括：
  * peer_response_timeout: 这个的定义和全局的response_timeout一样，指的是远程client的响应超时，默认为10秒。
  * receive_timeout: 接收一条完整请求的超时，默认为-1。
  * keep_alive_timeout: 连接保持时间。默认1分钟。redis server为5分钟。
  * ssl_accept_timeout: 完成ssl握手的超时，默认为10秒。

在这个默认配置下，client可以每9秒发送一个字节，让server一直接收而不引起超时。所以，如果服务用于公网，需要配置receive_timeout。  

### 任务级别的超时配置

任务级别的超时配置通过网络任务的几个接口调用来完成：
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
    void set_watch_timeout(int timeout) { this->watch_timeo = timeout; }
...
}
~~~
其中，set_send_timeout()设置发送完整消息的超时，默认值为-1。  
set_receive_timeout()只对client任务有效，指接收完整server回复的超时，默认值为-1。  
  * server任务的receive_timeout在server启动配置里。对server任务设置receive_timeout没有意义，因为消息已经接收完成。

set_keep_alive()接口设置连接保持超时。一般来讲，框架能很好的处理连接保持的问题，用户不需要调用。  
如果是http协议，client或server想要使用短连接，可通过添加HTTP header来完成，尽量不要用这个接口去修改。  
如果一个redis client想要在请求之后关闭连接，则需要用这个接口。显然，在callback里set_keep_alive()是无效的（连接已经被复用）。  

set_watch_timeout()接口为client任务专有，代表一个client任务的请求发出之后，接收到第一个返回包的最大等待时间。  
利用watch timeout，可以避免一些需要等待数据推送的client任务受到response timeout和receive timeout的约束而超时。  
设置了watch timeout之后，从接收到第一个数据包再开始计算receive timeout。

### 任务的同步等待超时

有一个非常特殊的超时配置，是全局唯一一个同步等待超时。我们并不鼓励使用，但在某些应用场景下能得到很好的效果。  
目前框架里，目标服务器是有连接上限的（全局和upstream都可以配置）。如果连接已经达到上限，默认的情况下，client任务失败返回。  
callback里task->get_state()得到WFT_STATE_SYS_ERROR, task->get_error()得到EAGAIN。如果任务配置了retry，会自动发起重试。  
在这里，我们允许通过task->set_wait_timeout()接口，配置一个同步等待超时，如果在这段时间内，有连接被释放，则任务可以占用这个连接。  
如果用户配置了wait_timeout，并且在超时之前没有拿到连接，则callback得到WFT_STATE_SYS_ERROR状态和ETIMEDOUT错误。
~~~cpp
class CommRequest : public SubTask, public CommSession
{
public:
    ...
    void set_wait_timeout(int wait_timeout) { this->wait_timeout = wait_timeout; }
}
~~~

### 超时的原因查看

通信task包含一个get_timeout_reason()接口，用于返回超时原因，但不是很细致，包括以下几个返回值：
  * TOR_NOT_TIMEOUT: 不是超时。
  * TOR_WAIT_TIMEOUT: 同步等待超时。
  * TOR_CONNECT_TIMEOUT: 连接超时。包括TCP，SCTP等协议的连接和SSL连接超时，都是这个值。
  * TOR_TRANSMIT_TIMEOUT: 一切传输超时。不能进一步区分是发送阶段还是接收阶段。以后可能会细化。
    * server任务，超时原因一定是TRANSMIT_TIMEOUT，并且一定是发送回复的阶段。

### 超时功能的实现

框架内部，需要处理的超时种类比我们在这里展现的还要更多。除了wait_timeout，全都是依赖于Linux的timerfd或kqueue的timer事件。  
每个poller线程包含一个timerfd，默认配置下，poller线程数为4，可以满足大多数应用的需要了。  
目前的超时算法利用了链表+红黑树的数据结构，时间复杂度在O(1)和O(logn)之间，其中n为poller线程的fd数量。  
超时处理目前看不是瓶颈所在，因为Linux内核epoll相关调用也是O(logn)时间复杂度，我们把超时都做到O(1)也区别不大。
