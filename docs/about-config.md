# 关于全局配置

全局配置用于配置全局默认参数，以适应的实际业务需求，提升程序性能。
全局配置的修改必须在使用框架任何调用之前，否则修改可能无法生效。
另外，一些全局配置选项，可以被upstream配置覆盖。这部分请参考upstream相关文档。

# 修改默认配置

在[WFGlobal.h](../src/manager/WFGlobal.h)里，包含了全局配置的结构体与默认值：
~~~cpp
struct WFGlobalSettings
{
    struct EndpointParams endpoint_params;
    unsigned int dns_ttl_default;   ///< in seconds, DNS TTL when network request success
    unsigned int dns_ttl_min;       ///< in seconds, DNS TTL when network request fail
    int dns_threads;
    int poller_threads;
    int handler_threads;
    int compute_threads;            ///< auto-set by system CPU number if value<=0
};


static constexpr struct WFGlobalSettings GLOBAL_SETTINGS_DEFAULT =
{
    .endpoint_params    =   ENDPOINT_PARAMS_DEFAULT,
    .dns_ttl_default    =   12 * 3600,
    .dns_ttl_min        =   180,
    .dns_threads        =   4,
    .poller_threads     =   4,
    .handler_threads    =   20,
    .compute_threads    =   -1,
};
~~~

其中EndpointParams结构体和默认值在[EndpointParams.h](../src/manager/EndpointParams.h)文件里：

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

举个例子，把默认的连接超时改为5秒，dns默认ttl改为1小时，用于消息反序列化的poller线程增加到10个：

~~~cpp
#include "workflow/WFGlobal.h"

int main()
{
    struct WFGlobalSettings settings = GLOBAL_SETTINGS_DEFAULT;

    settings.endpoint_params.connect_timeout = 5 * 1000;
    settings.dns_ttl_default = 3600;
    settings.poller_threads = 10;
    WORKFLOW_library_init(&settings);

    ...
}
~~~

大多数参数的意义都比较清晰。注意dns ttl相关参数，单位是**秒**。endpoint相关超时参数单位是**毫秒**，并且可以用-1表示无限。  
dns_threads表示并行访问dns的线程数。目前我们dns是通过系统函数getaddrinfo访问的。如果对dns并发性能有需求，可增加这个值。  
compute_threads表示用于计算的线程数，默认-1代表与当前节点CPU核数相同。  

与网络性能相关的两个参数为poller_threads和handler_threads：
* poller线程主要负责epoll（kqueue）和消息反序列化。
* handler线程是网络任务callback和process所在线程。

所有框架需要的资源，都是在第一次被使用时才申请的。例如用户没有用到dns解析，那么dns线程不会被启动。  
