# About global configuration

Global configuration is used to configure default global parameters to meet the actual business requirements and improve performance. The change of the global configuration must be made before you call any intefaces in the framework. Otherwise the change may not take effect. In addition, some global configuration items can be overridden in the upstream configuration. Please see upstream documents for reference.

# Changing default configuration

[WFGlobal.h](/src/manager/WFGlobal.h) defines the struts and the default values of the global configuration.

~~~cpp
struct WFGlobalSettings
{
    struct EndpointParams endpoint_params;
    struct EndpointParams dns_server_params;
    unsigned int dns_ttl_default;   ///< in seconds, DNS TTL when network request success
    unsigned int dns_ttl_min;       ///< in seconds, DNS TTL when network request fail
    int dns_threads;
    int poller_threads;
    int handler_threads;
    int compute_threads;            ///< auto-set by system CPU number if value<=0
    int fio_max_events;
    const char *resolv_conf_path;
    const char *hosts_path;
};


static constexpr struct WFGlobalSettings GLOBAL_SETTINGS_DEFAULT =
{
    .endpoint_params    =   ENDPOINT_PARAMS_DEFAULT,
    .dns_server_params  =   ENDPOINT_PARAMS_DEFAULT,
    .dns_ttl_default    =   12 * 3600,
    .dns_ttl_min        =   180,
    .dns_threads        =   4,
    .poller_threads     =   4,
    .handler_threads    =   20,
    .compute_threads    =   -1,
	.fio_max_events     =   4096,
    .resolv_conf_path   =   "/etc/resolv.conf",
    .hosts_path         =   "/etc/hosts",
};
~~~

[EndpointParams.h](/src/manager/EndpointParams.h) defines the struture of EndpointParams and the default values.

~~~cpp

struct EndpointParams
{
    size_t max_connections;
    int connect_timeout;
    int response_timeout;
    int ssl_connect_timeout;
    bool use_tls_sni;
};

static constexpr struct EndpointParams ENDPOINT_PARAMS_DEFAULT =
{
    .max_connections        = 200,
    .connect_timeout        = 10 * 1000,
    .response_timeout       = 10 * 1000,
    .ssl_connect_timeout    = 10 * 1000,
    .use_tls_sni            = false,
};
~~~

If you want to change the default connecting timeout to 5 seconds, the default TTL for DNS to 1 hour and increase the number of poller threads for message deserialization to 10, you can follow the example below:

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

Most of the parameters are self-explanatory. Note: the ttl and related parameters in DNS configuration are in **seconds**. The timeout for endpoint is in **milliseconds**, and -1 indicates an infinite timeout.   
dns\_threads indicates the total number of threads accessing DNS in parallel, but by default, we use asynchronous DNS resolving and don't create any dns threads (Except windows platform).  
dns\_server\_params indicates parameters that we access DNS server, including the maximum cocurrent connections, and the DNS server's connecting and response timeout.  
compute\_threads indicates the number of threads used for computation. The default value is -1, meaning the number of threads is the same as the number of CPU cores in the current node.   
fio\_max\_events indicates the maximum number of concurrent asynchronous file IO events.  
resolv\_conf\_path indicates the path of dns resolving configuration file. The default value is "/etc/resolv.conf" on unix platforms and NULL on windows. On the windows platform, we still use multi-threaded dns resolving by default.  
hosts_path indicates the path of the **hosts** file. The default value is "/etc/hosts" on unix platforms. If resolv_conf_path is NULL, this configuration will be ignored.  
poller\_threads and handler\_threads are the two parameters for tuning network performance:

* poller\_threads is mainly used for epoll (kqueue) and message deserialization.
* handler\_threads is the number of threads for the callback and the process of a network task.

All resources required by the framework are applied for when they are used for the first time. For example, if a user task does not involve DNS resolution, the asynchronous DNS resolver or DNS threads will not be created.
