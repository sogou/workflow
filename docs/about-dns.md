# 关于DNS

DNS(域名服务协议)是一种分布式网络目录服务，主要用于域名与IP地址的相互转换。  
在进行通信访问的时候，需要对非IP的域名进行DNS解析，这个过程就是域名到IP地址的转换过程。  
DNS解析是一个比较大的消耗，不管是服务器还是本地操作系统，通常都会有自己的DNS Cache负责减少不必要的请求。  
有一些程序也会在自己的进程内设计自己的DNS Cache，包括常见流行的浏览器、通信框架等。
workflow也设计了自己的DNS Cache，为了方便用户使用，DNS这部分功能被框架完全接管“隐藏”了起来。

### TTL

全称是“生存时间（Time To Live)”，简单的说TTL表示DNS记录在DNS Cache上缓存的时间。

### 框架的DNS方法

#### 同步请求
通过调用系统函数getaddrinfo获取结果，一些细节：
1. 当命中框架自己的DNS Cache且TTL有效时，DNS解析不会发生。
2. 当域名是ipv4、ipv6、unix-domain-socket，DNS解析不会发生。
3. DNS解析是一个特殊的计算任务,被封装成了一个WFThreadTask。
4. DNS解析使用的是一个完全独立隔离的线程池，即不占用计算线程池、也不占用通信线程池。

#### 异步请求
框架实现了完备的DNS协议解析，在Unix系统下默认将默认使用框架内置的DNS解析器，不会创建DNS线程池。  
如需想恢复为多线程dns解析，需要在全局配置里将resolv_conf_path参数设置为NULL。

### 全局DNS配置

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
    const char *resolv_conf_path;
    const char *hosts_path;
};

static constexpr struct WFGlobalSettings GLOBAL_SETTING_DEFAULT =
{
    .endpoint_params    =    ENDPOINT_PARAMS_DEFAULT,
    .dns_server_params	=    ENDPOINT_PARAMS_DEFAULT,
    .dns_ttl_default    =    12 * 3600,  /* in seconds */
    .dns_ttl_min        =    180,        /* reacquire when communication error */
    .dns_threads        =    4,
    .poller_threads     =    4,
    .handler_threads    =    20,
    .compute_threads    =    -1,
    .resolv_conf_path   =    "/etc/resolv.conf",
    .hosts_path         =    "/etc/hosts",
};
~~~
其中，与DNS相关的配置包括：
  * dns_server_params：对dns服务器的最大并发数，超时等配置。
  * dns_threads: DNS线程池线程数，默认4。只有当resolv_conf_path配置为空时，这个参数才会起作用。否则我们并不会创建dns线程。
  * dns_ttl_default: DNS Cache中默认的TTL，单位秒，默认12小时，dns cache是当前进程的，即进程退出就会消失，配置也仅对当前进程有效。
  * dns_ttl_min: dns最短生效时间，单位秒，默认3分钟，用于通信失败重试是否尝试重新dns的决策。
  * resolv_conf_path: resolv.conf配置文件路径，为NULL表示使用多线程DNS解析。
  * hosts_path: hosts配置文件路径。可以为NULL。

简单来讲，每次通信都会检查TTL来决定要不要重新进行DNS解析。  
默认检查dns_ttl_default，通信失败重试时才会去检查dns_ttl_min。

全局的DNS配置，可以通过upstream功能，被单独的地址配置覆盖。  
Upstream每一个AddressParams也有dns_ttl_default和dns_ttl_min配置项，使用方式与Global相仿。  
具体结构详见[upstream文档](./about-upstream.md#Address属性)。

## SSL DNS (DoT)的支持
我们的主分支代码（不包括windows分支）支持通过SSL连接访问DNS服务器，即DoT。  
我们简单的扩展了**resolv.conf**的格式，你可以通过以下方式加入一个SSL dns server:
~~~bash
nameserver dnss://8.8.8.8/
~~~
我们用**dnss://** 来表示一个SSL dns server地址。通过以上的配置，我们所有的DNS请求都将通过SSL连接与全球DNS server 8.8.8.8通信。  
全球DNS server完美支持SSL连接，大家可以立刻试用一下这个功能。  
为了不用修改系统的**resolv.conf**文件，你可能需要创建一个私有的**resolv.conf**，并修改workflow配置：
~~~cpp
#include <workflow/WFGlobal.h>
#include <workflow/WFTaskFactory.h>

int main()
{
    struct WFGlobalSettings settings = GLOBAL_SETTINGS_DEFAULT;
    settings.resolv_conf_path = "./myresolv.conf";
    WORKFLOW_library_init(&settings);

    WFHttpTask *task = WFTaskFactory::create_http_task("https://www.example.com", ...);
	...
}
~~~

### DNS解析策略与DNS cache过期策略
* 同一个域名，同时只会发送一个DNS请求，这是通过一种异步锁机制实现的。
  * 只有一种例外，两个不同的upstream指向同一个域名，但分别要求只用IPv4和只用IPv6，可能会同时发起两个请求。
* 对DNS server的最大并发，受dns_server_params.max_connections控制，默认为200。
* 某个域名DNS cache过期一瞬间，如果多个请求同时需要请求该域名，会有一个任务重新发起DNS请求，并把原cache有效期临时延长5秒，尽量减少DNS cache过期引起的访问中断。
