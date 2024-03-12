# 关于DNS
当使用域名请求网络时，首先需要通过域名解析获取服务器地址，再使用网络地址进行后续的请求。Workflow已经实现了完备的域名解析和缓存系统，通常来说用户无需知晓内部机制即可流畅地发起网络任务。

## DNS相关配置
Workflow中的全局配置包括

~~~cpp
struct WFGlobalSettings
{
    struct EndpointParams endpoint_params;
    struct EndpointParams dns_server_params;
    unsigned int dns_ttl_default;
    unsigned int dns_ttl_min;
    int dns_threads;
    int poller_threads;
    int handler_threads;
    int compute_threads;
    int fio_max_events;
    const char *resolv_conf_path;
    const char *hosts_path;
};
~~~

其中与域名解析相关的配置项有

* dns_server_params
  * address_family: 该项会在后续展开说明
  * max_connections: 向DNS服务器发送请求的最大并发数，默认为200
  * connect_timeout/response_timeout/ssl_connect_timeout: 参考[超时](about-timeout.md)相关说明
* dns_threads: 当使用同步方式实现域名解析时，解析操作会在独立的线程池中执行，该项指定线程池的线程数，默认为4
* dns_ttl_default: 域名解析成功的结果会被放到域名缓存中，该项指定其存活时间，单位为秒，默认值1小时，当解析结果过期后会重新解析以获取最新内容
* dns_ttl_min: 当通信失败时，有可能出现缓存的结果已经失效的情况，该项指定一个较短的存活时间，当通信失败时以更频繁的速率更新缓存，单位为秒，默认值1分钟
* resolv_conf_path: 该文件保存了访问DNS相关的配置，在常见的Linux发行版上通常位于`/etc/resolv.conf`，若该项配置为`NULL`则表示使用多线程同步解析的模式
* hosts_path: 该文件是一个本地的域名查找表，若被解析的域名命中该表则不会向DNS发起请求，在常见的Linux发行版上通常位于`/etc/hosts`，若该项配置为`NULL`则表示不使用查找表

### resolv.conf扩展功能
Workflow对`resolv.conf`配置文件进行了扩展，用户可以通过修改配置以支持`DNS over TLS(DoT)`功能，**注意**直接修改`/etc/resolv.conf`会影响其他进程，可以将该文件复制一份用于修改，并将Workflow的`resolv_conf_path`配置修改为新文件的路径。例如使用`dnss`协议的`nameserver`会通过SSL进行连接

~~~bash
nameserver dnss://8.8.8.8/
nameserver dnss://[2001:4860:4860::8888]/
~~~

### Address Family
在某些网络环境下，虽然本机支持IPv6，但因未被分配公网IPv6地址而无法与外部通信（例如本地IPv6地址以`fe80`开始）。此时可以将`endpoint_params.address_family`设置为`AF_INET`来强制域名解析时仅解析IPv4地址。同样的，`resolv.conf`文件中可能同时指定了`nameserver`的IPv4地址和IPv6地址，此时可以将`dns_server_params.address_family`设置为`AF_INET`或`AF_INET6`来强制仅使用IPv4或IPv6地址来访问DNS。

### 使用Upstream配置
全局配置默认对每个域名生效，若需要对某些域名单独指定不同的配置，则可使用[Upstream](./about-upstream.md#Address属性)功能。使用Upstream可以单独指定`dns_ttl_default`、`dns_ttl_min`配置项，以及通过`endpoint_params.address_family`单独指定该域名使用的IP地址类别。


## 域名解析与缓存策略
网络任务通常需要通过域名解析获取到需要访问的IP地址，Workflow中域名解析相关策略如下

1. 检查域名缓存是否有该域名对应的IP地址，若有缓存且未过期，则使用该组IP地址
2. 检查域名是否为IPv4、IPv6地址或`Unix Domain Socket`，若是则直接使用该地址，无需发起域名解析
3. 检查`hosts_path`文件中是否包含该域名对应的IP地址，若有则直接使用该地址
4. 获取异步锁，保证同一域名的解析请求在同一时刻仅发起一次，并向DNS发起解析请求
5. 解析成功后会将解析结果保存到当前进程的域名缓存中，以供下次使用，并释放异步锁
6. 解析失败后会释放异步锁且将失败原因通知给等在同一个异步锁上的所有任务，通知结束后再发起的新的任务则会再次请求DNS

许多需要大量发起网络请求的场景都会配备域名缓存组件，如果每次发起网络任务时都向DNS发起解析请求，则DNS必然会不堪重负。Workflow设置了缓存存活时长（dns_ttl_default和dns_ttl_min）来保证缓存会在合理的时间后过期，以及时更新域名的解析结果。当某个域名的缓存项过期后，首先发现过期的任务会将其存活时间延长5秒并向DNS发起解析请求，5秒内同一域名上的请求会直接使用缓存的DNS解析结果，而无需等待本次解析结束。

异步锁机制可以保证**同一域名**的解析请求在同一时刻仅发起一次，在没有锁保护的情况下，若短时间内对同一域名发起大量网络任务，每个任务都会因无法从缓存中获取结果而向DNS发起解析请求，这会对DNS带来很大且不必要的负担。这里的同一域名表示的是`(host, port, family)`三元组，若通过Upstream的方式对某域名分别要求只使用IPv4和IPv6，则他们会被不同的异步锁保护，也就有可能同时发起DNS请求。


### 异步域名解析
Workflow实现了完备的DNS任务（参考[dns_cli](./tutorial-17-dns_cli.md)），若指定了`resolv_conf_path`配置项，则向DNS发起域名解析时会使用异步请求的方式进行，在类Unix系统下，Workflow默认使用`/etc/resolv.conf`作为该配置的值。异步域名解析不会阻塞任何线程，也不会独占线程池，可以更高效地完成域名解析的任务。

### 同步域名解析
若指定`resolv_conf_path`为`NULL`，则会通过调用`getaddrinfo`函数来实现同步域名解析，该方式会使用独立的线程池，其线程数通过`dns_threads`参数配置。若短时间内需要发起较多的域名解析请求，则同步的方式会带来较大的延迟。
