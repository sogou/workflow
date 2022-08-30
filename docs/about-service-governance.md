# 关于服务治理

我们拥有一套完整的机制，来管理我们所依赖的服务。这套机制包括以下的几个功能：
* 用户级DNS。
* 服务地址的选取
  * 包括多种选取机制，如权重随机，一致性哈希，用户指定选取方式等。
* 服务的熔断与恢复。
* 负载均衡。
* 单个服务的独立参数配置。
* 服务的主备关系等。

所有这些功能都依赖于我们的upstream子系统。利用好这个系统，我们可以轻易地实现更复杂的服务网格功能。

# upstream名

upstream名相当于程序内部的域名，但相比一般的域名，upstream拥有更多的功能，包括：
* 域名通常只能指向一组ip地址，upstream名可以指向一组ip地址或域名。
* upstream指向的对象（域名或ip），可以包括端口信息。
* upstream有管理和选择目标的强大功能，每个目标可以包含大量属性。
* upstream的更新，是实时而且完全线程安全的，而域名的DNS信息，并不能实时更新。

实现上，如果无需访问外网，用upstream可以完全代替域名和DNS。

# upstream的创建与删除

在[UpstreamManager.h](../src/manager/UpstreamManager.h)里，包括几个upstream创建接口：
~~~cpp
using upstream_route_t = std::function<unsigned int (const char *, const char *, const char *)>;

class UpstreamManager
{
public:
    static int upstream_create_consistent_hash(const std::string& name,
                                               upstream_route_t consitent_hash);

    static int upstream_create_weighted_random(const std::string& name,
                                               bool try_another);

    static int upstream_create_manual(const std::string& name,
                                      upstream_route_t select,
                                      bool try_another,
                                      upstream_route_t consitent_hash);

    static int upstream_delete(const std::string& name);
    ...
};
~~~
三个函数创建分别为3种类型的upstream：一致性hash，权重随机和用户手动选取。  
参数name为upstream名，创建之后，就和域名一样的使用了。  
consistent_hash和select参数，都是一个类型为upstream_route_t的std::function，用于指定路由方式。  
而try_another表示，如果选取到的目标不可用（熔断），是否继续尝试找到一个可用目标。consistent_hash模式没有这个属性。  
upstream_route_t参数接收的3个参数分别是url里的path, query和fragment部分。例如URL为：http://abc.com/home/index.html?a=1#bottom  
则这三个参数分别为"/home/index.html", "a=1"和"bottom"。用户可以根据这三个部分，选择目标服务器，或者进行一致性hash。  
注意，以上接口中，consistent_hash参数都可以传nullptr，我们将使用默认的一致性哈希算法。  

# 示例1：权重分配

我们想把50%访问www.sogou.com的请求，打到127.0.0.1:8000和127.0.0.1:8080两个地址，并且让他们的负载为1:4。  
我们无需要关心域名www.sogou.com之下，有多少个ip地址。总之实际域名会接收50%的请求。
~~~cpp
#include "workflow/UpstreamManager.h"
#include "workflow/WFTaskFactory.h"

int main()
{
    UpstreamManager::upstream_create_weighted_random("www.sogou.com", false);
    struct AddressParams params = ADDRESS_PARAMS_DEFAULT;

    params.weight = 5;
    UpstreamManager::upstream_add_server("www.sogou.com", "www.sogou.com", &params);
    params.weight = 1;
    UpstreamManager::upstream_add_server("www.sogou.com", "127.0.0.1:8000", &params);
    params.weight = 4;
    UpstreamManager::upstream_add_server("www.sogou.com", "127.0.0.1:8080", &params);

    WFHttpTask *task = WFTaskFactory::create_http_task("http://www.sogou.com/index.html", ...);
    ...
}
~~~
请注意，以上这些函数可以在任何场景下调用，完全线程安全，并实时生效。  
另外，由于我们一切协议，包括用户自定义协议都有URL，所以upstream功能可作用于一切协议。

# 示例2：手动选择

同样是上面的例子，我们想让url里，query为"123"的请求，打到127.0.0.1:8000，如果是"abc"，打到8080端口，其它打正常域名。  
~~~cpp
#include "workflow/UpstreamManager.h"
#include "workflow/WFTaskFactory.h"

int my_select(const char *path, const char *query, const char *fragment)
{
    if (strcmp(query, "123") == 0)
        return 1;
    else if (strcmp(query, "abc") == 0)
        return 2;
    else
        return 0;
}

int main()
{
    UpstreamManager::upstream_create_manual("www.sogou.com", my_select, false, nullptr);

    UpstreamManager::upstream_add_server("www.sogou.com", "www.sogou.com");
    UpstreamManager::upstream_add_server("www.sogou.com", "127.0.0.1:8000");
    UpstreamManager::upstream_add_server("www.sogou.com", "127.0.0.1:8080");

    /* This URL will route to 127.0.0.1:8080 */
    WFHttpTask *task = WFTaskFactory::create_http_task("http://www.sogou.com/index.html?abc", ...);
    ...
}
~~~
由于我们原生提供了redis和mysql协议，用这个方法，可以极其方便的实现数据库的读写分离功能（注：非事务的操作）。  
以上两个例子，upstream名用的是www.sogou.com，这本身也是一个域名。当然用户可以更简单的用字符串sogou，这样创建任务时：
~~~cpp
    WFHttpTask *task = WFTaskFactory::create_http_task("http://sogou/home/1.html?abc", ...);
~~~
总之url的host部分，如果是一个已经创建的upstream，则会被当作upstream使用。  

# 示例3：一致性hash

这个场景里，我们要从10个redis实例中，随机选择一台机器通信。但保证同一个url肯定访问一个确定的目标。方法很简单：
~~~cpp
int main()
{
    UpstreamManager::upstream_create_consistent_hash("redis.name", nullptr);

    UpstreamManager::upstream_add_server("redis.name", "10.135.35.53");
    UpstreamManager::upstream_add_server("redis.name", "10.135.35.54");
    UpstreamManager::upstream_add_server("redis.name", "10.135.35.55");
    ...
    UpstreamManager::upstream_add_server("redis.name", "10.135.35.62");

    auto *task = WFTaskFactory::create_redis_task("redis://:mypassword@redis.name/2?a=hello#111", ...);
    ...
}
~~~
我们的redis任务并不识别query部分，用户可以随意填写。path部分的2为redis库号。  
这个时候，consistent_hash函数将得到"/2"，"a=hello"和"111"三个参数，但因为我们用nullptr，默认一致性hash将被调用。  
upstream里的服务器没有指定端口号，于是将使用url里的端口。redis默认为6379。  
consitent_hash并没有try_another选项，如果目标熔断，将自动选取另一个。相同url还将得到相同选择（cache友好）。  

# upstream server的参数

示例１中，我们通过params参数设置了server的权重。当然server参数远不止权重一项。这个结构定义如下：
~~~cpp
// In EndpointParams.h
struct EndpointParams
{
    size_t max_connections;
    int connect_timeout;
    int response_timeout;
    int ssl_connect_timeout;
    bool use_tls_sni;
};

// In ServiceGovernance.h
struct AddressParams
{
    struct EndpointParams endpoint_params; ///< Connection config
    unsigned int dns_ttl_default;          ///< in seconds, DNS TTL when network request success
    unsigned int dns_ttl_min;              ///< in seconds, DNS TTL when network request fail
/**
 * - The max_fails directive sets the number of consecutive unsuccessful attempts to communicate with the server.
 * - After 30s following the server failure, upstream probe the server with some live client’s requests.
 * - If the probes have been successful, the server is marked as a live one.
 * - If max_fails is set to 1, it means server would out of upstream selection in 30 seconds when failed only once
 */
    unsigned int max_fails;                ///< [1, INT32_MAX] max_fails = 0 means max_fails = 1
    unsigned short weight;                 ///< [1, 65535] weight = 0 means weight = 1. only for main server
    int server_type;                       ///< 0 for main and 1 for backup
    int group_id;                          ///< -1 means no group. Backup without group will backup for any main node
};
~~~
大多数参数的作用一眼了然。其中endpoint_params和dns相关参数，可以覆盖全局的配置。  
例如，全局对每个目标ip最大连接数为200，但我想为10.135.35.53设置最多1000连接数，可以这么做：
~~~cpp
    UpstreamManager::upstream_create_weighted_random("10.135.35.53", false);
    struct AddressParams params = ADDRESS_PARAMS_DEFAULT;
    params.endpoint_params.max_connections = 1000;
    UpstreamManager::upstream_add_server("10.135.35.53", "10.135.35.53", &params);
~~~
max_fails参数为最大出错次数，如果选取目标连续出错达到max_fails则熔断，如果upstream的try_another属性为false，则任务失败，  
在任务callback里，get_state()=WFT_STATE_TASK_ERROR，get_error()=WFT_ERR_UPSTREAM_UNAVAILABLE。  
如果try_another为true，并且所有server都熔断的话，会得到同样错误。熔断时间为30秒。  
server_type和group_id用于主备功能。所有upstream必需有type为0(主节点)的server，否则upstream不可用。  
类型为1（备份节点）的server，会在同group_id的主节点熔断情况下被使用。  

更多upstream功能查询：[about-upstream.md](./about-upstream.md)。
