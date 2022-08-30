# 关于Upstream

在nginx里，Upstream代表了反向代理的负载均衡配置。在这里，我们扩充Upstream的含义，让其具备以下几个特点：
1. 每一个Upstream都是一个独立的反向代理
2. 访问一个Upstream等价于，在一组服务/目标/上下游，使用合适的策略选择其中一个进行访问
3. Upstream具备负载均衡、出错处理、熔断和其他服务治理能力
4. 对于同一个请求的多次重试，Upstream可以避开已试过的目标
5. 通过Upstream可以对不同下游配置不同的连接参数
6. 动态增删目标地址实时生效，方便对接任意的服务发现系统

### Upstream相对于域名DNS解析的优势

Upstream和域名DNS解析都可以将一组ip配置到一个Host，但是
1. DNS域名解析是不针对于端口号的，相同ip不同端口的服务DNS域名是不能配置到一起的；但Upstream可以
2. DNS域名解析对应的一组address，必定是ip；Upstream对应的一组address，可以是ip、域名或unix-domain-socket
3. 通常情况下，DNS域名解析会被操作系统或网络上DNS服务器所缓存，更新时间受到ttl的限制；Upstream可以做到实时更新实时生效
4. DNS域名解析消耗比Upstream解析和选取大很多

### Workflow的Upstream

这是一个本地反向代理模块，代理配置对server和client都生效。  

支持动态配置，可用于服务发现系统，目前[workflow-k8s](https://github.com/sogou/workflow-k8s)可以对接Kubernetes的API Server。  

Upstream名不包括端口，但Upstream请求支持指定端口（如果使用非内置协议，Upstream名暂时需要加上端口号以保证构造时的解析成功）。  

每一个Upstream配置自己的独立名称UpstreamName，并添加设定着一组Address，这些Address可以是：
1. ip4
2. ip6
2. 域名
3. unix-domain-socket

### 为什么要替代nginx的Upstream

#### nginx的Upstream工作方式
1. 只支持http/https协议
2. 需要搭建一个nginx服务，启动进程占用socket等其他资源
3. 请求先打到nginx上，nginx再向远端转发请求，这会多一次通信开销

#### workflow本地Upstream工作方式
1. 协议无关，你甚至可以通过upstream访问mysql、redis、mongodb等等
2. 无需额外启动其他进程或端口，直接在进程内模拟反向代理的功能
3. 选取过程是基本的计算和查表，不会有额外的通信开销

# 使用Upstream

### 常用接口
~~~cpp
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
    static int upstream_create_vnswrr(const std::string& name);
    static int upstream_delete(const std::string& name);

public:
    static int upstream_add_server(const std::string& name,
                                   const std::string& address);
    static int upstream_add_server(const std::string& name,
                                   const std::string& address,
                                   const struct AddressParams *address_params);
    static int upstream_remove_server(const std::string& name,
                                      const std::string& address);
    ...
}
~~~

### 例1 在多个目标中随机访问
配置一个本地反向代理，将本地发出的my_proxy.name所有请求均匀的打到6个目标server上
~~~cpp
UpstreamManager::upstream_create_weighted_random(
    "my_proxy.name",
    true);//如果遇到熔断机器，再次尝试直至找到可用或全部熔断

UpstreamManager::upstream_add_server("my_proxy.name", "192.168.2.100:8081");
UpstreamManager::upstream_add_server("my_proxy.name", "192.168.2.100:8082");
UpstreamManager::upstream_add_server("my_proxy.name", "192.168.10.10");
UpstreamManager::upstream_add_server("my_proxy.name", "test.sogou.com:8080");
UpstreamManager::upstream_add_server("my_proxy.name", "abc.sogou.com");
UpstreamManager::upstream_add_server("my_proxy.name", "abc.sogou.com");
UpstreamManager::upstream_add_server("my_proxy.name", "/dev/unix_domain_scoket_sample");

auto *http_task = WFTaskFactory::create_http_task("http://my_proxy.name/somepath?a=10", 0, 0, nullptr);
http_task->start();
~~~
基本原理
1. 随机选择一个目标
2. 如果try_another配置为true，那么将在所有存活的目标中随机选择一个
3. 仅在main中选择，选中目标所在group的主备和无group的备都视为有效的可选对象

### 例2 在多个目标中按照权重大小随机访问
配置一个本地反向代理，将本地发出的weighted.random所有请求按照5/20/1的权重分配打到3个目标server上
~~~cpp
UpstreamManager::upstream_create_weighted_random(
    "weighted.random",
    false);//如果遇到熔断机器，不再尝试，这种情况下此次请求必定失败

AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
address_params.weight = 5;//权重为5
UpstreamManager::upstream_add_server("weighted.random", "192.168.2.100:8081", &address_params);//权重5
address_params.weight = 20;//权重为20
UpstreamManager::upstream_add_server("weighted.random", "192.168.2.100:8082", &address_params);//权重20
UpstreamManager::upstream_add_server("weighted.random", "abc.sogou.com");//权重1

auto *http_task = WFTaskFactory::create_http_task("http://weighted.random:9090", 0, 0, nullptr);
http_task->start();
~~~
基本原理
1. 按照权重分配，随机选择一个目标，权重越大概率越大
2. 如果try_another配置为true，那么将在所有存活的目标中按照权重分配随机选择一个
3. 仅在main中选择，选中目标所在group的主备和无group的备都视为有效的可选对象

### 例3 在多个目标中按照框架默认的一致性哈希访问
~~~cpp
UpstreamManager::upstream_create_consistent_hash(
    "abc.local",
    nullptr);//nullptr代表使用框架默认的一致性哈希函数

UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8081");
UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8082");
UpstreamManager::upstream_add_server("abc.local", "192.168.10.10");
UpstreamManager::upstream_add_server("abc.local", "test.sogou.com:8080");
UpstreamManager::upstream_add_server("abc.local", "abc.sogou.com");

auto *http_task = WFTaskFactory::create_http_task("http://abc.local/service/method", 0, 0, nullptr);
http_task->start();
~~~
基本原理
1. 每1个main视为16个虚拟节点
2. 框架会使用std::hash对所有节点的address+虚拟index+此address加到此upstream的次数进行运算，作为一致性哈希的node值
3. 框架会使用std::hash对path+query+fragment进行运算，作为一致性哈希data值
4. 每次都选择存活node最近的值作为目标
5. 对于每一个main、只要有存活group内main/有存活group内backup/有存活no group backup，即视为存活
6. 如果upstream_add_server()时加上AddressParams，并配上权重weight，则每1个main视为16 * weight个虚拟节点，适用于带权一致性哈希或者希望一致性哈希标准差更小的场景

### 例4 自定义一致性哈希函数
~~~cpp
UpstreamManager::upstream_create_consistent_hash(
    "abc.local",
    [](const char *path, const char *query, const char *fragment) -> unsigned int {
        unsigned int hash = 0;

        while (*path)
            hash = (hash * 131) + (*path++);

        while (*query)
            hash = (hash * 131) + (*query++);

        while (*fragment)
            hash = (hash * 131) + (*fragment++);

        return hash;
    });

UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8081");
UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8082");
UpstreamManager::upstream_add_server("abc.local", "192.168.10.10");
UpstreamManager::upstream_add_server("abc.local", "test.sogou.com:8080");
UpstreamManager::upstream_add_server("abc.local", "abc.sogou.com");

auto *http_task = WFTaskFactory::create_http_task("http://abc.local/sompath?a=1#flag100", 0, 0, nullptr);
http_task->start();
~~~
基本原理
1. 框架会使用用户自定义的一致性哈希函数作为data值
2. 其余与上例原理一致

### 例5 自定义选取策略
~~~cpp
UpstreamManager::upstream_create_manual(
    "xyz.cdn",
    [](const char *path, const char *query, const char *fragment) -> unsigned int {
        return atoi(fragment);
    },
    true,//如果选择到已经熔断的目标，将进行二次选取
    nullptr);//nullptr代表二次选取时使用框架默认的一致性哈希函数

UpstreamManager::upstream_add_server("xyz.cdn", "192.168.2.100:8081");
UpstreamManager::upstream_add_server("xyz.cdn", "192.168.2.100:8082");
UpstreamManager::upstream_add_server("xyz.cdn", "192.168.10.10");
UpstreamManager::upstream_add_server("xyz.cdn", "test.sogou.com:8080");
UpstreamManager::upstream_add_server("xyz.cdn", "abc.sogou.com");

auto *http_task = WFTaskFactory::create_http_task("http://xyz.cdn/sompath?key=somename#3", 0, 0, nullptr);
http_task->start();
~~~
基本原理
1. 框架首先依据用户提供的普通选取函数、按照取模，在main列表中确定选取
2. 对于每一个main、只要有存活group内main/有存活group内backup/有存活no group backup，即视为存活
3. 如果选中目标不再存活且try_another设为true，将再使用一致性哈希函数进行二次选取
4. 如果触发二次选取，一致性哈希将保证一定会选择一个存活目标、除非全部机器都被熔断掉

### 例6 简单的主备模式
~~~cpp
UpstreamManager::upstream_create_weighted_random(
    "simple.name",
    true);//一主一备这项设什么没区别

AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
address_params.server_type = 0;
UpstreamManager::upstream_add_server("simple.name", "main01.test.ted.bj.sogou", &address_params);//主
address_params.server_type = 1;
UpstreamManager::upstream_add_server("simple.name", "backup01.test.ted.gd.sogou", &address_params);//备

auto *http_task = WFTaskFactory::create_http_task("http://simple.name/request", 0, 0, nullptr);
auto *redis_task = WFTaskFactory::create_redis_task("redis://simple.name/2", 0, nullptr);
redis_task->get_req()->set_query("MGET", {"key1", "key2", "key3", "key4"});
(*http_task * redis_task).start();
~~~
基本原理
1. 主备模式与前面所展示的任何模式都不冲突，可以同时生效
2. 主备数量各自独立，没有限制。主和主之间平等，备与备之间平等，主备之间不平等。
3. 只要有主活着，请求一直会使用某一个主
4. 如果主都被熔断，备将作为替代目标接管请求直至有主恢复正常
5. 在每一个策略中，存活的备都可以作为主的存活依据

### 例7 主备+一致性哈希+分组
~~~cpp
UpstreamManager::upstream_create_consistent_hash(
    "abc.local",
    nullptr);//nullptr代表使用框架默认的一致性哈希函数

AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
address_params.server_type = 0;
address_params.group_id = 1001;
UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8081", &address_params);//main in group 1001
address_params.server_type = 1;
address_params.group_id = 1001;
UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8082", &address_params);//backup for group 1001
address_params.server_type = 0;
address_params.group_id = 1002;
UpstreamManager::upstream_add_server("abc.local", "main01.test.ted.bj.sogou", &address_params);//main in group 1002
address_params.server_type = 1;
address_params.group_id = 1002;
UpstreamManager::upstream_add_server("abc.local", "backup01.test.ted.gd.sogou", &address_params);//backup for group 1002
address_params.server_type = 1;
address_params.group_id = -1;
UpstreamManager::upstream_add_server("abc.local", "test.sogou.com:8080", &address_params);//backup for no group mean backup for all group and no group
UpstreamManager::upstream_add_server("abc.local", "abc.sogou.com");//main, no group

auto *http_task = WFTaskFactory::create_http_task("http://abc.local/service/method", 0, 0, nullptr);
http_task->start();
~~~
基本原理
1. 组号-1代表无组，这种目标不属于任何组
2. 无组的main之间是平等的，甚至可以视为同一个组。但与有组的main之间是隔离的
3. 无组的backup可以为全局任何组目标/任何无组目标作为备
4. 组号可以区分哪些主备是在一起工作的
5. 不同组之间的备是相互隔离的，只为本组的main服务
6. 添加目标的默认组号-1，type为0，表示主节点。

### 例8 NVSWRR平滑按权重选取策略
~~~cpp
UpstreamManager::upstream_create_vnswrr("nvswrr.random");

AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
address_params.weight = 3;//权重为3
UpstreamManager::upstream_add_server("weighted.random", "192.168.2.100:8081", &address_params);//权重3
address_params.weight = 2;//权重为2
UpstreamManager::upstream_add_server("weighted.random", "192.168.2.100:8082", &address_params);//权重2
UpstreamManager::upstream_add_server("weighted.random", "abc.sogou.com");//权重1

auto *http_task = WFTaskFactory::create_http_task("http://nvswrr.random:9090", 0, 0, nullptr);
http_task->start();
~~~
基本原理
1. 虚拟节点初始化顺序按照[SWRR算法](https://github.com/nginx/nginx/commit/52327e0627f49dbda1e8db695e63a4b0af4448b1)选取
2. 虚拟节点运行时分批初始化，避免密集型计算集中，每批次虚拟节点使用完后再进行下一批次虚拟节点列表初始化
3. 兼具[SWRR算法](https://github.com/nginx/nginx/commit/52327e0627f49dbda1e8db695e63a4b0af4448b1)的平滑、分散特点，又能具备O(1)的时间复杂度
4. 算法具体细节参见[tengine](https://github.com/alibaba/tengine/pull/1306)

# Upstream选择策略

当发起请求的url的URIHost填UpstreamName时，视做对与名字对应的Upstream发起请求，接下来将会在Upstream记录的这组Address中进行选择：
1. 权重随机策略：按照权重随机选择
2. 一致性哈希策略：框架使用标准的一致性哈希算法，用户可以自定义对请求uri的一致性哈希函数consistent_hash
3. 手动策略：根据用户提供的对请求uri的select函数进行确定的选择，如果选中了已经熔断的目标：
  a. 如果try_another为false，这次请求将返回失败
  b. 如果try_another为true，框架使用标准的一致性哈希算法重新选取，用户可以自定义对请求uri的一致性哈希函数consistent_hash
4. 主备策略：按照先主后备的优先级，只要主可以用就选择主。此策略可以与[1]、[2]、[3]中的任何一个同时生效，相互影响。

round-robin/weighted-round-robin：视为与[1]等价，暂不提供  
框架建议普通用户使用策略[2]，可以保证集群具有良好的容错性和可扩展性  
对于复杂需求场景，高级用户可以使用策略[3]，订制复杂的选择逻辑

# Address属性

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

struct AddressParams
{
    struct EndpointParams endpoint_params;
    unsigned int dns_ttl_default;
    unsigned int dns_ttl_min;
    unsigned int max_fails;
    unsigned short weight;
    int server_type;
    int group_id;
};

static constexpr struct AddressParams ADDRESS_PARAMS_DEFAULT =
{
    .endpoint_params    =    ENDPOINT_PARAMS_DEFAULT,
    .dns_ttl_default    =    12 * 3600,
    .dns_ttl_min        =    180,
    .max_fails          =    200,
    .weight             =    1,    //only for main of UPSTREAM_WEIGHTED_RANDOM
    .server_type        =    0,
    .group_id           =    -1,
};
~~~
每个Addreess都可以配置自己的自定义参数：
  * EndpointParams的max_connections, connect_timeout, response_timeout, ssl_connect_timeout：连接相关的参数
  * dns_ttl_default：dns cache中默认的ttl，单位秒，默认12小时，dns cache是针对当前进程的，即进程退出就会消失，配置也仅对当前进程有效
  * dns_ttl_min：dns最短生效时间，单位秒，默认3分钟，用于在通信失败重试时是否进行重新dns的决策
  * max_fails：触发熔断的【连续】失败次数（注：每次通信成功，计数会清零）
  * weight：权重，默认1，仅对main有效，用于Upstream随机策略选取和一致性哈希选取，权重大越容易被选中
  * server_type：主备配置，默认主。无论什么时刻，同组的主优先级永远高于其他的备
  * group_id：分组依据，默认-1。-1代表无分组(游离)，游离的备可视为任何主的备，有组的备优先级永远高于游离的备。

# 关于熔断

## MTTR

平均修复时间（Mean time to repair，MTTR），是描述产品由故障状态转为工作状态时修理时间的平均值。

## 服务雪崩效应

服务雪崩效应是一种因“服务提供者的故障”（原因），导致“服务调用者故障”（结果），并将不可用逐渐/逐级放大的现象  
若不加以有效控制，效应不会收敛，而且会以几何级放大，犹如雪崩，雪崩效应因此得名  
日常表现通常为：起初只是一个很小的服务or模块异常/超时，引起下游其他依赖的服务随之异常/超时，产生连锁反应，最终导致绝大多数甚至全部的服务陷入瘫痪  
随着故障的修复，效应随之消失，所以效应持续时间通常等于MTTR

## 熔断机制

当某一个目标的错误or异常触达到预先设定的阈值条件时，暂时认为这个目标不可用，剔除目标，即熔断开启进入熔断期  
在熔断持续时间达到MTTR时长后，会进入半熔断状态，(尝试)恢复目标
如果恢复的时候发现其他所有目标都被熔断，会同一时间把所有目标恢复
熔断机制策略可以有效阻止雪崩效应

## Upstream熔断保护机制

MTTR=30秒，暂时不可配置，后续会考虑开放给用户自行配置  
当某一个Addrees连续失败次数达到设定上限（默认200次），这个Address会被熔断MTTR=30秒  
Address在熔断期间，一旦被策略选中，Upstream会根据具体配置决定是否尝试其他Address、如何尝试  

请注意满足下面1-4的某个情景，通信任务将得到一个WFT_ERR_UPSTREAM_UNAVAILABLE = 1004的错误：
1. 权重随机策略，全部目标都处于熔断期
2. 一致性哈希策略，全部目标都处于熔断期
3. 手动策略 && try_another==true，全部目标都处于熔断期  
4. 手动策略 && try_another==false，且同时满足下面三个条件：  
  1). select函数选中的main处于熔断期，，且游离的备都处于熔断期  
  2). 这个main是游离的主，或者这个main所在的group其他目标都处于熔断期  
  3). 所有游离的备都处于熔断期  

# Upstream端口优先级

1. 优先选择显式配置在Upstream Address上的端口号
2. 若没有，再选择显式配置在请求url中的端口号
3. 若都没有，使用协议默认端口号

~~~text
配置 UpstreamManager::upstream_add_server("my_proxy.name", "192.168.2.100:8081");
请求 http://my_proxy.name:456/test.html => http://192.168.2.100:8081/test.html
请求 http://my_proxy.name/test.html => http://192.168.2.100:8081/test.html
~~~

~~~text
配置 UpstreamManager::upstream_add_server("my_proxy.name", "192.168.10.10");
请求 http://my_proxy.name:456/test.html => http://192.168.10.10:456/test.html
请求 http://my_proxy.name/test.html => http://192.168.10.10:80/test.html
~~~

