# About Upstream

In nginx, Upstream represents the load balancing configuration of the reverse proxy. Here, we expand the meaning of Upstream so that it has the following characteristics:

1. Each Upstream is an independent reverse proxy
2. Accessing an Upstream is equivalent to using an appropriate strategy to select one in a group of services/targets/upstream and downstream for access
3. Upstream has load balancing, error handling, circuit breaker and other service governance capabilities
4. For multiple retries of the same request, Upstream can avoid addresses that already tried
5. Different connection parameters can be configured for different addresses through Upstream
6. Dynamically adding/removing target will take effect in real time, which is convenient for any service discovery system

### Advantages of Upstream over domain name DNS resolution

Both Upstream and domain name DNS resolution can configure a group of ip to a host, but

1. DNS domain name resolution doesn’t address port number. The service DNS domain names with the same IP and different ports cannot be configured together; but it is possible for Upstream.
2. The set of addresses corresponding to DNS domain name resolution must be ip; while the set of addresses corresponding to Upstream can be ip, domain name or unix-domain-socket
3. Normally, DNS domain name resolution will be cached by operating system or DNS server on the network, and the update time is limited by ttl; while Upstream can be updated in real time and take effect in real time
4. The consumption of DNS domain name is much greater than that of Upstream resolution and selection

### Upstream of Workflow

This is a local reverse proxy module, and the proxy configuration is effective for both server and client.

Support dynamic configuration and available for any service discovery system. Currently, [workflow-k8s](https://github.com/sogou/workflow-k8s) can be used to acquire Pods information from the API server of Kubernetes.

Upstream name does not include port, but upstream request supports specified port. (However, for non-built-in protocols, Upstream name temporarily needs to be added with the port to ensure parsing during construction).

Each Upstream is configured with its own independent name UpstreamName, and a set of Addresses is added and set. These Addresses can be:

1. ip4
2. ip6
3. Domain name
4. unix-domain-socket

### Why to replace nginx's Upstream

#### Upstream working mode of nginx

1. Supports http/https protocol only

2. Needs to build a nginx service, start the start process occupies socket and other resources

3. The request is sent to nginx first, and nginx forwards the request to remote end, which will increase one more network communication overhead

#### Local Upstream working method of workflow

1. Protocol irrelevant, you can even access mysql, redis, mongodb, etc. through upstream

2. You can directly simulate the function of reverse proxy in the process, no need to start other processes or ports 

3. The selection process is basic calculation and table lookup, no additional network communication overhead

# Use Upstream

### Common interfaces

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

### Example 1 Random access in multiple targets

Configure a local reverse proxy to evenly send all the local requests for **my_proxy.name** to 6 target servers

~~~cpp
UpstreamManager::upstream_create_weighted_random(
    "my_proxy.name",
    true); // In case of fusing, retry till the available is found or all fuses are blown

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

Basic principles

1. Select a target randomly
2. If try_another is configured as true, one of all surviving targets will be selected randomly
3. Select in the main servers only, the mains and backups of the group where the selected target is located and the backup without group are regarded as valid optional objects

### Example 2 Random access among multiple targets based on weights

Configure a local reverse proxy, send all **weighted.random** requests to the 3 target servers based on the weight distribution of 5/20/1

~~~cpp
UpstreamManager::upstream_create_weighted_random(
    "weighted.random",
    false); // If you don’t retry in case of fusing, the request will surely fail

AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
address_params.weight = 5; //weight is 5
UpstreamManager::upstream_add_server("weighted.random", "192.168.2.100:8081", &address_params); // weight is 5
address_params.weight = 20; // weight is 20
UpstreamManager::upstream_add_server("weighted.random", "192.168.2.100:8082", &address_params); // weight is 20
UpstreamManager::upstream_add_server("weighted.random", "abc.sogou.com"); // weight is 1

auto *http_task = WFTaskFactory::create_http_task("http://weighted.random:9090", 0, 0, nullptr);
http_task->start();
~~~

Basic principles

1. According to the weight distribution, randomly select a target, the greater the weight is, the greater the probability is
2. If try_another is configured as true, one of all surviving targets will be selected randomly as per weights.
3. Select in the main servers only, the main and backup of the group where the selected target is located and the backup without group are regarded as valid optional objects

### Example 3 Access among multiple targets based on the framework's default consistent hash

~~~cpp
UpstreamManager::upstream_create_consistent_hash(
    "abc.local",
    nullptr); // nullptr represents using the default consistent hash function of the framework

UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8081");
UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8082");
UpstreamManager::upstream_add_server("abc.local", "192.168.10.10");
UpstreamManager::upstream_add_server("abc.local", "test.sogou.com:8080");
UpstreamManager::upstream_add_server("abc.local", "abc.sogou.com");

auto *http_task = WFTaskFactory::create_http_task("http://abc.local/service/method", 0, 0, nullptr);
http_task->start();
~~~

Basic principles

1. Each main server is regarded as 16 virtual nodes
2. The framework will use std::hash to calculate "the address + virtual index of all nodes + the number of times for this address to add into this Upstream" as the node value of the consistent hash
3. The framework will use std::hash to calculate path + query + fragment as a consistent hash data value
4. Choose the value nearest to the surviving node as the target each time
5. For each main, as long as there is a main in surviving group, or there is a backup in surviving group, or there is a surviving no group backup, it is regarded as surviving
6. If weight on AddressParams is set with upstream_add_server(), each main server is regarded as 16 * weight virtual nodes. This is suitable for weighted consistent hash or shrinking the standard deviation of consistent hash

### Example 4 User-defined consistent hash function

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

Basic principles

1. The framework will use a user-defined consistent hash function as the data value
2. The rest is the same as the above principles

### Example 5 User-defined selection strategy

~~~cpp
UpstreamManager::upstream_create_manual(
    "xyz.cdn",
    [](const char *path, const char *query, const char *fragment) -> unsigned int {
        return atoi(fragment);
    },
    true, // If a blown target is selected, a second selection will be made
    nullptr); // nullptr represents using the default consistent hash function of the framework in the second selection

UpstreamManager::upstream_add_server("xyz.cdn", "192.168.2.100:8081");
UpstreamManager::upstream_add_server("xyz.cdn", "192.168.2.100:8082");
UpstreamManager::upstream_add_server("xyz.cdn", "192.168.10.10");
UpstreamManager::upstream_add_server("xyz.cdn", "test.sogou.com:8080");
UpstreamManager::upstream_add_server("xyz.cdn", "abc.sogou.com");

auto *http_task = WFTaskFactory::create_http_task("http://xyz.cdn/sompath?key=somename#3", 0, 0, nullptr);
http_task->start();
~~~

Basic principles

1. The framework first determines the selection in the main server list according to the normal selection function provided by the user and then get the modulo
2. For each main server, as long as there is a main server in surviving group, or there is a backup in surviving group, or there is a surviving no group backup, it is regarded as surviving
3. If the selected target no longer survives and try_another is set as true, a second selection will be made using consistent hash function
4. If the second selection is triggered, the consistent hash will ensure that a survival target will be selected, unless all machines are blown

### Example 6 Simple main-backup mode
~~~cpp
UpstreamManager::upstream_create_weighted_random(
    "simple.name",
    true);//One main, one backup, nothing is different in this item

AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
address_params.server_type = 0;   /* 1 for main server */
UpstreamManager::upstream_add_server("simple.name", "main01.test.ted.bj.sogou", &address_params); // main
address_params.server_type = 1;   /* 0 for backup server */
UpstreamManager::upstream_add_server("simple.name", "backup01.test.ted.gd.sogou", &address_params); //backup

auto *http_task = WFTaskFactory::create_http_task("http://simple.name/request", 0, 0, nullptr);
auto *redis_task = WFTaskFactory::create_redis_task("redis://simple.name/2", 0, nullptr);
redis_task->get_req()->set_query("MGET", {"key1", "key2", "key3", "key4"});
(*http_task * redis_task).start();
~~~

Basic principles
1. The main-backup mode does not conflict with any of the modes shown above, and it can take effect at the same time
2. The number of main/backup is independent of each other and there is no limit. All main servers are coequal to each other, and all backup servers are coequal to each others, but main and backup are not coequal to each other.
3. As long as a main server is alive, the request will always use a main server.
4. If all main servers are blown, backup server will take over the request as a substitute target until any main server works well again
5. In every strategy, surviving backup can be used as the basis for the survival of main

### Example 7 Main-backup + consistent hash + grouping
~~~cpp
UpstreamManager::upstream_create_consistent_hash(
    "abc.local",
    nullptr);//nullptr represents using the default consistent hash function of the framework 

AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
address_params.server_type = 0;
address_params.group_id = 1001;
UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8081", &address_params);//main in group 1001
address_params.server_type = 1;
address_params.group_id = 1001;
UpstreamManager::upstream_add_server("abc.local", "192.168.2.100:8082", &address_params);//backup for group 1001
address_params.server_type = 0;
address_params.group_id = 1002;
UpstreamManager::upstream_add_server("abc.local", "backup01.test.ted.bj.sogou", &address_params);//main in group 1002
address_params.server_type = 1;
address_params.group_id = 1002;
UpstreamManager::upstream_add_server("abc.local", "backup01.test.ted.gd.sogou", &address_params);//backup for group 1002
address_params.server_type = 1;
address_params.group_id = -1;
UpstreamManager::upstream_add_server("abc.local", "test.sogou.com:8080", &address_params);//backup with no group mean backup for all groups and no group
UpstreamManager::upstream_add_server("abc.local", "abc.sogou.com");//main, no group

auto *http_task = WFTaskFactory::create_http_task("http://abc.local/service/method", 0, 0, nullptr);
http_task->start();
~~~

Basic principles

1. Group number -1 means no group, this kind of target does not belong to any group
2. The main servers without a group are coequal to each other, and they can even be regarded as one group. But they are isolated from the other main servers with a group
3. A backup without a group can serve as a backup for any group target of Global/any target without a group
4. The group number can identify which main and backup are working together
5. The backups of different groups are isolated from each other, and they serve the main servers of their own group only
6. Add the default group number -1 of the target, and the type is main

### Example 8 NVSWRR selection weighting strategy
~~~cpp
UpstreamManager::upstream_create_vnswrr("nvswrr.random");

AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
address_params.weight = 3;//weight is 3
UpstreamManager::upstream_add_server("nvswrr.random", "192.168.2.100:8081", &address_params);//weight is 3
address_params.weight = 2;//weight is 2
UpstreamManager::upstream_add_server("nvswrr.random", "192.168.2.100:8082", &address_params);//weight is 2
UpstreamManager::upstream_add_server("nvswrr.random", "abc.sogou.com");//weight is 1

auto *http_task = WFTaskFactory::create_http_task("http://nvswrr.random:9090", 0, 0, nullptr);
http_task->start();
~~~
1. The virtual node initialization sequence is selected according to the [SWRR algorithm](https://github.com/nginx/nginx/commit/52327e0627f49dbda1e8db695e63a4b0af4448b1)
2. The virtual nodes are initialized in batches during operation to avoid intensive computing concentration. After each batch of virtual nodes is used up, the next batch of virtual node lists can be initialized.
3. It has both the smooth and scattered characteristics of [SWRR algorithm](https://github.com/nginx/nginx/commit/52327e0627f49dbda1e8db695e63a4b0af4448b1) and the time complexity of O(1)
4. For specific details of the algorithm, see tengine(https://github.com/alibaba/tengine/pull/1306)

# Upstream selection strategy

When the URIHost of the url that initiates the request is filled with UpstreamName, it is regarded as a request to the Upstream corresponding to the name, and then it will be selected from the set of Addresses recorded by the Upstream:

1. Weight random strategy: selection randomly according to weight
2. Consistent hash strategy: The framework uses a standard consistent hashing algorithm, and users can define the consistent hash function consistent_hash for the requested uri
3. Manual strategy: make definite selection according to the select function that user provided for the requested uri, if the blown target is selected: **a.** If try_another is false, this request will return to failure **b.** If try_another is true, the framework uses standard consistent hash algorithm to make a second selection, and the user can define the consistent hash function consistent_hash for the requested uri
4. Main-backup strategy: According to the priority of main first, backup next, select a main server as long as it can be used. This strategy can take effect concurrently with any of [1], [2], and [3], and they influence each other.

Round-robin/weighted-round-robin: regarded as equivalent to [1], not available for now

The framework recommends common users to use strategy [2], which can ensure that the cluster has good fault tolerance and scalability

For complex scenarios, advanced users can use strategy [3] to customize complex selection logic

# Address attribute
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
    int server_type;   /* 0 for main and 1 for backup. */
    int group_id;
};

static constexpr struct AddressParams ADDRESS_PARAMS_DEFAULT =
{
    .endpoint_params    =    ENDPOINT_PARAMS_DEFAULT,
    .dns_ttl_default    =    12 * 3600,
    .dns_ttl_min        =    180,
    .max_fails          =    200,
    .weight             =    1,    // only for main of UPSTREAM_WEIGHTED_RANDOM
    .server_type        =    0,
    .group_id           =    -1,
};
~~~

Each address can be configured with custom parameters:

  * Max_connections, connect_timeout, response_timeout, ssl_connect_timeout of EndpointParams: connection-related parameters
  * dns_ttl_default: The default ttl in the dns cache in seconds, and the default value is 12 hours. The dns cache is for the current process, that is, the process will disappear after exiting, and the configuration is only valid for the current process
  * dns_ttl_min: The shortest effective time of dns in seconds, and the default value is 3 minutes. It is used to decide whether to perform dns again when communication fails and retry.
  * max_fails: the number of [continuous] failures that triggered fusing (Note: each time the communication is successful, the count will be cleared)
  * Weight: weight, the default value is 1, which is only valid for main. It is used for Upstream weighted random strategy selection and consistent hash strategy selection, the larger the weight is, the easier it is to be selected.
  * server_type: main/backup configuration, main by default (server_type=0). At any time, the main servers in the same group are always at higher priority than backups
  * group_id: basis for grouping, the default value is -1. -1 means no grouping (free). A free backup can be regarded as backup to any main server. Any backup with group is always at higher priority than any free backup.

# About fuse

## MTTR
Mean time to repair (MTTR) is the average value of the repair time when the product changes from a fault state to a working state.

## Service avalanche effect

Service avalanche effect is a phenomenon in which "service caller failure" (result) is caused by "service provider's failure" (cause), and the unavailability is amplified gradually/level by level

If it is not controlled effectively, the effect will not converge, but will be amplified geometrically, just like an avalanche, that’s why it is called avalanche effect

Description of the phenomenon: at first it is just a small service or module abnormality/timeout, causing abnormality/timeout of other downstream dependent services, then causing a chain reaction, eventually leading to paralysis of most or all services

As the fault is repaired, the effect will disappear, so the duration of the effect is usually equal to MTTR

## Fuse mechanism

When the error or abnormal touch of a certain target meets the preset threshold condition, the target is temporarily considered unavailable, and the target is removed, namely fuse is started and enters the fuse period

After the fuse duration reaches MTTR duration, turn into half-open status, (attempt to) restore the target

If all targets are found fused whenever recovering one target, all targets will be restored at the same time

Fuse mechanism strategy can effectively prevent avalanche effect

## Upstream fuse protection mechanism

MTTR=30 seconds, which is temporarily not configurable, but we will consider opening it to be configured by users in the future.

When the number of consecutive failures of a certain Address reaches the set upper limit (200 times by default), this Address will be blown, MTTR=30 seconds.

During the fusing period, once the Address is selected by the strategy, Upstream will decide whether to try other Addresses and how to try according to the specific configuration

Please note that if one of the following 1-4 scenarios is met, the communication task will get an error of WFT_ERR_UPSTREAM_UNAVAILABLE = 1004:

 1. Weight random strategy, all targets are in the fusing period
 2. Consistent hash strategy, all targets are in the fusing period
 3. Manual strategy and try_another==true, all targets are in the fusing period
 4. Manual strategy and try_another==false, and all the following three conditions shall meet at the same time:

    1). The main selected by the select function is in the fusing period, and all free devices are in the fusing period

    2). The main is a free main, or other targets in the group where the main is located are all in the fusing period

    3). All free devices are in the fusing period
  
# Upstream port priority

1. Priority is given to the port number explicitly configured on the Upstream Address

2. If not, select the port number explicitly configured in the request url

3. If none, use the default port number of the protocol

~~~cpp
Configure UpstreamManager::upstream_add_server("my_proxy.name", "192.168.2.100:8081");
Request http://my_proxy.name:456/test.html => http://192.168.2.100:8081/test.html
Request http://my_proxy.name/test.html => http://192.168.2.100:8081/test.html
~~~

~~~cpp
Configure UpstreamManager::upstream_add_server("my_proxy.name", "192.168.10.10");
Request http://my_proxy.name:456/test.html => http://192.168.10.10:456/test.html
Request http://my_proxy.name/test.html => http://192.168.10.10:80/test.html
~~~
