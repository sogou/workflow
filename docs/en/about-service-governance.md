# About service governance

We have a complete mechanism to manage the services we depend on. This mechanism includes the following functions:

* User level DNS.
* Selection of service addresses.
  * Including a variety of selection mechanisms, such as random weight, consistent hash, manual selection methods, etc.
* Service circuit breaker and recovery.
* Load balancing.
* Configuring independent parameters for a single service.
* Main/backup relations for a service, etc.

All these functions depend on our upstream subsystem. By making good use of this system, we can easily implement more complex service mesh functions.

# upstream name

upstream name is equivalent to the domain name inside the program. However, compared with the general domain name, upstream has more functions, including:

* Generally, a domain name can only point to a set of IP addresses; an upstream name can point to a set of IP addresses or domain names.
* The objects (domain names or IPs) pointed by the upstream may include port information.
* upstream has powerful functions for managing and selecting targets, and each target can contain a large number of attributes.
* upstream update is real-time and completely thread-safe, while the DNS of domain names cannot be updated in real time.

In practice, if you don't need to access the external network, the domain names and DNS can be completely replaced by upstream.

# Creating and deleting upstream

[UpstreamMananer.h](/src/manager/UpstreamManager.h) contains several interfaces for creating upstream:

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

The three functions create three types of upstream: consistent hash, weighted random and manual selection.   
The parameter **name** means upstream name, which is used in the same way as a domain name after creation.   
**consistent\_hash** and **select** parameters are both **std::function** of **upstream\_route\_t**, which are used to specify the routing method.   
And try\_another indicates whether to continue trying to find an available target if the selected target is unavailable (blown). consistent\_hash mode does not have this attribute.   
The upstream\_route\_t parameter receives three parameters: path, query and fragment in a URL. For example, if the URL is http://abc.com/home/index.html?a=1#bottom, the three parameters are "/home/index.html", "a=1” and "bottom” respectively. Based on these three parts, the system can select the target server or perform consistent hashing.   
Please note that you call pass nullptr to all consistent\_hash parameters in the above interfaces, and the framework will use the default consistent hash algorithm.

# Example 1: weight allocation

We want to allocate 50% of the requests to www.sogou.com to 127.0.0.1:8000 and 127.0.0.1:8080, and make their load be 1:4.   
We don't need to care about the number of IP addresses behind the domain name www.sogou.com. In short, the actual domain name will receive 50% of the requests.

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

Please note that these functions can be called in any scenario. They are completely thread-safe and takes effect instantly.   
In addition, because all our protocols, including user-defined protocols, have URLs, the upstream function can be applied to all protocols.

# Example 2: manual selection

In the same example as above, we want to allocate 127.0.0.1:8000 if the query in the request URLs is "123", port 8080 if the query is "abc", and normal domain names for other requests.

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

Because Redis and MySQL protocols are provided natively, it is very convenient to realize the read-write separation function of the database with this method (Note: non-transactional operation).   
In the above two examples, the upstream name is www.sogou.com, which is also a domain name. Of course, you can use a simpler string sogou as upstream name. Thus:

~~~cpp
    WFHttpTask *task = WFTaskFactory::create_http_task("http://sogou/home/1.html?abc", ...);
~~~

In a word, if the host part of the URL is a created upstream, it will be used as an upstream.

# Example 3: consistent hash

In this scenario, we will randomly select one machine from 10 Redis instances and communicate with it. But we must ensure that the same URL always accesses the same specific target. The method is very simple:

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

Our Redis task does not recognize the query part, so you can fill it out at will. 2 in the path indicates the Redis database ID.   
At this time, the consistent\_hash function will get three parameters: "/2", "a=hello" and "111". Because we use nullptr, the default consistent hash will be called.   
As we does not specify the port number for the server in upstream, it will use the port in the URL. The default port of Redis is 6379.   
There is no try\_another option for consitent\_hash. If the target is blown, another one will be automatically selected. The same URL will always get the same server (cache friendly).

# Parameters of upstream server

In Example 1, we set the weight of a server through params. But the server parameters is far more than just a weight. Its struct is defined as follows:

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
 * - After 30s following the server failure, upstream probe the server with some alive client’s requests.
 * - If the probes have been successful, the server is marked as an alive one.
 * - If max_fails is set to 1, it means server would out of upstream selection in 30 seconds when failed only once
 */
    unsigned int max_fails;                ///< [1, INT32_MAX] max_fails = 0 means max_fails = 1
    unsigned short weight;                 ///< [1, 65535] weight = 0 means weight = 1. only for main
    int server_type;                       ///< 0 for main and 1 for backup
    int group_id;                          ///< -1 means no group. Backup without group will backup for any main
};
~~~

Most of the parameters are self-explanatory. Among these parameters, endpoint\_params, dns and other parameters will override the global configuration.   
For example, if the global maximum number of connections to each target IP is 200, but you want to set a maximum of 1000 connections for 10.135.35.53, please follow the instructions below:

~~~cpp
    UpstreamManager::upstream_create_weighted_random("10.135.35.53", false);
    struct AddressParams params = ADDRESS_PARAMS_DEFAULT;
    params.endpoint_params.max_connections = 1000;
    UpstreamManager::upstream_add_server("10.135.35.53", "10.135.35.53", &params);
~~~

max\_fails parameter indicates the maximum number of failure. If the selected target continuously fails, and the number of failure reaches max\_failures, it will enter the fusing state. If the try\_another attribute of upstream is false, the task will fail. 
In the callback of the task, get\_state()=WFT\_STATE\_TASK\_ERROR，get\_error()=WFT\_ERR\_UPSTREAM\_UNAVAILABLE.   
If try\_another is true and all server are blown, you will get the same error. The fusing time is 30 seconds.   
Server\_type and group\_id are used for main/backup features. All upstream must have a server whose type is 0, representing main, otherwise the upstream is unavailable.   
Backup servers (server_type 1) will be used when the main servers of the same group\_id is blown.

For more information on the features of upstream, please see [about-upstream.md](/docs/en/about-upstream.md).
