# About DNS
When using a domain name to request the network, you first need to obtain the server address through domain name resolution, and then use the network address to make subsequent requests. Workflow has implemented a complete domain name resolution and caching system. Generally speaking, users can initiate network tasks smoothly without knowing the internal mechanism.

## DNS related configuration
Global configuration in Workflow includes

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

Among them, the configuration items related to domain name resolution include

* dns_server_params
  * address_family: This item will be explained later
  * max_connections: The maximum number of concurrent requests sent to the DNS server, the default is 200
  * connect_timeout/response_timeout/ssl_connect_timeout: refer to [timeout](about-timeout.md) for related instructions
* dns_threads: When using synchronous mode to implement domain name resolution, the resolution operation will be executed in an independent thread pool. This item specifies the number of threads in the thread pool. The default is 4.
* dns_ttl_default: The result of successful domain name resolution will be placed in the domain name cache. This item specifies its survival time in seconds. The default value is 1 hour. When the resolution result expires, it will be re-parsed to obtain the latest content.
* dns_ttl_min: When communication fails, the cached result may have expired. This item specifies a shorter survival time. When communication fails, the cache is updated at a more frequent rate. The unit is seconds. The default value is 1 minute.
* resolv_conf_path: This file saves the configuration related to accessing DNS. It is usually located in `/etc/resolv.conf` on common Linux distributions. If this item is configured as `NULL`, it means using multi-threaded synchronous resolution mode.
* hosts_path: This file is a local domain name lookup table. If the resolved domain name hits this table, it will not initiate a request to DNS. It is usually located in `/etc/hosts` on common Linux distributions. If this item is configured as `NULL` means not to use the lookup table

### resolv.conf extensions
Workflow has extended the `resolv.conf` configuration file. Users can modify the configuration to support the `DNS over TLS(DoT)`. **Note** directly modifying `/etc/resolv.conf` will affect other processes. You can make a copy of the file for modification, and modify the `resolv_conf_path` configuration of Workflow to the path of the new file. For example, a `nameserver` using the `dnss` protocol will connect via SSL

~~~bash
nameserver dnss://8.8.8.8/
nameserver dnss://[2001:4860:4860::8888]/
~~~

### Address Family
In some network environments, although the machine supports IPv6, it cannot communicate with the outside because it has not been assigned a public IPv6 address (for example, the local IPv6 address starts with `fe80`). At this time, you can set `endpoint_params.address_family` to `AF_INET` to force only IPv4 addresses to be resolved during domain name resolution. Similarly, the `resolv.conf` file may specify both the IPv4 address and the IPv6 address of the `nameserver`. In this case, you can set `dns_server_params.address_family` to `AF_INET` or `AF_INET6` to force the use of only IPv4 or IPv6 addresses to access DNS.

### Use Upstream configuration
The global configuration takes effect for each domain name by default. If you need to specify different configurations for certain domain names, you can use the [Upstream](./about-upstream.md#Address attribute) function. Using Upstream, you can individually specify the `dns_ttl_default` and `dns_ttl_min` configuration items, and individually specify the IP address family used by the domain name through `endpoint_params.address_family`.


## Domain name resolution and caching strategy
Network tasks usually require domain name resolution to obtain the IP address that needs to be accessed. The relevant strategies for domain name resolution in Workflow are as follows:

1. Check whether the domain name cache has the IP address corresponding to the domain name. If there is a cache and it has not expired, use this set of IP addresses.
2. Check whether the domain name is an IPv4, IPv6 address or `Unix Domain Socket`. If so, use the address directly without initiating domain name resolution.
3. Check whether the `hosts_path` file contains the IP address corresponding to the domain name. If so, use the address directly.
4. Obtain an asynchronous lock to ensure that a resolution request for the same domain name is only initiated once at the same time, and initiate a resolution request to DNS
5. After successful parsing, the parsing result will be saved to the domain name cache of the current process for next use, and the asynchronous lock will be released.
6. After the parsing fails, the asynchronous lock will be released and the failure reason will be notified to all tasks waiting on the same asynchronous lock. New tasks initiated after the notification is completed will request DNS again.

Many scenarios that require a large number of network requests will be equipped with a domain name caching component. If a resolution request is sent to the DNS every time a network task is initiated, the DNS will inevitably be overwhelmed. Workflow sets the cache survival time (dns_ttl_default and dns_ttl_min) to ensure that the cache will expire after a reasonable period of time and the domain name resolution results can be updated in a timely manner. When a cache item of a domain name expires, the first task found to be expired will extend its survival time by 5 seconds and initiate a resolution request to DNS. Requests on the same domain name within 5 seconds will directly use the cached DNS resolution results without waiting.

The asynchronous lock mechanism can ensure that the resolution request for the **same domain name** is only initiated once at the same time. Without lock protection, if a large number of network tasks are initiated for the same domain name in a short period of time, each task will be unable to be retrieved from the cache. Too many resolution request to DNS will place a large and unnecessary burden on DNS. The same domain name here represents the `(host, port, family)` triplet. If a domain name is required to only use IPv4 and IPv6 through Upstream, they will be protected by different asynchronous locks, and it is possible to request DNS at the same time.


### Asynchronous domain name resolution
Workflow implements a complete DNS task. If the `resolv_conf_path` configuration item is specified, an asynchronous request will be used when initiating domain name resolution to DNS. Under Unix-like systems, Workflow uses `/etc/resolv.conf` as the value of this configuration by default. Asynchronous domain name resolution does not block any threads or monopolize the thread pool, and can complete the task of domain name resolution more efficiently.

### Synchronous domain name resolution
If `resolv_conf_path` is specified as `NULL`, synchronous domain name resolution will be achieved by calling the `getaddrinfo` function. This method will use an independent thread pool, and the number of threads is configured through the `dns_threads` parameter. If a large number of domain name resolution requests need to be initiated in a short period of time, the synchronization method will cause a large delay.
