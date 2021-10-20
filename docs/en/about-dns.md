# About DNS

Domain Network System (DNS) is a distributed network directory service. It is mainly used for the conversion between a domain name and an IP address.   
During the communication access, it is required to perform DNS resolution for a non-IP domain name. DNS resolution is the process that converts a domain name to an IP address.   
DNS resolution is resource consuming. The operating systems on both servers and local computers usually have their own DNS Cache to reduce unnecessary requests.   
Some programs, including popular browsers and communication frameworks, also have their own DNS Cache in their processes. Workflow is also designed with its own DNS Cache. For convenience purposes, DNS features are completely transparent and “hidden” in the framework.

### TTL

TTL (Time To Live) refers to the amount of time a DNS record is considered up-to-date in the DNS Cache.

### DNS methods in the framework

#### Sync request method
Currently the framework directly calls the system function **getaddrinfo** to resolve domain names. Some details:

1. When the DNS Cache of the framework is hit and its TTL is valid, DNS resolution will not happen.
2. When the domain name belongs to IPv4, IPv6 or unix-domain-socket, DNS resolution will not happen.
3. DNS resolution is a special computing task, which is encapsulated as a WFThreadTask.
4. DNS resolution uses a completely independent and isolated thread pool, that is, it does not occupy the computing thread pool or the communication thread pool.

#### Async request method
The framework implements a complete DNS protocol resolution. The current version requires the user to manually specify `resolv_conf_path` to enable this method. On common Linux distributions, `resolv_conf_path` is generally `/etc/resolv.conf`, and `hosts_path` is generally `/etc/hosts`. Leave the above parameters blank, and the synchronous request method will be used.

### Global DNS configuration

You can see global settings in [WFGlobal.h](/src/manager/WFGlobal.h).

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

where the DNS-related configuration items include:

* dns\_threads: the number of threads in the DNS thread pool, 4 by default. This item will be ignored if the resolv_conf_path is not NULL, and no DNS thread will be created.  
* dns\_ttl\_default: default TTL in DNS Cache in seconds, 12 hours by default; DNS cache is used by the current process, and will be destroyed when the process exists. The configuration is valid only for the current process.
* dns\_ttl\_min: minimum DNS ttl value, in seconds, 3 minutes by default, which is used to decide whether to retry DNS resolution after communication failure.
* resolv_conf_path: Path of the resolv.conf configuration file, we will use multi-threaded DNS resolution when it is NULL.
* hosts_path: Path of the hosts configuration file. This item can also be NULL.

To put it simply, in every communication, the system will check TTL to decide whether to refresh DNS resolution.   
dns\_ttl\_default is checked by default, and dns\_ttl\_min is checked in the retry after communication failure. 

The global DNS configuration can be overridden by the configuration for an individual address in the upstream.   
In Upstream, each AddressParams can also have its own dns\_ttl\_default and dns\_ttl\_min, and you can configure them in the same way as you configure the Global items.   
For the detailed structures, please see [upstream documents](/docs/en/about-upstream.md#Address).

### DNS over SSL (Dot)

On the master branch (not available on windows branch), we also supports DNS resolving over SSL (Dot) by extending the format of **resolv.conf** slightly. You may edit the **resolv.conf** file and add an SSL dns server like:
~~~bash
nameserver dnss://8.8.8.8/
~~~
We use the **dnss://** scheme to represent an SSL dns server address. With the config abort, all DNS resolving will use SSL connection to global dns server 8.8.8.8. The global DNS supports SSL perfectly, and you can try this feature right now! But to avoid changing the system **resolv.conf** file (/etc/resolv.conf), you may need to setup a private **resolv.conf** path:
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

### Handling at TTL expiration moment under high concurrency

At the moment when the TTL is exceeded, if a large number of concurrent requests are sent to a domain name, a large amount of DNS resolution for that domain name may occur at the same time.   
The framework uses a self-consistent logic to reasonably avoid/reduce this possibility:

* When the results are obtained from DNS Cache, if the TTL is exceeded, the TTL will be increased by 10 seconds, and then the TTL expiration will be returned. All happen under the protection of a Mutex.
* If a large number of requests flood in at the moment of TTL expiration, under the protection of this Mutex, \[the first request] will get the expired results and initiate DNS resolution, while other requests will continue to use the old results within 10 seconds.
* As long as the new DNS resolution for \[the first request] is successfully completed within 10 seconds, the DNS Cache is updated to ensure the correctness of the logic; in the next 10 seconds, there will be only one DNS resolution.
* In every ten seconds, there will be only one DNS resolution for the “recently” expired domain name. 
* In order to prevent this mutual exclusion logic from affecting performance, the framework uses the double-checked locks to accelerate processing and effectively avoid the competition of Mutex locks.
* Once again, please note that it is only valid for the "just" expired DNS records, and has no impact for the DNS records that expires long time ago.
* For further information on the logic of this part, please see the source codes of [DNSCache](/src/manager/DNSCache.h).

Currently, there are still two scenarios in which the framework has to perform a large number of DNS resolutions for the same domain name at the same time:

1. The program just started, and instantly made a large number of requests to the same domain name.
2. A domain name has not been visited for a long time (far larger than TTL), and suddenly a lot of requests are made to this domain name.

We think that these two scenarios are acceptable in the framework. To put it more precisely, a large number of DNS requests in this scenario are completely reasonable and logical.
