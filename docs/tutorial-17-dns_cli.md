# 使用workflow请求DNS
作为一款优秀的异步编程框架，workflow帮助用户处理了大量的细节，其中就包括域名解析，因此在大部分情况下，用户无需关心如何请求DNS服务。正如workflow中的其他模块一样，DNS解析模块设计的同样完备而优雅，若恰好需要实现一些域名解析任务，workflow中的WFDnsClient和WFDnsTask无疑是一个绝佳的选择。

[about-dns](about-dns.md)中介绍了如何配置DNS相关参数，而本篇文档的重点在于介绍如何创建DNS任务以及获取解析结果。

[tutorial-17-dns_cli.cc](/tutorial/tutorial-17-dns_cli.cc)

## 使用WFDnsClient创建任务
WFDnsClient是经过封装的高级接口，其行为类似于系统提供的`resolv.conf`配置文件，帮助用户代理了重试、search列表拼接、server轮换等功能，使用起来非常简单。WFDnsClient的初始化方式有以下几种情况，当函数返回0时表示初始化成功

- 使用一个DNS IPv4地址初始化，下述两种写法等价
```cpp
client.init("8.8.8.8");
// or
client.init("dns://8.8.8.8/");
```
- 使用一个DNS IPv6地址初始化
```cpp
client.init("[2402:4e00::]:53");
```
- 使用DNS over TLS(DoT)地址初始化，默认端口号为853
```cpp
client.init("dnss://120.53.53.53/");
```
- 使用多个由逗号分隔的DNS地址初始化
```cpp
client.init("dns://8.8.8.8/,119.29.29.29");
```
- 显式指定重试策略的初始化，示例代码等价于下述`resolv.conf`描述的策略
```
nameserver 8.8.8.8
search sogou.com tencent.com
options nodts:1 attempts:2 rotate
```
```cpp
client.init("8.8.8.8", "sogou.com,tencent.com", 1, 2, true);
```

使用WFDnsClient创建的任务默认为`DNS_TYPE_A`、`DNS_CLASS_IN`类型的解析请求，且已经设置了递归解析的选项，即`task->get_req()->set_rd(1)`。了解了`WFDnsClient`的初始化的方式，仅需八行即可发起一个DNS解析任务

```cpp
int main()
{
    WFDnsClient client;
    client.init("8.8.8.8");

    WFDnsTask *task = client.create_dns_task("www.sogou.com", dns_callback);
    task->start();

    pause();

    client.deinit();
    return 0;
}
```

## 使用工厂函数创建任务
若不需要WFDnsClient提供的额外功能，或想自行组织重试策略，可使用工厂函数创建任务。

使用工厂函数创建任务时，可以在`url path`中指定要被解析的域名，工厂函数创建的任务默认为`DNS_TYPE_A`、`DNS_CLASS_IN`类型的解析请求，创建后可以通过`set_question_type`和`set_question_class`修改，例如

```cpp
std::string url = "dns://8.8.8.8/www.sogou.com";
WFDnsTask *task = WFTaskFactory::create_dns_task(url, 0, dns_callback);
protocol::DnsRequest *req = task->get_req();
req->set_rd(1);
req->set_question_type(DNS_TYPE_AAAA);
req->set_question_class(DNS_CLASS_IN);
```

若不在创建任务时指定要被解析的域名(此时默认的任务是对根域名`.`进行解析)，在创建任务后可以使用`set_question`函数设置域名等参数，例如

```cpp
std::string url = "dns://8.8.8.8/";
WFDnsTask *task = WFTaskFactory::create_dns_task(url, 0, dns_callback);
protocol::DnsRequest *req = task->get_req();
req->set_rd(1);
req->set_question("www.zhihu.com", DNS_TYPE_AAAA, DNS_CLASS_IN);
```

## 借助工具获取结果
一次成功的DNS请求会获得完整的DNS请求结果，有两种简便的接口可以从结果中获取信息

### DnsUtil::getaddrinfo
该函数类似于系统的`getaddrinfo`函数，调用成功时返回零并成功获得一组`struct addrinfo`，调用失败时返回`EAI_*`类型的错误码。对该函数的成功调用最终**都应该**使用`DnsUtil::freeaddrinfo`释放资源

```cpp
void dns_callback(WFDnsTask *task)
{
    // ignore handle error states

    struct addrinfo *res;
    protocol::DnsResponse *resp = task->get_resp();
    int ret = protocol::DnsUtil::getaddrinfo(resp, 80, &res);
    // ignore check ret == 0

    char ip_str[INET6_ADDRSTRLEN + 1] = { 0 };
    for (struct addrinfo *p = res; p; p = p->ai_next)
    {
        void *addr = nullptr;
        if (p->ai_family == AF_INET)
            addr = &((struct sockaddr_in *)p->ai_addr)->sin_addr;
        else if (p->ai_family == AF_INET6)
            addr = &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;

        if (addr)
        {
            inet_ntop(p->ai_family, addr, ip_str, p->ai_addrlen);
            printf("ip:%s\n", ip_str);
        }
    }

    protocol::DnsUtil::freeaddrinfo(res);
}
```

### DnsResultCursor
`DnsUtil::getaddrinfo`一般用于获取`IPv4`、`IPv6`地址，而使用DnsResultCursor可以完整地遍历DNS结果。DNS解析结果分为answer、authority、additional三个区域，一般情况下主要内容位于answer区域，此处分别判断每个区域是否有内容，并调用`show_result`以逐一展示结果

```cpp
void dns_callback(WFDnsTask *task)
{
    // ignore handle error states

    protocol::DnsResponse *resp = task->get_resp();
    protocol::DnsResultCursor cursor(resp);

    if(resp->get_ancount() > 0)
    {
        cursor.reset_answer_cursor();
        printf(";; ANSWER SECTION:\n");
        show_result(cursor);
    }
    if(resp->get_nscount() > 0)
    {
        cursor.reset_authority_cursor();
        printf(";; AUTHORITY SECTION\n");
        show_result(cursor);
    }
    if(resp->get_arcount() > 0)
    {
        cursor.reset_additional_cursor();
        printf(";; ADDITIONAL SECTION\n");
        show_result(cursor);
    }
}
```

根据请求类型不同，结果中包含的数据可以多种多样，常见的有

- DNS_TYPE_A: IPv4类型的地址
- DNS_TYPE_AAAA: IPv6类型的地址
- DNS_TYPE_NS: 该域名的权威DNS服务器
- DNS_TYPE_CNAME: 该域名的权威名称

```cpp
void show_result(protocol::DnsResultCursor &cursor)
{
    char information[1024];
    const char *info;
    struct dns_record *record;
    struct dns_record_soa *soa;
    struct dns_record_srv *srv;
    struct dns_record_mx *mx;

    while(cursor.next(&record))
    {
        switch (record->type)
        {
        case DNS_TYPE_A:
            info = inet_ntop(AF_INET, record->rdata, information, 64);
            break;
        case DNS_TYPE_AAAA:
            info = inet_ntop(AF_INET6, record->rdata, information, 64);
            break;
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_PTR:
            info = (const char *)(record->rdata);
            break;
        case DNS_TYPE_SOA:
            soa = (struct dns_record_soa *)(record->rdata);
            sprintf(information, "%s %s %u %d %d %d %u",
                soa->mname, soa->rname, soa->serial, soa->refresh,
                soa->retry, soa->expire, soa->minimum
            );
            info = information;
            break;
        case DNS_TYPE_SRV:
            srv = (struct dns_record_srv *)(record->rdata);
            sprintf(information, "%u %u %u %s",
                srv->priority, srv->weight, srv->port, srv->target
            );
            info = information;
            break;
        case DNS_TYPE_MX:
            mx = (struct dns_record_mx *)(record->rdata);
            sprintf(information, "%d %s", mx->preference, mx->exchange);
            info = information;
            break;
        default:
            info = "Unknown";
        }

        printf("%s\t%d\t%s\t%s\t%s\n",
            record->name, record->ttl,
            dns_class2str(record->rclass),
            dns_type2str(record->type),
            info
        );
    }
    printf("\n");
}
```
