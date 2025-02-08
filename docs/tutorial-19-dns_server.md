# 使用workflow实现DNS服务器
前述文档已经讲解了使用workflow实现服务器的方法，workflow框架贴心地为用户处理了底层逻辑和各种细节，因此本文档主要介绍如何组装DNS消息。

[tutorial-19-dns_server.cc](/tutorial/tutorial-19-dns_server.cc)

DNS协议内容中包含三个section，有`DNS_ANSWER_SECTION`、`DNS_AUTHORITY_SECTION`、`DNS_ADDITIONAL_SECTION`，每个section中可包含零或多条资源记录`Resource record`。目前`protocol::DnsResponse`支持添加的资源记录类型有`DNS_TYPE_A`、`DNS_TYPE_AAAA`、`DNS_TYPE_CNAME`、`DNS_TYPE_PTR`、`DNS_TYPE_SOA`、`DNS_TYPE_SRV`、`DNS_TYPE_MX`，其接口如下所示。

```cpp
int add_a_record(int section, const char *name,
				 uint16_t rclass, uint32_t ttl,
				 const void *data);

int add_aaaa_record(int section, const char *name,
					uint16_t rclass, uint32_t ttl,
					const void *data);

int add_ns_record(int section, const char *name,
				  uint16_t rclass, uint32_t ttl,
				  const char *data);

int add_cname_record(int section, const char *name,
					 uint16_t rclass, uint32_t ttl,
					 const char *data);

int add_ptr_record(int section, const char *name,
				   uint16_t rclass, uint32_t ttl,
				   const char *data);

int add_soa_record(int section, const char *name,
				   uint16_t rclass, uint32_t ttl,
				   const char *mname, const char *rname,
				   uint32_t serial, int32_t refresh,
				   int32_t retry, int32_t expire, uint32_t minimum);

int add_srv_record(int section, const char *name,
				   uint16_t rclass, uint32_t ttl,
				   uint16_t priority, uint16_t weight, uint16_t port,
				   const char *target);

int add_mx_record(int section, const char *name,
				  uint16_t rclass, uint32_t ttl,
				  int16_t preference, const char *exchange);

int add_raw_record(int section, const char *name, uint16_t type,
				   uint16_t rclass, uint32_t ttl,
				   const void *data, uint16_t dlen);
```

例如要添加一条AAAA记录，可使用下述方式实现

```cpp
struct in6_addr addr;

inet_pton(AF_INET6, "1234:5678:9abc:def0::", (void *)&addr);
resp->add_aaaa_record(DNS_ANSWER_SECTION,
					  name.c_str(), DNS_CLASS_IN, 600, &addr);
```

对于未支持的资源记录类型，可通过`add_raw_record`接口添加，例如要添加一条TXT记录，可使用下述方式实现

```cpp
const char *raw_txt_data = "\x0dmy dns server\x0fyour dns server";
uint16_t data_len = 30;

resp->add_raw_record(DNS_ANSWER_SECTION, name.c_str(), DNS_TYPE_TXT,
					 DNS_CLASS_IN, 1200, raw_txt_data, data_len);
```

注意，默认情况下`WFDnsServer`会启动一个UDP服务，若需要启动TCP服务，可通过修改WFServerParams中的transport_type字段为`TT_TCP`来实现。DNS客户端通常会优先使用UDP协议发起请求，当要回复的消息过大时，可仅添加部分资源记录，并通过`resp->set_tc(1)`设置截断标记，指示客户端可使用TCP协议重新请求。
