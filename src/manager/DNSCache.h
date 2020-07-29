/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#ifndef _DNSCACHE_H_
#define _DNSCACHE_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdint.h>
#include <string>
#include <mutex>
#include <utility>
#include "LRUCache.h"

#define GET_TYPE_TTL		0
#define GET_TYPE_CONFIDENT	1

struct DNSCacheValue
{
	struct addrinfo *addrinfo;
	int64_t confident_time;
	int64_t expire_time;
};

class ValueDeleter
{
public:
	void operator() (const DNSCacheValue& value) const
	{
		freeaddrinfo(value.addrinfo);
	}
};

typedef std::pair<std::string, unsigned short> HostPort;
typedef LRUHandle<HostPort, DNSCacheValue> DNSHandle;

// RAII: NO. Release handle by user
// Thread safety: YES
// MUST call release when handle no longer used
class DNSCache
{
public:
	// release handle by get/put
	void release(DNSHandle *handle);
	void release(const DNSHandle *handle);

	// get handler
	// Need call release when handle no longer needed
	//Handle *get(const KEY &key);
	const DNSHandle *get(const HostPort& host_port);
	const DNSHandle *get(const std::string& host, unsigned short port);
	const DNSHandle *get(const char *host, unsigned short port);

	const DNSHandle *get_ttl(const HostPort& host_port);
	const DNSHandle *get_ttl(const std::string& host, unsigned short port);
	const DNSHandle *get_ttl(const char *host, unsigned short port);

	const DNSHandle *get_confident(const HostPort& host_port);
	const DNSHandle *get_confident(const std::string& host, unsigned short port);
	const DNSHandle *get_confident(const char *host, unsigned short port);

	// put copy
	// Need call release when handle no longer needed
	const DNSHandle *put(const HostPort& host_port,
						 struct addrinfo *addrinfo,
						 unsigned int dns_ttl_default,
						 unsigned int dns_ttl_min);

	const DNSHandle *put(const std::string& host,
						 unsigned short port,
						 struct addrinfo *addrinfo,
						 unsigned int dns_ttl_default,
						 unsigned int dns_ttl_min);

	const DNSHandle *put(const char *host,
						 unsigned short port,
						 struct addrinfo *addrinfo,
						 unsigned int dns_ttl_default,
						 unsigned int dns_ttl_min);

	// delete from cache, deleter delay called when all inuse-handle release.
	void del(const HostPort& key);
	void del(const std::string& host, unsigned short port);
	void del(const char *host, unsigned short port);

private:
	const DNSHandle *get_inner(const HostPort& host_port, int type);

	std::mutex mutex_;
	LRUCache<HostPort, DNSCacheValue, ValueDeleter> cache_pool_;
};

////////////////////

inline void DNSCache::release(DNSHandle *handle)
{
	cache_pool_.release(handle);
}

inline void DNSCache::release(const DNSHandle *handle)
{
	cache_pool_.release(handle);
}

inline const DNSHandle *DNSCache::get(const HostPort& host_port)
{
	return cache_pool_.get(host_port);
}

inline const DNSHandle *DNSCache::get(const std::string& host, unsigned short port)
{
	return get(HostPort(host, port));
}

inline const DNSHandle *DNSCache::get(const char *host, unsigned short port)
{
	return get(std::string(host), port);
}

inline const DNSHandle *DNSCache::get_ttl(const HostPort& host_port)
{
	return get_inner(host_port, GET_TYPE_TTL);
}

inline const DNSHandle *DNSCache::get_ttl(const std::string& host, unsigned short port)
{
	return get_ttl(HostPort(host, port));
}

inline const DNSHandle *DNSCache::get_ttl(const char *host, unsigned short port)
{
	return get_ttl(std::string(host), port);
}

inline const DNSHandle *DNSCache::get_confident(const HostPort& host_port)
{
	return get_inner(host_port, GET_TYPE_CONFIDENT);
}

inline const DNSHandle *DNSCache::get_confident(const std::string& host, unsigned short port)
{
	return get_confident(HostPort(host, port));
}

inline const DNSHandle *DNSCache::get_confident(const char *host, unsigned short port)
{
	return get_confident(std::string(host), port);
}

inline const DNSHandle *DNSCache::put(const std::string& host,
									  unsigned short port,
									  struct addrinfo *addrinfo,
									  unsigned int dns_ttl_default,
									  unsigned int dns_ttl_min)
{
	return put(HostPort(host, port), addrinfo, dns_ttl_default, dns_ttl_min);
}

inline const DNSHandle *DNSCache::put(const char *host,
									  unsigned short port,
									  struct addrinfo *addrinfo,
									  unsigned int dns_ttl_default,
									  unsigned int dns_ttl_min)
{
	return put(std::string(host), port, addrinfo, dns_ttl_default, dns_ttl_min);
}

inline void DNSCache::del(const HostPort& key)
{
	cache_pool_.del(key);
}

inline void DNSCache::del(const std::string& host, unsigned short port)
{
	del(HostPort(host, port));
}

inline void DNSCache::del(const char *host, unsigned short port)
{
	del(std::string(host), port);
}

#endif

