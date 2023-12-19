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

#include <netdb.h>
#include <stdint.h>
#include <string>
#include <mutex>
#include <utility>
#include "LRUCache.h"
#include "DnsUtil.h"

#define GET_TYPE_TTL		0
#define GET_TYPE_CONFIDENT	1

struct DnsCacheValue
{
	struct addrinfo *addrinfo;
	int64_t confident_time;
	int64_t expire_time;

	bool delayed() const
	{
		return addrinfo->ai_flags & 2;
	}
};

// RAII: NO. Release handle by user
// Thread safety: YES
// MUST call release when handle no longer used
class DnsCache
{
public:
	using HostPort = std::pair<std::string, unsigned short>;
	using DnsHandle = LRUHandle<HostPort, DnsCacheValue>;

public:
	// get handler
	// Need call release when handle no longer needed
	//Handle *get(const KEY &key);
	const DnsHandle *get(const HostPort& host_port);

	const DnsHandle *get(const std::string& host, unsigned short port)
	{
		return get(HostPort(host, port));
	}

	const DnsHandle *get(const char *host, unsigned short port)
	{
		return get(std::string(host), port);
	}

	const DnsHandle *get_ttl(const HostPort& host_port)
	{
		return get_inner(host_port, GET_TYPE_TTL);
	}

	const DnsHandle *get_ttl(const std::string& host, unsigned short port)
	{
		return get_ttl(HostPort(host, port));
	}

	const DnsHandle *get_ttl(const char *host, unsigned short port)
	{
		return get_ttl(std::string(host), port);
	}

	const DnsHandle *get_confident(const HostPort& host_port)
	{
		return get_inner(host_port, GET_TYPE_CONFIDENT);
	}

	const DnsHandle *get_confident(const std::string& host, unsigned short port)
	{
		return get_confident(HostPort(host, port));
	}

	const DnsHandle *get_confident(const char *host, unsigned short port)
	{
		return get_confident(std::string(host), port);
	}

	const DnsHandle *put(const HostPort& host_port,
						 struct addrinfo *addrinfo,
						 unsigned int dns_ttl_default,
						 unsigned int dns_ttl_min);

	const DnsHandle *put(const std::string& host,
						 unsigned short port,
						 struct addrinfo *addrinfo,
						 unsigned int dns_ttl_default,
						 unsigned int dns_ttl_min)
	{
		return put(HostPort(host, port), addrinfo, dns_ttl_default, dns_ttl_min);
	}

	const DnsHandle *put(const char *host,
						 unsigned short port,
						 struct addrinfo *addrinfo,
						 unsigned int dns_ttl_default,
						 unsigned int dns_ttl_min)
	{
		return put(std::string(host), port, addrinfo, dns_ttl_default, dns_ttl_min);
	}

	// release handle by get/put
	void release(const DnsHandle *handle);

	// delete from cache, deleter delay called when all inuse-handle release.
	void del(const HostPort& key);

	void del(const std::string& host, unsigned short port)
	{
		del(HostPort(host, port));
	}

	void del(const char *host, unsigned short port)
	{
		del(std::string(host), port);
	}

private:
	const DnsHandle *get_inner(const HostPort& host_port, int type);

	std::mutex mutex_;

	class ValueDeleter
	{
	public:
		void operator() (const DnsCacheValue& value) const
		{
			struct addrinfo *ai = value.addrinfo;

			if (ai && (ai->ai_flags & 1))
				freeaddrinfo(ai);
			else
				protocol::DnsUtil::freeaddrinfo(ai);
		}
	};

	LRUCache<HostPort, DnsCacheValue, ValueDeleter> cache_pool_;

public:
	// To prevent inline calling LRUCache's constructor and deconstructor.
	DnsCache();
	~DnsCache();
};

#endif

