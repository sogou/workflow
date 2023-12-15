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
           Xie Han (xiehan@sogou-inc.com)
*/

#include <stdint.h>
#include <chrono>
#include "DnsCache.h"

#define GET_CURRENT_SECOND	std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()

#define	TTL_INC				5

const DnsCache::DnsHandle *DnsCache::get_inner(const HostPort& host_port,
											   int type)
{
	int64_t cur = GET_CURRENT_SECOND;
	std::lock_guard<std::mutex> lock(mutex_);
	const DnsHandle *handle = cache_pool_.get(host_port);

	if (handle && ((type == GET_TYPE_TTL && cur > handle->value.expire_time) ||
		(type == GET_TYPE_CONFIDENT && cur > handle->value.confident_time)))
	{
		if (!handle->value.delayed())
		{
			DnsHandle *h = const_cast<DnsHandle *>(handle);
			if (type == GET_TYPE_TTL)
				h->value.expire_time += TTL_INC;
			else
				h->value.confident_time += TTL_INC;

			h->value.addrinfo->ai_flags |= 2;
		}

		cache_pool_.release(handle);
		return NULL;
	}

	return handle;
}

const DnsCache::DnsHandle *DnsCache::put(const HostPort& host_port,
										 struct addrinfo *addrinfo,
										 unsigned int dns_ttl_default,
										 unsigned int dns_ttl_min)
{
	int64_t expire_time;
	int64_t confident_time;
	int64_t cur_time = GET_CURRENT_SECOND;

	if (dns_ttl_min > dns_ttl_default)
		dns_ttl_min = dns_ttl_default;

	if (dns_ttl_min == (unsigned int)-1)
		confident_time = INT64_MAX;
	else
		confident_time = cur_time + dns_ttl_min;

	if (dns_ttl_default == (unsigned int)-1)
		expire_time = INT64_MAX;
	else
		expire_time = cur_time + dns_ttl_default;

	std::lock_guard<std::mutex> lock(mutex_);
	return cache_pool_.put(host_port, {addrinfo, confident_time, expire_time});
}

const DnsCache::DnsHandle *DnsCache::get(const DnsCache::HostPort& host_port)
{
	std::lock_guard<std::mutex> lock(mutex_);
	return cache_pool_.get(host_port);
}

void DnsCache::release(const DnsCache::DnsHandle *handle)
{
	std::lock_guard<std::mutex> lock(mutex_);
	cache_pool_.release(handle);
}

void DnsCache::del(const DnsCache::HostPort& key)
{
	std::lock_guard<std::mutex> lock(mutex_);
	cache_pool_.del(key);
}

DnsCache::DnsCache()
{
}

DnsCache::~DnsCache()
{
}

