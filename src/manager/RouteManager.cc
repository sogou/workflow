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

#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <chrono>
#include <mutex>
#include <vector>
#include <string>
#include <algorithm>
#include "list.h"
#include "rbtree.h"
#include "WFGlobal.h"
#include "WFConnection.h"
#include "MD5Util.h"
#include "CommScheduler.h"
#include "EndpointParams.h"
#include "RouteManager.h"
#include "StringUtil.h"

#define GET_CURRENT_SECOND	std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
#define MTTR_SECOND			30

using RouteTargetTCP = RouteManager::RouteTarget;

class RouteTargetUDP : public RouteManager::RouteTarget
{
private:
	virtual int create_connect_fd()
	{
		const struct sockaddr *addr;
		socklen_t addrlen;

		this->get_addr(&addr, &addrlen);
		return socket(addr->sa_family, SOCK_DGRAM, 0);
	}
};

class RouteTargetSCTP : public RouteManager::RouteTarget
{
private:
	virtual int create_connect_fd()
	{
		const struct sockaddr *addr;
		socklen_t addrlen;

		this->get_addr(&addr, &addrlen);
		return socket(addr->sa_family, SOCK_STREAM, IPPROTO_SCTP);
	}
};

//  protocol_name\n user\n pass\n dbname\n ai_addr ai_addrlen \n....
//

struct RouterParams
{
	TransportType transport_type;
	const struct addrinfo *addrinfo;
	uint64_t md5_16;
	SSL_CTX *ssl_ctx;
	int connect_timeout;
	int ssl_connect_timeout;
	int response_timeout;
	size_t max_connections;
};

class Router
{
public:
	struct rb_node rb;
	CommSchedObject *request_object;
	CommSchedGroup *group;
	std::mutex mutex;
	std::vector<CommSchedTarget *> targets;
	struct list_head breaker_list;
	uint64_t md5_16;
	int nleft;
	int nbreak;

	Router():
		request_object(NULL),
		group(NULL)
	{
		INIT_LIST_HEAD(&this->breaker_list);
		this->nleft = 0;
		this->nbreak = 0;
	}

public:
	int init(const struct RouterParams *params);
	void deinit();

	void notify_unavailable(CommSchedTarget *target);
	void notify_available(CommSchedTarget *target);
	void check_breaker();

private:
	void free_list();
	CommSchedTarget *create_target(const struct RouterParams *params,
								   const struct addrinfo *addrinfo);
	int add_group_targets(const struct RouterParams *params);
};

struct __breaker_node
{
	CommSchedTarget *target;
	int64_t timeout;
	struct list_head breaker_list;
};

CommSchedTarget *Router::create_target(const struct RouterParams *params,
									   const struct addrinfo *addr)
{
	CommSchedTarget *target;

	switch (params->transport_type)
	{
	case TT_TCP:
	case TT_TCP_SSL:
		target = new RouteTargetTCP();
		break;
	case TT_UDP:
		target = new RouteTargetUDP();
		break;
	case TT_SCTP:
	case TT_SCTP_SSL:
		target = new RouteTargetSCTP();
		break;
	default:
		errno = EINVAL;
		return NULL;
	}

	if (target->init(addr->ai_addr, addr->ai_addrlen, params->ssl_ctx,
					 params->connect_timeout, params->ssl_connect_timeout,
					 params->response_timeout, params->max_connections) < 0)
	{
		delete target;
		target = NULL;
	}

	return target;
}

int Router::init(const struct RouterParams *params)
{
	const struct addrinfo *addr = params->addrinfo;
	CommSchedTarget *target;

	if (addr == NULL)//0
	{
		errno = EINVAL;
		return -1;
	}

	if (addr->ai_next == NULL)//1
	{
		target = this->create_target(params, addr);
		if (target)
		{
			this->targets.push_back(target);
			this->request_object = target;
			this->md5_16 = params->md5_16;
			return 0;
		}

		return -1;
	}

	this->group = new CommSchedGroup();
	if (this->group->init() >= 0)
	{
		if (this->add_group_targets(params) >= 0)
		{
			this->request_object = this->group;
			this->md5_16 = params->md5_16;
			return 0;
		}

		this->group->deinit();
	}

	delete this->group;
	return -1;
}

int Router::add_group_targets(const struct RouterParams *params)
{
	const struct addrinfo *addr;
	CommSchedTarget *target;

	for (addr = params->addrinfo; addr; addr = addr->ai_next)
	{
		target = this->create_target(params, addr);
		if (target)
		{
			if (this->group->add(target) >= 0)
			{
				this->targets.push_back(target);
				this->nleft++;
				continue;
			}

			target->deinit();
			delete target;
		}

		for (auto *target : this->targets)
		{
			this->group->remove(target);
			target->deinit();
			delete target;
		}

		return -1;
	}

	return 0;
}

void Router::deinit()
{
	for (auto *target : this->targets)
	{
		if (this->group)
			this->group->remove(target);

		target->deinit();
		delete target;
	}

	if (this->group)
	{
		this->group->deinit();
		delete this->group;
	}

	struct list_head *pos, *tmp;
	__breaker_node *node;

	list_for_each_safe(pos, tmp, &this->breaker_list)
	{
		node = list_entry(pos, __breaker_node, breaker_list);
		list_del(pos);
		delete node;
	}
}

void Router::notify_unavailable(CommSchedTarget *target)
{
	if (this->targets.size() <= 1)
		return;

	int errno_bak = errno;
	std::lock_guard<std::mutex> lock(this->mutex);

	if (this->nleft <= 1)
		return;

	if (this->group->remove(target) < 0)
	{
		errno = errno_bak;
		return;
	}

	auto *node = new __breaker_node;

	node->target = target;
	node->timeout = GET_CURRENT_SECOND + MTTR_SECOND;
	list_add_tail(&node->breaker_list, &this->breaker_list);
	this->nbreak++;
	this->nleft--;
}

void Router::notify_available(CommSchedTarget *target)
{
	if (this->targets.size() <= 1 || this->nbreak == 0)
		return;

	int errno_bak = errno;
	std::lock_guard<std::mutex> lock(this->mutex);

	if (this->group->add(target) == 0)
		this->nleft++;
	else
		errno = errno_bak;
}

void Router::check_breaker()
{
	if (this->targets.size() <= 1 || this->nbreak == 0)
		return;

	struct list_head *pos, *tmp;
	__breaker_node *node;
	int errno_bak = errno;
	int64_t cur_time = GET_CURRENT_SECOND;
	std::lock_guard<std::mutex> lock(this->mutex);

	list_for_each_safe(pos, tmp, &this->breaker_list)
	{
		node = list_entry(pos, __breaker_node, breaker_list);
		if (cur_time >= node->timeout)
		{
			if (this->group->add(node->target) == 0)
				this->nleft++;
			else
				errno = errno_bak;

			list_del(pos);
			delete node;
			this->nbreak--;
		}
	}
}

static inline int __addr_cmp(const struct addrinfo *x, const struct addrinfo *y)
{
	//todo ai_protocol
	if (x->ai_addrlen == y->ai_addrlen)
		return memcmp(x->ai_addr, y->ai_addr, x->ai_addrlen);
	else if (x->ai_addrlen < y->ai_addrlen)
		return -1;
	else
		return 1;
}

static inline bool __addr_less(const struct addrinfo *x, const struct addrinfo *y)
{
	return __addr_cmp(x, y) < 0;
}

static uint64_t __generate_key(TransportType type,
							   const struct addrinfo *addrinfo,
							   const std::string& other_info)
{
	std::string str = "TT";

	str += std::to_string(type);
	str += '\n';
	if (!other_info.empty())
	{
		str += other_info;
		str += '\n';
	}

	std::vector<const struct addrinfo *> sorted_addr;

	for (const struct addrinfo *p = addrinfo; p; p = p->ai_next)
		sorted_addr.push_back(p);

	std::sort(sorted_addr.begin(), sorted_addr.end(), __addr_less);
	for (const struct addrinfo *p : sorted_addr)
	{
		str += std::string((const char *)p->ai_addr, p->ai_addrlen);
		str += '\n';
	}

	return MD5Util::md5_integer_16(str);
}

RouteManager::~RouteManager()
{
	Router *router;

	while (cache_.rb_node)
	{
		router = rb_entry(cache_.rb_node, Router, rb);
		rb_erase(cache_.rb_node, &cache_);
		router->deinit();
		delete router;
	}
}

int RouteManager::get(TransportType type,
					  const struct addrinfo *addrinfo,
					  const std::string& other_info,
					  const struct EndpointParams *endpoint_params,
					  RouteResult& result)
{
	result.cookie = NULL;
	result.request_object = NULL;
	if (!addrinfo)
	{
		errno = EINVAL;
		return -1;
	}

	uint64_t md5_16 = __generate_key(type, addrinfo, other_info);
	rb_node **p = &cache_.rb_node;
	rb_node *parent = NULL;
	Router *router;
	std::lock_guard<std::mutex> lock(mutex_);

	while (*p)
	{
		parent = *p;
		router = rb_entry(*p, Router, rb);

		if (md5_16 < router->md5_16)
			p = &(*p)->rb_left;
		else if (md5_16 > router->md5_16)
			p = &(*p)->rb_right;
		else
		{
			router->check_breaker();
			break;
		}
	}

	if (*p == NULL)
	{
		int ssl_connect_timeout = 0;
		SSL_CTX *ssl_ctx = NULL;

		if (type == TT_TCP_SSL || type == TT_SCTP_SSL)
		{
			static SSL_CTX *client_ssl_ctx = WFGlobal::get_ssl_client_ctx();

			ssl_ctx = client_ssl_ctx;
			ssl_connect_timeout = endpoint_params->ssl_connect_timeout;
		}

		struct RouterParams params = {
			.transport_type			=	type,
			.addrinfo 				= 	addrinfo,
			.md5_16					=	md5_16,
			.ssl_ctx 				=	ssl_ctx,
			.connect_timeout		=	endpoint_params->connect_timeout,
			.ssl_connect_timeout	=	ssl_connect_timeout,
			.response_timeout		=	endpoint_params->response_timeout,
			.max_connections		=	endpoint_params->max_connections
		};

		if (StringUtil::start_with(other_info, "?maxconn="))
		{
			int maxconn = atoi(other_info.c_str() + 9);

			if (maxconn <= 0)
				maxconn = 1;

			params.max_connections = maxconn;
		}

		router = new Router();
		if (router->init(&params) >= 0)
		{
			rb_link_node(&router->rb, parent, p);
			rb_insert_color(&router->rb, &cache_);
		}
		else
		{
			delete router;
			router = NULL;
		}
	}

	if (router)
	{
		result.cookie = router;
		result.request_object = router->request_object;
		return 0;
	}

	return -1;
}

void RouteManager::notify_unavailable(void *cookie, CommTarget *target)
{
	if (cookie && target)
		((Router *)cookie)->notify_unavailable((CommSchedTarget *)target);
}

void RouteManager::notify_available(void *cookie, CommTarget *target)
{
	if (cookie && target)
		((Router *)cookie)->notify_available((CommSchedTarget *)target);
}

