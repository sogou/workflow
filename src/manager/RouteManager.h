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

#ifndef _ROUTEMANAGER_H_
#define _ROUTEMANAGER_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string>
#include <mutex>
#include <openssl/ssl.h>
#include "rbtree.h"
#include "WFConnection.h"
#include "EndpointParams.h"
#include "CommScheduler.h"

class RouteManager
{
public:
	class RouteResult
	{
	public:
		void *cookie;
		CommSchedObject *request_object;

	public:
		RouteResult(): cookie(NULL), request_object(NULL) { }
		void clear() { cookie = NULL; request_object = NULL; }
	};

	class RouteTarget : public CommSchedTarget
	{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	public:
		int init(const struct sockaddr *addr, socklen_t addrlen, SSL_CTX *ssl_ctx,
				 int connect_timeout, int ssl_connect_timeout, int response_timeout,
				 size_t max_connections)
		{
			int ret = this->CommSchedTarget::init(addr, addrlen, ssl_ctx,
								connect_timeout, ssl_connect_timeout,
								response_timeout, max_connections);

			if (ret >= 0 && ssl_ctx)
				SSL_CTX_up_ref(ssl_ctx);

			return ret;
		}

		void deinit()
		{
			SSL_CTX *ssl_ctx = this->get_ssl_ctx();

			this->CommSchedTarget::deinit();
			if (ssl_ctx)
				SSL_CTX_free(ssl_ctx);
		}
#endif

	public:
		int state;

	private:
		virtual WFConnection *new_connection(int connect_fd)
		{
			return new WFConnection;
		}

	public:
		RouteTarget() : state(0) { }
	};

public:
	int get(enum TransportType type,
			const struct addrinfo *addrinfo,
			const std::string& other_info,
			const struct EndpointParams *ep_params,
			const std::string& hostname, SSL_CTX *ssl_ctx,
			RouteResult& result);

	RouteManager()
	{
		cache_.rb_node = NULL;
	}

	~RouteManager();

private:
	std::mutex mutex_;
	struct rb_root cache_;

public:
	static void notify_unavailable(void *cookie, CommTarget *target);
	static void notify_available(void *cookie, CommTarget *target);
};

#endif

