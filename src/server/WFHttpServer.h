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

  Authors: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _WFHTTPSERVER_H_
#define _WFHTTPSERVER_H_

#include <utility>
#include "HttpMessage.h"
#include "WFServer.h"
#include "WFTaskFactory.h"

using http_process_t = std::function<void (WFHttpTask *)>;
using WFHttpServer = WFServer<protocol::HttpRequest,
							  protocol::HttpResponse>;

static constexpr struct WFServerParams HTTP_SERVER_PARAMS_DEFAULT =
{
/*	.max_connections		=	*/	2000,
/*	.peer_response_timeout	=	*/	10 * 1000,
/*	.receive_timeout		=	*/	-1,
/*	.keep_alive_timeout		=	*/	60 * 1000,
/*	.request_size_limit		=	*/	(size_t)-1,
/*	.ssl_accept_timeout		=	*/	10 * 1000
};

template<>
inline WFHttpServer::WFServer(http_process_t proc) :
	WFServerBase(&HTTP_SERVER_PARAMS_DEFAULT),
	process(std::move(proc))
{
}

template<>
inline CommSession *WFHttpServer::new_session(long long seq, CommConnection *conn)
{
	WFHttpTask *task;

	task = WFServerTaskFactory::create_http_task(this, this->process);
	task->set_keep_alive(this->params.keep_alive_timeout);
	task->set_receive_timeout(this->params.receive_timeout);
	task->get_req()->set_size_limit(this->params.request_size_limit);

	return task;
}

WFHttpTask *__new_https_server_session(long long, CommConnection *,
									   CommService *, SSL_CTX *,
									   http_process_t&);

/* On Windows platform, please use 'WFHttpsServer' to start a https server. */
class WFHttpsServer : public WFHttpServer
{
public:
	WFHttpsServer(const struct WFServerParams *params,
				  http_process_t proc)
		: WFHttpServer(params, std::move(proc)), ssl_ctx(NULL)
	{ }

	WFHttpsServer(http_process_t proc)
		: WFHttpsServer(&HTTP_SERVER_PARAMS_DEFAULT, std::move(proc))
	{ }

	~WFHttpsServer()
	{
		deinit();
	}

	CommSession *new_session(long long seq, CommConnection *conn)
	{
		auto *task = __new_https_server_session(seq, conn,
												this, this->ssl_ctx,
												this->process);

		task->set_keep_alive(this->params.keep_alive_timeout);
		task->set_receive_timeout(this->params.receive_timeout);
		task->get_req()->set_size_limit(this->params.request_size_limit);

		return task;
	}

	int start(unsigned short port) = delete;
	int start(int family, unsigned short port) = delete;
	int start(const char *host, unsigned short port) = delete;
	int start(int family, const char *host, unsigned short port) = delete;
	int start(const struct sockaddr *bind_addr, socklen_t addrlen) = delete;
	int serve(int listen_fd) = delete;

	int start(unsigned short port, const char *cert_file, const char *key_file)
	{
		return start(AF_INET, NULL, port, cert_file, key_file);
	}

	int start(int family, unsigned short port,
			  const char *cert_file, const char *key_file)
	{
		return start(family, NULL, port, cert_file, key_file);
	}

	int start(const char *host, unsigned short port,
			  const char *cert_file, const char *key_file)
	{
		return start(AF_INET, host, port, cert_file, key_file);
	}

	int start(int family, const char *host, unsigned short port,
			  const char *cert_file, const char *key_file)
	{
		deinit();

		if (init(cert_file, key_file) != 0)
			return -1;

		return WFHttpServer::start(family, host, port);
	}

	int start(const struct sockaddr *bind_addr, socklen_t addrlen,
			  const char *cert_file, const char *key_file)
	{
		deinit();

		if (init(cert_file, key_file) != 0)
			return -1;

		return WFHttpServer::start(bind_addr, addrlen);
	}

	int serve(int listen_fd, const char *cert_file, const char *key_file)
	{
		deinit();

		if (init(cert_file, key_file) != 0)
			return -1;

		return WFHttpServer::serve(listen_fd);
	}

private:
	int init(const char *cert, const char *key)
	{
		ssl_ctx = new_ssl_ctx(cert, key);
		return !this->ssl_ctx;
	}

	void deinit()
	{
		if (ssl_ctx)
		{
			SSL_CTX_free(ssl_ctx);
			ssl_ctx = NULL;
		}
	}

private:
	SSL_CTX *ssl_ctx;
};

#endif

