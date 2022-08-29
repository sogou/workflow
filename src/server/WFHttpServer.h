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

class WFHttpsServer : public WFHttpServer
{
	static long ssl_ctx_callback(SSL *, int *, void *)
	{
		return SSL_TLSEXT_ERR_OK;
	}

public:
	WFHttpsServer(const char *cert, const char *key,
				  const struct WFServerParams *params,
				  http_process_t proc)
		: WFHttpServer(params, std::move(proc))
	{
		ssl_ctx = WFGlobal::new_ssl_server_ctx();
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
		SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM);
		SSL_CTX_set_tlsext_servername_callback(ssl_ctx, ssl_ctx_callback);
		SSL_CTX_set_tlsext_servername_arg(ssl_ctx, this);
	}

	WFHttpsServer(const char *cert, const char *key, http_process_t proc)
		: WFHttpsServer(cert, key, &HTTP_SERVER_PARAMS_DEFAULT, std::move(proc))
	{ }

	~WFHttpsServer()
	{
		SSL_CTX_free(ssl_ctx);
	}

	CommSession *new_session(long long seq, CommConnection *conn)
	{
		auto *task = __new_https_server_session(seq, conn,
			this, this->ssl_ctx, this->process);

		task->set_keep_alive(this->params.keep_alive_timeout);
		task->set_receive_timeout(this->params.receive_timeout);
		task->get_req()->set_size_limit(this->params.request_size_limit);

		return task;
	}

	// user cannot use start with cert_file and key_file

private:
	SSL_CTX *ssl_ctx;
};

#endif

