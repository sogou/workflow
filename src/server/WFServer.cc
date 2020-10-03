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
           Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include "CommScheduler.h"
#include "WFConnection.h"
#include "WFGlobal.h"
#include "WFServer.h"

#define PORT_STR_MAX	5

class WFServerConnection : public WFConnection
{
public:
	WFServerConnection(std::atomic<size_t> *conn_count)
	{
		this->conn_count = conn_count;
	}

	virtual ~WFServerConnection()
	{
		(*this->conn_count)--;
	}

private:
	std::atomic<size_t> *conn_count;
};

int WFServerBase::init(const struct sockaddr *bind_addr, socklen_t addrlen,
					   const char *cert_file, const char *key_file)
{
	int timeout = this->params.peer_response_timeout;

	if (this->params.receive_timeout >= 0)
	{
		if ((unsigned int)timeout > (unsigned int)this->params.receive_timeout)
			timeout = this->params.receive_timeout;
	}

	if (this->CommService::init(bind_addr, addrlen, -1, timeout) < 0)
		return -1;

	if (key_file && cert_file)
	{
		SSL_CTX *ssl_ctx = WFGlobal::get_ssl_server_ctx();

		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
		if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
			SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0)
		{
			this->deinit();
			return -1;
		}

		this->set_ssl(ssl_ctx, params.ssl_accept_timeout);
	}

	this->scheduler = WFGlobal::get_scheduler();
	return 0;
}

int WFServerBase::create_listen_fd()
{
	int listen_fd  = this->listen_fd;

	if (listen_fd < 0)
	{
		const struct sockaddr *bind_addr;
		socklen_t addrlen;
		int reuse = 1;

		this->get_addr(&bind_addr, &addrlen);
		listen_fd = socket(bind_addr->sa_family, SOCK_STREAM, 0);
		if (listen_fd >= 0)
		{
			setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
					   &reuse, sizeof (int));
		}
	}

	return listen_fd;
}

CommConnection *WFServerBase::new_connection(int accept_fd)
{
	if (++this->conn_count <= this->params.max_connections ||
		this->drain(1) == 1)
	{
		int reuse = 1;
		setsockopt(accept_fd, SOL_SOCKET, SO_REUSEADDR,
				   &reuse, sizeof (int));
		return new WFServerConnection(&this->conn_count);
	}

	this->conn_count--;
	errno = EMFILE;
	return NULL;
}

void WFServerBase::handle_unbound()
{
	this->mutex.lock();
	this->unbind_finish = true;
	this->cond.notify_one();
	this->mutex.unlock();
}

int WFServerBase::start(const struct sockaddr *bind_addr, socklen_t addrlen,
						const char *cert_file, const char *key_file)
{
	if (this->init(bind_addr, addrlen, cert_file, key_file) >= 0)
	{
		if (this->scheduler->bind(this) >= 0)
			return 0;

		this->deinit();
	}

	return -1;
}

int WFServerBase::start(int family, const char *host, unsigned short port,
						const char *cert_file, const char *key_file)
{
	struct addrinfo hints = {
		.ai_flags		=	AI_PASSIVE,
		.ai_family		=	family,
		.ai_socktype	=	SOCK_STREAM,
	};
	struct addrinfo *addrinfo;
	char port_str[PORT_STR_MAX + 1];
	int ret;

	snprintf(port_str, PORT_STR_MAX + 1, "%d", port);
	ret = getaddrinfo(host, port_str, &hints, &addrinfo);
	if (ret == 0)
	{
		ret = start(addrinfo->ai_addr, (socklen_t)addrinfo->ai_addrlen,
					cert_file, key_file);
		freeaddrinfo(addrinfo);
	}
	else
	{
		if (ret != EAI_SYSTEM)
			errno = EINVAL;
		ret = -1;
	}

	return ret;
}

static int __get_addr_bound(int sockfd, struct sockaddr *addr, socklen_t *len)
{
	int family;
	socklen_t i;

	if (getsockname(sockfd, addr, len) < 0)
		return -1;

	family = addr->sa_family;
	addr->sa_family = 0;
	for (i = 0; i < *len; i++)
	{
		if (((char *)addr)[i])
			break;
	}

	if (i == *len)
	{
		errno = EINVAL;
		return -1;
	}

	addr->sa_family = family;
	return 0;
}

int WFServerBase::serve(int listen_fd,
						const char *cert_file, const char *key_file)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof ss;
	int ret;

	if (__get_addr_bound(listen_fd, (struct sockaddr *)&ss, &len) < 0)
		return -1;

	listen_fd = dup(listen_fd);
	if (listen_fd < 0)
		return -1;

	this->listen_fd = listen_fd;
	ret = start((struct sockaddr *)&ss, len, cert_file, key_file);
	this->listen_fd = -1;
	return ret;
}

void WFServerBase::shutdown()
{
	this->scheduler->unbind(this);
}

void WFServerBase::wait_finish()
{
	std::unique_lock<std::mutex> lock(this->mutex);

	while (!this->unbind_finish)
		this->cond.wait(lock);

	this->deinit();
	this->unbind_finish = false;
	lock.unlock();
}

