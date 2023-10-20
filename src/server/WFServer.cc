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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
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

int WFServerBase::init(const struct sockaddr *bind_addr, socklen_t addrlen)
{
	int timeout = this->params.peer_response_timeout;

	if (this->params.receive_timeout >= 0)
	{
		if ((unsigned int)timeout > (unsigned int)this->params.receive_timeout)
			timeout = this->params.receive_timeout;
	}

	if (this->CommService::init(bind_addr, addrlen, -1, timeout) < 0)
		return -1;

	this->scheduler = WFGlobal::get_scheduler();
	return 0;
}

int WFServerBase::create_listen_fd()
{
	if (this->listen_fd < 0)
	{
		const struct sockaddr *bind_addr;
		socklen_t addrlen;
		int reuse = 1;

		this->get_addr(&bind_addr, &addrlen);
		this->listen_fd = socket(bind_addr->sa_family, SOCK_STREAM, 0);
		if (this->listen_fd >= 0)
		{
			setsockopt(this->listen_fd, SOL_SOCKET, SO_REUSEADDR,
					   &reuse, sizeof (int));
		}
	}
	else
		this->listen_fd = dup(this->listen_fd);

	return this->listen_fd;
}

WFConnection *WFServerBase::new_connection(int accept_fd)
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

void WFServerBase::delete_connection(WFConnection *conn)
{
	delete (WFServerConnection *)conn;
}

void WFServerBase::handle_unbound()
{
	this->mutex.lock();
	this->unbind_finish = true;
	this->cond.notify_one();
	this->mutex.unlock();
}

int WFServerBase::start(const struct sockaddr *bind_addr, socklen_t addrlen)
{
	if (this->init(bind_addr, addrlen) >= 0)
	{
		if (this->scheduler->bind(this) >= 0)
			return 0;

		this->deinit();
	}

	this->listen_fd = -1;
	return -1;
}

int WFServerBase::start(int family, const char *host, unsigned short port)
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
		ret = start(addrinfo->ai_addr, (socklen_t)addrinfo->ai_addrlen);
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

int WFServerBase::serve(int listen_fd)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof ss;

	if (getsockname(listen_fd, (struct sockaddr *)&ss, &len) < 0)
		return -1;

	this->listen_fd = listen_fd;
	return start((struct sockaddr *)&ss, len);
}

void WFServerBase::shutdown()
{
	this->listen_fd = -1;
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

