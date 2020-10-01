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

#ifndef _WFSERVER_H_
#define _WFSERVER_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include "CommScheduler.h"
#include "WFTaskFactory.h"

struct WFServerParams
{
	size_t max_connections;
	int peer_response_timeout;	/* timeout of each read or write operation */
	int receive_timeout;	/* timeout of receiving the whole message */
	int keep_alive_timeout;
	size_t request_size_limit;
};

static constexpr struct WFServerParams SERVER_PARAMS_DEFAULT =
{
	.max_connections		=	2000,
	.peer_response_timeout	=	10 * 1000,
	.receive_timeout		=	-1,
	.keep_alive_timeout		=	60 * 1000,
	.request_size_limit		=	(size_t)-1,
};

class WFServerBase : protected CommService
{
public:
	WFServerBase(const struct WFServerParams *params) :
		conn_count(0)
	{
		this->params = *params;
		this->listen_fd = -1;
		this->unbind_finish = false;
	}

public:
	/* To start a TCP server */

	/* Start on port with IPv4. */
	int start(unsigned short port)
	{
		return start(AF_INET, NULL, port);
	}

	/* Start with family. AF_INET or AF_INET6. */
	int start(int family, unsigned short port)
	{
		return start(family, NULL, port);
	}

	/* Start with hostname and port. */
	int start(const char *host, unsigned short port)
	{
		return start(AF_INET, host, port);
	}

	/* Start with family, hostname and port. */
	int start(int family, const char *host, unsigned short port);

	/* Start with binding address. The only necessary start function. */
	int start(const struct sockaddr *bind_addr, socklen_t addrlen);

	/* To start with a specified fd. For graceful restart or SCTP server. */
	int serve(int listen_fd);

	/* stop() is a blocking operation. */
	void stop()
	{
		this->shutdown();
		this->wait_finish();
	}

	/* Nonblocking terminating the server. For stopping multiple servers.
	 * Typically, call shutdown() and then wait_finish().
	 * But indeed wait_finish() can be called before shutdown(), even before
	 * start() in another thread. */
	void shutdown();
	void wait_finish();

public:
	size_t get_conn_count() const { return this->conn_count; }

protected:
	WFServerParams params;

protected:
	virtual CommConnection *new_connection(int accept_fd);

private:
	int init(const struct sockaddr *bind_addr, socklen_t addrlen);
	virtual int create_listen_fd();
	virtual void handle_unbound();

protected:
	std::atomic<size_t> conn_count;

private:
	int listen_fd;
	bool unbind_finish;

	std::mutex mutex;
	std::condition_variable cond;

	CommScheduler *scheduler;
};

template<class REQ, class RESP>
class WFServer : public WFServerBase
{
public:
	WFServer(const struct WFServerParams *params,
			 std::function<void (WFNetworkTask<REQ, RESP> *)> proc) :
		WFServerBase(params),
		process(std::move(proc))
	{
	}

	WFServer(std::function<void (WFNetworkTask<REQ, RESP> *)> proc) :
		WFServerBase(&SERVER_PARAMS_DEFAULT),
		process(std::move(proc))
	{
	}

protected:
	virtual CommSession *new_session(long long seq, CommConnection *conn);

protected:
	std::function<void (WFNetworkTask<REQ, RESP> *)> process;
};

template<class REQ, class RESP>
CommSession *WFServer<REQ, RESP>::new_session(long long seq, CommConnection *conn)
{
	WFNetworkTask<REQ, RESP> *task;

	task = WFNetworkTaskFactory<REQ, RESP>::create_server_task(this->process);
	task->set_keep_alive(this->params.keep_alive_timeout);
	task->set_receive_timeout(this->params.receive_timeout);
	task->get_req()->set_size_limit(this->params.request_size_limit);

	return task;
}

#endif

