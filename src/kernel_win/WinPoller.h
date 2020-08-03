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

#ifndef _WPOLLER_H_
#define _WPOLLER_H_

#include <thread>
#include <mutex>
#include "PlatformSocket.h"

#define ACCEPT_ADDR_SIZE	(sizeof (struct sockaddr_storage) + 16)

struct poller_data
{
	HANDLE handle;
	void *context;
#define PD_OP_READ			1
#define PD_OP_WRITE			2
#define PD_OP_ACCEPT		3
#define PD_OP_CONNECT		4
#define PD_OP_SLEEP			5
#define PD_OP_USER			16
	uint16_t operation;
};

struct poller_result
{
#define PR_ST_SUCCESS		0
#define PR_ST_FINISHED		1
#define PR_ST_ERROR			2
#define PR_ST_STOPPED		5
#define PR_ST_TIMEOUT		6
	int state;
	int error;
	DWORD iobytes;
	struct poller_data data;
};

class AcceptConext
{
public:
	void *service;
	SOCKET accept_sockfd;

	char *buf;
	struct sockaddr *remote;
	int remote_len;

	AcceptConext(void *sc)
	{
		service = sc;

		buf = new char[ACCEPT_ADDR_SIZE * 2];
	}

	~AcceptConext()
	{
		delete []buf;
	}
};

class ConnectContext
{
public:
	void *entry;
	struct sockaddr *addr;
	socklen_t addrlen;

	ConnectContext(void *e, struct sockaddr *a, socklen_t l)
	{
		entry = e;
		addr = a;
		addrlen = l;
	}
};

class ReadContext
{
public:
	void *entry;
	DWORD msgsize;
	WSABUF buffer;

	ReadContext(void *e)
	{
		entry = e;
		msgsize = 0;
	}
};

class WriteContext
{
public:
	char *buf;
	void *entry;
	WSABUF *buffers;
	DWORD count;

	WriteContext(void *e)
	{
		buf = NULL;
		entry = e;
	}

	~WriteContext()
	{
		delete []buf;
	}
};

class WinPoller
{
public:
	WinPoller(size_t poller_threads);
	~WinPoller();

	int start();
	void stop();

	int bind(HANDLE handle);
	void unbind_socket(SOCKET sockfd) const;

	int transfer(const struct poller_data *data, DWORD iobytes);
	int put_io(const struct poller_data *data, int timeout);
	int get_io_result(struct poller_result *res, int timeout);
	int cancel_pending_io(HANDLE handle) const;

	void timer_routine();

private:
	void *timer_queue_;
	std::mutex timer_mutex_;
	std::thread *timer_thread_;
	HANDLE timer_handle_;
	HANDLE iocp_;
	SOCKET lpfn_sockfd_;
	void *lpfn_connectex_;
	//void *lpfn_disconnectex_;
	volatile bool stop_;
};

#endif

