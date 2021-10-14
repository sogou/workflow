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

#include <Winsock2.h>
#include <Ioapiset.h>
#include <Mswsock.h>
#include <Synchapi.h>
#include <stdint.h>
#include <string.h>
#include <atomic>
#include <chrono>
#include <set>
#include "PlatformSocket.h"
#include "WinPoller.h"

#define GET_CURRENT_MS	std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()

#define IOCP_KEY_HANDLE		1
#define IOCP_KEY_STOP		2

static OVERLAPPED __stop_overlap;

class IOCPData
{
public:
	poller_data data;
	OVERLAPPED overlap;
	int64_t deadline;
	bool cancel_by_timer;
	bool in_rbtree;
	bool queue_out;

	IOCPData(const struct poller_data *d, int t)
	{
		data = *d;
		memset(&overlap, 0, sizeof (OVERLAPPED));
		deadline = t;
		cancel_by_timer = false;
		in_rbtree = false;
		queue_out = false;
		ref = 1;
	}

	void incref()
	{
		ref++;
	}

	void decref()
	{
		if (--ref == 0)
			delete this;
	}

private:
	~IOCPData() { }

	std::atomic<int> ref;
};

static inline bool operator<(const IOCPData& x, const IOCPData& y)
{
	if (x.deadline != y.deadline)
		return x.deadline < y.deadline;

	return (const ULONG_PTR)(&x.overlap) < (const ULONG_PTR)(&y.overlap);
}

class CMP
{
public:
	bool operator() (IOCPData *x, IOCPData *y) const
	{
		return *x < *y;
	}
};

WinPoller::WinPoller(size_t poller_threads)
{
	timer_queue_ = new std::set<IOCPData *, CMP>();
	timer_thread_ = NULL;
	stop_ = false;
	timer_handle_ = CreateWaitableTimer(NULL, FALSE, NULL);
	iocp_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, (DWORD)poller_threads);

	GUID GuidConnectEx = WSAID_CONNECTEX;
	//GUID GuidDisconnectEx = WSAID_DISCONNECTEX;
	DWORD dwBytes;

	lpfn_sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
	if (WSAIoctl(lpfn_sockfd_, SIO_GET_EXTENSION_FUNCTION_POINTER,
				&GuidConnectEx, sizeof(GuidConnectEx),
				&lpfn_connectex_, sizeof(lpfn_connectex_),
				&dwBytes, NULL, NULL) == SOCKET_ERROR)
		lpfn_connectex_ = NULL;
/*
	if (WSAIoctl(lpfn_sockfd_, SIO_GET_EXTENSION_FUNCTION_POINTER,
				&GuidDisconnectEx, sizeof(GuidDisconnectEx),
				&lpfn_disconnectex_, sizeof(lpfn_disconnectex_),
				&dwBytes, NULL, NULL) == SOCKET_ERROR)
		lpfn_disconnectex_ = NULL;*/

	if (!timer_handle_ || !iocp_ || !lpfn_connectex_)
		abort();
}

WinPoller::~WinPoller()
{
	closesocket(lpfn_sockfd_);
	CloseHandle(iocp_);
	CloseHandle(timer_handle_);
	delete (std::set<IOCPData *, CMP> *)timer_queue_;
}

int WinPoller::start()
{
	timer_thread_ = new std::thread(&WinPoller::timer_routine, this);
	stop_ = false;
	return 0;
}

void WinPoller::stop()
{
	LARGE_INTEGER due;

	due.QuadPart = -1;
	stop_ = true;
	SetWaitableTimer(timer_handle_, &due, 0, NULL, NULL, FALSE);

	if (timer_thread_)
	{
		timer_thread_->join();
		delete timer_thread_;
		timer_thread_ = NULL;
	}

	PostQueuedCompletionStatus(iocp_, sizeof (OVERLAPPED),
							   IOCP_KEY_STOP, &__stop_overlap);
}

void WinPoller::timer_routine()
{
	auto *timer_queue = (std::set<IOCPData *, CMP> *)timer_queue_;

	while (!stop_)
	{
		if (WaitForSingleObject(timer_handle_, INFINITE) == WAIT_OBJECT_0)
		{
			std::lock_guard<std::mutex> lock(timer_mutex_);

			if (timer_queue->empty())
				continue;

			int64_t cur_ms = GET_CURRENT_MS;

			while (!timer_queue->empty())
			{
				const auto it = timer_queue->cbegin();
				IOCPData *iocp_data = *it;

				if (cur_ms < iocp_data->deadline)
				{
					LARGE_INTEGER due;

					due.QuadPart = iocp_data->deadline - cur_ms;
					due.QuadPart *= -10000;
					SetWaitableTimer(timer_handle_, &due, 0, NULL, NULL, FALSE);
					break;
				}

				iocp_data->in_rbtree = false;
				iocp_data->cancel_by_timer = true;
				if (iocp_data->data.operation == PD_OP_SLEEP)
					PostQueuedCompletionStatus(iocp_, sizeof IOCPData, IOCP_KEY_HANDLE, &iocp_data->overlap);
				else if (CancelIoEx(iocp_data->data.handle, &iocp_data->overlap) == 0 && GetLastError() == ERROR_NOT_FOUND)
					iocp_data->cancel_by_timer = false;

				timer_queue->erase(it);
				iocp_data->decref();
			}
		}
	}

	std::lock_guard<std::mutex> lock(timer_mutex_);

	while (!timer_queue->empty())
	{
		const auto it = timer_queue->cbegin();
		IOCPData *iocp_data = *it;

		iocp_data->in_rbtree = false;
		if (iocp_data->data.operation == PD_OP_SLEEP)
			PostQueuedCompletionStatus(iocp_, sizeof IOCPData, IOCP_KEY_HANDLE, &iocp_data->overlap);
		else
			CancelIoEx(iocp_data->data.handle, &iocp_data->overlap);

		timer_queue->erase(it);
		iocp_data->decref();
	}
}

int WinPoller::bind(HANDLE handle)
{
	if (CreateIoCompletionPort(handle, iocp_, IOCP_KEY_HANDLE, 0) != NULL)
		return 0;

	errno = GetLastError();
	return -1;
}

void WinPoller::unbind_socket(SOCKET sockfd) const
{
	CancelIoEx((HANDLE)sockfd, NULL);
	shutdown(sockfd, SD_BOTH);
}

int WinPoller::cancel_pending_io(HANDLE handle) const
{
	if (CancelIoEx(handle, NULL) != 0)
		return 0;

	errno = GetLastError();
	return -1;
}

static int __accept_io(IOCPData *iocp_data, int timeout)
{
	AcceptConext *ctx = (AcceptConext *)iocp_data->data.context;
	DWORD dwBytes;
	BOOL ret = AcceptEx((SOCKET)iocp_data->data.handle, ctx->accept_sockfd,
						ctx->buf, 0, ACCEPT_ADDR_SIZE, ACCEPT_ADDR_SIZE,
						&dwBytes, &iocp_data->overlap);
	if (ret == TRUE || WSAGetLastError() == ERROR_IO_PENDING)
	{
		if (ret != TRUE && timeout == 0)
			CancelIoEx(iocp_data->data.handle, &iocp_data->overlap);

		return 0;
	}
	else
		errno = WSAGetLastError();

	return -1;
}

static int __connect_io(IOCPData *iocp_data, int timeout, void *lpfn)
{
	ConnectContext *ctx = (ConnectContext *)iocp_data->data.context;
	LPFN_CONNECTEX lpfn_connectex = (LPFN_CONNECTEX)lpfn;
	BOOL ret = lpfn_connectex((SOCKET)iocp_data->data.handle,
							  ctx->addr, ctx->addrlen, NULL, 0, NULL,
							  &iocp_data->overlap);

	if (ret == TRUE || WSAGetLastError() == ERROR_IO_PENDING)
	{
		if (ret != TRUE && timeout == 0)
			CancelIoEx(iocp_data->data.handle, &iocp_data->overlap);

		return 0;
	}

	errno = WSAGetLastError();
	return -1;
}

static int __read_io(IOCPData *iocp_data, int timeout)
{
	ReadContext *ctx = (ReadContext *)iocp_data->data.context;
	DWORD Flags = 0;
	int ret = WSARecv((SOCKET)iocp_data->data.handle, &ctx->buffer, 1, NULL, &Flags, &iocp_data->overlap, NULL);

	if (ret == 0 || WSAGetLastError() == WSA_IO_PENDING)
	{
		if (ret != 0 && timeout == 0)
			CancelIoEx(iocp_data->data.handle, &iocp_data->overlap);

		return 0;
	}

	errno = WSAGetLastError();
	return -1;
}

static int __write_io(IOCPData *iocp_data, int timeout)
{
	WriteContext *ctx = (WriteContext *)iocp_data->data.context;
	int ret = WSASend((SOCKET)iocp_data->data.handle, ctx->buffers, ctx->count, NULL, 0, &iocp_data->overlap, NULL);

	if (ret == 0 || WSAGetLastError() == WSA_IO_PENDING)
	{
		if (ret != 0 && timeout == 0)
			CancelIoEx(iocp_data->data.handle, &iocp_data->overlap);

		return 0;
	}

	errno = WSAGetLastError();
	return -1;
}

static int __sleep_io(IOCPData *iocp_data, int timeout, HANDLE iocp)
{
	if (timeout == 0)
	{
		if (PostQueuedCompletionStatus(iocp, sizeof IOCPData, IOCP_KEY_HANDLE, &iocp_data->overlap) != 0)
			return 0;

		errno = GetLastError();
		return -1;
	}

	return 0;
}

int WinPoller::transfer(const struct poller_data *data, DWORD iobytes)
{
	if (data->operation != PD_OP_USER)
	{
		errno = EINVAL;
		return -1;
	}

	IOCPData *iocp_data = new IOCPData(data, -1);
	if (PostQueuedCompletionStatus(iocp_, iobytes, IOCP_KEY_HANDLE, &iocp_data->overlap) != 0)
		return 0;

	iocp_data->decref();
	errno = GetLastError();
	return -1;
}

int WinPoller::put_io(const struct poller_data *data, int timeout)
{
	auto *timer_queue = (std::set<IOCPData *, CMP> *)timer_queue_;
	IOCPData *iocp_data = new IOCPData(data, timeout);
	bool succ;

	iocp_data->incref();//for timeout
	switch (data->operation & 0xFF)
	{
	case PD_OP_READ:
		succ = (__read_io(iocp_data, timeout) >= 0);

		break;
	case PD_OP_WRITE:
		succ = (__write_io(iocp_data, timeout) >= 0);

		break;
	case PD_OP_ACCEPT:
		succ = (__accept_io(iocp_data, timeout) >= 0);

		break;
	case PD_OP_CONNECT:
		succ = (__connect_io(iocp_data, timeout, lpfn_connectex_) >= 0);

		break;
	case PD_OP_SLEEP:
		succ = (__sleep_io(iocp_data, timeout, iocp_) >= 0);

		break;
	default:
		succ = false;
		errno = EINVAL;
		break;
	}

	if (timeout <= 0)
		iocp_data->decref();

	if (!succ)
	{
		iocp_data->decref();
		return -1;
	}

	if (timeout > 0)
	{
		iocp_data->deadline += GET_CURRENT_MS;
		timer_mutex_.lock();
		if (!iocp_data->queue_out)
		{
			iocp_data->in_rbtree = true;
			timer_queue->insert(iocp_data);
			if (*timer_queue->cbegin() == iocp_data)
			{
				LARGE_INTEGER due;

				due.QuadPart = timeout;
				due.QuadPart *= -10000;
				SetWaitableTimer(timer_handle_, &due, 0, NULL, NULL, FALSE);
			}
		}

		timer_mutex_.unlock();
	}

	return 0;
}

static void __accept_on_success(struct poller_result *res)
{
	SOCKET listen_sockfd = (SOCKET)res->data.handle;
	AcceptConext *ctx = (AcceptConext *)res->data.context;
	struct sockaddr *local;
	struct sockaddr *remote;
	int local_len = sizeof (struct sockaddr);
	int remote_len = sizeof (struct sockaddr);
	int seconds;
	int seconds_len = sizeof (int);

	if (getsockopt(ctx->accept_sockfd, SOL_SOCKET, SO_CONNECT_TIME, (char *)&seconds, &seconds_len) == 0)
	{
		if (setsockopt(ctx->accept_sockfd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&listen_sockfd, sizeof (listen_sockfd)) == 0)
		{
			GetAcceptExSockaddrs(ctx->buf, 0, ACCEPT_ADDR_SIZE, ACCEPT_ADDR_SIZE, &local, &local_len, &remote, &remote_len);
			ctx->remote = remote;
			ctx->remote_len = remote_len;
			return;
		}
	}

	res->state = PR_ST_ERROR;
	res->error = WSAGetLastError();
}

static void __connect_on_success(struct poller_result *res)
{
	SOCKET sockfd = (SOCKET)res->data.handle;
	ConnectContext *ctx = (ConnectContext *)res->data.context;
	int seconds;
	int seconds_len = sizeof (int);

	if (getsockopt(sockfd, SOL_SOCKET, SO_CONNECT_TIME, (char *)&seconds, &seconds_len) == 0)
	{
		//if (seconds == 0xFFFFFFFF) error?
		if (setsockopt(sockfd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == 0)
			return;
	}

	res->state = PR_ST_ERROR;
	res->error = WSAGetLastError();
}

int WinPoller::get_io_result(struct poller_result *res, int timeout)
{
	DWORD bytes_transferred;
	ULONG_PTR completion_key;
	OVERLAPPED* pOverlapped;
	DWORD dwMilliseconds;

	if (stop_)
		dwMilliseconds = 100;
	else if (timeout >= 0)
		dwMilliseconds = timeout;
	else
		dwMilliseconds = INFINITE;

	if (GetQueuedCompletionStatus(iocp_, &bytes_transferred, &completion_key,
								  &pOverlapped, dwMilliseconds) == FALSE)
	{
		res->state = PR_ST_ERROR;
		res->error = GetLastError();
		if (pOverlapped == NULL && res->error == ERROR_ABANDONED_WAIT_0)
			return -1;// IOCP closed

		if (res->error == ERROR_OPERATION_ABORTED)
			res->state = PR_ST_STOPPED;
	}
	else if (pOverlapped == NULL)
	{
		// An unrecoverable error occurred in the completion port.
		// Wait for the next notification
		res->state = PR_ST_ERROR;
		res->error = ENOENT;
	}
	else if (bytes_transferred == 0)
	{
		res->state = PR_ST_FINISHED;
		res->error = ECONNRESET;
	}
	else
	{
		res->state = PR_ST_SUCCESS;
		res->error = 0;
	}

	if (!pOverlapped)
		return 0;

	res->iobytes = bytes_transferred;
	if (completion_key == IOCP_KEY_STOP)
	{
		PostQueuedCompletionStatus(iocp_, sizeof (OVERLAPPED),
								   IOCP_KEY_STOP, &__stop_overlap);

		//return 0;
		return -1;// Thread over
	}

	IOCPData *iocp_data = CONTAINING_RECORD(pOverlapped, IOCPData, overlap);

	if (iocp_data->deadline > 0)// timeout > 0
	{
		timer_mutex_.lock();
		iocp_data->queue_out = true;
		if (iocp_data->in_rbtree)
		{
			iocp_data->in_rbtree = false;
			((std::set<IOCPData *, CMP> *)timer_queue_)->erase(iocp_data);
			iocp_data->decref();
		}

		timer_mutex_.unlock();

		if (res->state == PR_ST_STOPPED)
		{
			std::lock_guard<std::mutex> lock(timer_mutex_);

			if (iocp_data->cancel_by_timer)
			{
				res->state = PR_ST_TIMEOUT;
				res->error = ETIMEDOUT;
			}
		}
	}
	else if (iocp_data->deadline == 0 && res->state == PR_ST_STOPPED)// timeout == 0
	{
		res->state = PR_ST_TIMEOUT;
		res->error = ETIMEDOUT;
	}

	res->data = iocp_data->data;
	if (res->state == PR_ST_SUCCESS || res->state == PR_ST_FINISHED)
	{
		switch (res->data.operation)
		{
		case PD_OP_ACCEPT:
			__accept_on_success(res);

			break;
		case PD_OP_CONNECT:
			__connect_on_success(res);

			break;
		}
	}

	iocp_data->decref();

	return 1;
}

