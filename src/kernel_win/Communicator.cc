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
#include <Winsock2.h>
#include <io.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <chrono>
#include <atomic>
#include <vector>
#include "PlatformSocket.h"
#include "list.h"
#include "thrdpool.h"
#include "Communicator.h"

#define GET_CURRENT_MS	std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
#define READ_BUFSIZE	(64 * 1024)

#define TYPE_IDLE			0x0100
#define TYPE_SSL_CONNECT	0x0200
#define TYPE_SSL_ACCEPT		0x0400

struct CommConnEntry
{
	struct list_head list;
	CommConnection *conn;
	long long seq;
	SOCKET sockfd;
#define CONN_STATE_IDLE			4
#define CONN_STATE_KEEPALIVE	5
#define CONN_STATE_FREE			6
	int state;
	std::atomic<int> ref;
	SSL *ssl;
	BIO *bio_send;
	BIO *bio_recv;
	CommSession *session;
	CommTarget *target;
	CommService *service;
	WinPoller *poller;
	char *readbuf;
	//WSABUF *writebufs;
	std::vector<WSABUF> writebufs;
};

static inline int __set_fd_nonblock(SOCKET fd)
{
	unsigned long mode = 1;
	int ret = ioctlsocket(fd, FIONBIO, &mode);

	if (ret == SOCKET_ERROR)
	{
		errno = WSAGetLastError();
		return -1;
	}

	return 0;
}

static int __bind_and_listen(SOCKET listen_sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof (struct sockaddr_storage);

	if (getsockname(listen_sockfd, (struct sockaddr *)&ss, &len) == SOCKET_ERROR)
	{
		if (WSAGetLastError() == WSAEINVAL)
		{
			if (bind(listen_sockfd, addr, addrlen) == SOCKET_ERROR)
				return -1;
		}
	}

	if (listen(listen_sockfd, SOMAXCONN) == SOCKET_ERROR)
		return -1;

	return 0;
}

static int __bind_any(SOCKET sockfd, int sa_family)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;

	memset(&addr, 0, sizeof (struct sockaddr_storage));
	addr.ss_family = sa_family;
	if (sa_family == AF_INET)
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
		sin->sin_addr.s_addr = INADDR_ANY;
		sin->sin_port = 0;
		addrlen = sizeof (struct sockaddr_in);
	}
	else if (sa_family == AF_INET6)
	{
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
		sin6->sin6_addr = in6addr_any;
		sin6->sin6_port = 0;
		addrlen = sizeof (struct sockaddr_in6);
	}
	else
		addrlen = sizeof (struct sockaddr_storage);

	if (bind(sockfd, (struct sockaddr *)&addr, addrlen) == SOCKET_ERROR)
		return -1;

	return 0;
}

static int __create_ssl(SSL_CTX *ssl_ctx, CommConnEntry *entry)
{
	entry->bio_send = BIO_new(BIO_s_mem());
	if (entry->bio_send)
	{
		entry->bio_recv = BIO_new(BIO_s_mem());
		if (entry->bio_recv)
		{
			entry->ssl = SSL_new(ssl_ctx);
			if (entry->ssl)
			{
				BIO_set_nbio(entry->bio_recv, 0);
				BIO_set_nbio(entry->bio_send, 0);
				SSL_set_bio(entry->ssl, entry->bio_recv, entry->bio_send);
				return 0;
			}

			BIO_free(entry->bio_recv);
		}

		BIO_free(entry->bio_send);
	}

	return -1;
}

static int __ssl_accept(SSL_CTX *ssl_ctx, CommConnEntry *entry)
{
	if (__create_ssl(ssl_ctx, entry) >= 0)
	{
		SSL_set_accept_state(entry->ssl);
		return 0;
	}

	return -1;
}

static int __ssl_connect(SSL_CTX *ssl_ctx, CommConnEntry *entry)
{
	if (__create_ssl(ssl_ctx, entry) >= 0)
	{
		SSL_set_connect_state(entry->ssl);
		return 0;
	}

	return -1;
}

int CommTarget::init(const struct sockaddr *addr, socklen_t addrlen,
					 int connect_timeout, int response_timeout)
{
	this->addr = (struct sockaddr *)malloc(addrlen);
	if (this->addr)
	{
		memcpy(this->addr, addr, addrlen);
		this->addrlen = addrlen;
		this->connect_timeout = connect_timeout;
		this->response_timeout = response_timeout;
		INIT_LIST_HEAD(&this->idle_list);

		this->ssl_ctx = NULL;
		this->ssl_connect_timeout = 0;
		return 0;
	}

	return -1;
}

void CommTarget::deinit()
{
	free(this->addr);
}

static int __sync_send(const void *buf, size_t size, CommConnEntry *entry)
{
	int error;
	int ret;

	if (!entry->ssl)
		return send(entry->sockfd, (const char *)buf, (int)size, 0);

	if (size == 0)
		return 0;

	ret = SSL_write(entry->ssl, buf, (int)size);
	if (ret <= 0)
	{
		error = SSL_get_error(entry->ssl, ret);
		if (error != SSL_ERROR_SYSCALL)
			errno = -error;

		return -1;
	}

	int sz = BIO_pending(entry->bio_send);

	char *ssl_buf = new char[sz];
	if (sz == BIO_read(entry->bio_send, ssl_buf, sz))
		ret = send(entry->sockfd, ssl_buf, (int)sz, 0);
	else
		ret = -1;

	delete []ssl_buf;
	if (ret == sz)
		return size;

	if (ret > 0)
	{
		errno = ENOBUFS;
		ret = -1;
	}

	return ret;
}

int CommMessageIn::feedback(const void *buf, size_t size)
{
	return __sync_send(buf, size, this->entry);
}

int CommService::init(const struct sockaddr *bind_addr, socklen_t addrlen,
					  int listen_timeout, int response_timeout)
{
	this->bind_addr = (struct sockaddr *)malloc(addrlen);
	if (this->bind_addr)
	{
		memcpy(this->bind_addr, bind_addr, addrlen);
		this->addrlen = addrlen;
		this->listen_timeout = listen_timeout;
		this->response_timeout = response_timeout;
		INIT_LIST_HEAD(&this->alive_list);

		this->ssl_ctx = NULL;
		this->ssl_accept_timeout = 0;
		return 0;
	}

	return -1;
}

void CommService::deinit()
{
	free(this->bind_addr);
}

int CommService::drain(int max)
{
	CommConnEntry *entry;
	struct list_head *pos;
	int cnt = 0;

	this->mutex.lock();
	while (cnt != max && !list_empty(&this->alive_list))
	{
		pos = this->alive_list.next;
		entry = list_entry(pos, CommConnEntry, list);
		//todo timeout clean??
		{
			list_del(pos);
			entry->state = CONN_STATE_FREE;
			cnt++;
			entry->poller->unbind_socket(entry->sockfd);
			//CANNOT release_conn now
		}
	}

	this->mutex.unlock();
	return cnt;
}

inline void CommService::incref()
{
	this->ref++;
}

inline void CommService::decref()
{
	if (--this->ref == 0)
		this->handle_unbound();
}

class CommServiceTarget : public CommTarget
{
public:
	void incref()
	{
		this->ref++;
	}

	void decref()
	{
		if (--this->ref == 0)
		{
			this->service->decref();
			this->deinit();
			delete this;
		}
	}

	int init(const struct sockaddr *addr, socklen_t addrlen,
			 SOCKET accept_sockfd, CommService *service)
	{
		if (this->CommTarget::init(addr, addrlen, 0, service->response_timeout) >= 0)
		{
			service->incref();
			this->service = service;
			this->accept_sockfd = accept_sockfd;
			this->ref = 1;
			return 0;
		}

		return -1;
	}

private:
	SOCKET accept_sockfd;
	std::atomic<int> ref;

private:
	CommService *service;

private:
	virtual int create_connect_fd()
	{
		errno = EPERM;
		return -1;
	}

	friend class Communicator;
};

CommSession::~CommSession()
{
	if (!this->passive)
		return;

	CommConnEntry *entry;
	struct list_head *pos;
	CommServiceTarget *target = (CommServiceTarget *)this->target;
	if (this->passive == 1)
	{
		target->mutex.lock();
		if (!list_empty(&target->idle_list))
		{
			pos = target->idle_list.next;
			entry = list_entry(pos, CommConnEntry, list);
			entry->poller->cancel_pending_io((HANDLE)entry->sockfd);
		}

		target->mutex.unlock();
	}

	target->decref();
}

int Communicator::init(size_t poller_threads, size_t handler_threads)
{
	if (poller_threads == 0)
	{
		errno = EINVAL;
		return -1;
	}

	this->poller = new WinPoller(poller_threads);
	if (this->poller->start() >= 0)
	{
		this->total_fd_cnt = 0;
		if (this->create_handler_threads(handler_threads) >= 0)
			return 0;
	}

	return -1;
}

void Communicator::deinit()
{
	this->stop_flag = true;
	this->poller->stop();//todo timeout
	thrdpool_destroy(NULL, this->thrdpool);
	delete this->poller;
}

class EventContext
{
public:
	CommConnEntry *entry;
	int error;
#define EVENT_CLIENT_REQUEST_FAILED		1
#define EVENT_SERVER_REPLY_FAILED		2
	uint8_t event;

	EventContext(CommConnEntry *e, int err, uint8_t ev)
	{
		entry = e;
		error = err;
		event = ev;
	}
};

void Communicator::handle_event_result(struct poller_result *res)
{
	EventContext *ctx = (EventContext *)res->data.context;
	CommConnEntry *entry = (CommConnEntry *)ctx->entry;
	CommTarget *target = entry->target;

	switch (ctx->event)
	{
	case EVENT_CLIENT_REQUEST_FAILED:
		target->release(0);
		entry->session->handle(CS_STATE_ERROR, ctx->error);
		if (--entry->ref == 0)
			this->release_conn(entry);

		break;

	case EVENT_SERVER_REPLY_FAILED:
		entry->session->handle(CS_STATE_ERROR, ctx->error);
		if (--entry->ref == 0)
			this->release_conn(entry);

		break;

	default:
		assert(0);
		break;
	}

	delete ctx;
}

void Communicator::handle_sleep_result(struct poller_result *res)
{
	SleepSession *session = (SleepSession *)res->data.context;
	int cs_state;

	switch (res->state)
	{
	case PR_ST_SUCCESS:
	case PR_ST_TIMEOUT:
		cs_state = CS_STATE_SUCCESS;
		res->error = 0;
		break;

	case PR_ST_FINISHED:
	case PR_ST_ERROR:
		cs_state = CS_STATE_ERROR;
		break;

	case PR_ST_STOPPED:
		cs_state = CS_STATE_STOPPED;
		break;

	default:
		assert(0);
		break;
	}

	session->handle(cs_state, res->error);
	total_fd_cnt--;
}

int Communicator::request(CommSession *session, CommTarget *target)
{
	CommConnEntry *entry;
	struct poller_data data;
	int ret;

	if (session->passive)
	{
		errno = EINVAL;
		return -1;
	}

	session->target = target;
	session->out = NULL;
	session->in = NULL;
	entry = this->get_idle_conn(target);
	if (entry)
	{
		entry->session = session;
		session->conn = entry->conn;
		session->seq = entry->seq++;
		session->out = session->message_out();
		if (session->out)
		{
			ret = this->send_message(entry);
			if (ret >= 0)
				return 0;
		}

		// CANNOT call sync  this->release_conn(entry);
		// MUST   call async handle_request_result->handle ERROR
		auto *new_ctx = new EventContext(entry, errno, EVENT_CLIENT_REQUEST_FAILED);

		data.operation = PD_OP_USER;
		data.handle = (HANDLE)entry->sockfd;
		data.context = new_ctx;
		if (this->poller->put_io(&data, -1) < 0)
			delete new_ctx;

		return 0;
	}
	else
	{
		entry = this->launch_conn(session, target);
		if (entry)
		{
			session->conn = entry->conn;
			session->seq = entry->seq++;
			auto *new_ctx = new ConnectContext(entry, target->addr, target->addrlen);

			data.operation = PD_OP_CONNECT;
			data.handle = (HANDLE)entry->sockfd;
			data.context = new_ctx;
			if (this->poller->put_io(&data, session->target->connect_timeout) >= 0)
				return 0;

			delete new_ctx;
			this->poller->unbind_socket(entry->sockfd);
			this->release_conn(entry);
		}

		session->conn = NULL;
		session->seq = 0;
	}

	return -1;
}

int Communicator::reply(CommSession *session)
{
	CommConnEntry *entry;
	int ret;

	if (session->passive != 1)
	{
		errno = session->passive ? ENOENT : EINVAL;
		return -1;
	}

	session->passive = 2;
	entry = this->get_idle_conn(session->target);
	if (entry)
	{
		session->out = session->message_out();
		if (session->out)
		{
			ret = this->send_message(entry);
			if (ret >= 0)
				return 0;
		}

		// CANNOT call sync  this->release_conn(entry);
		// MUST   call async handle_reply_result->handle ERROR
		auto *new_ctx = new EventContext(entry, errno, EVENT_SERVER_REPLY_FAILED);
		struct poller_data data;

		data.operation = PD_OP_USER;
		data.handle = (HANDLE)entry->sockfd;
		data.context = new_ctx;
		if (this->poller->transfer(&data, sizeof (EventContext)) < 0)
			delete new_ctx;

		return 0;
	}

	return -1;
}

int Communicator::push(const void *buf, size_t size, CommSession *session)
{
	CommTarget *target = session->target;
	CommConnEntry *entry;
	int ret;

	if (session->passive != 1)
	{
		errno = session->passive ? ENOENT : EPERM;
		return -1;
	}

	target->mutex.lock();
	if (!list_empty(&target->idle_list))
	{
		entry = list_entry(target->idle_list.next, CommConnEntry, list);
		ret = __sync_send(buf, size, entry);
	}
	else
	{
		errno = ENOENT;
		ret = -1;
	}

	target->mutex.unlock();
	return ret;
}

int Communicator::bind(CommService *service)
{
	size_t i;
	SOCKET listen_sockfd = this->nonblock_listen(service);
	poller_data data;

	if (listen_sockfd != INVALID_SOCKET)
	{
		if (this->poller->bind((HANDLE)listen_sockfd) >= 0)
		{
			if (__bind_and_listen(listen_sockfd, service->bind_addr, service->addrlen) >= 0)
			{
				service->listen_sockfd = listen_sockfd;
				service->ref = 1;
				for (i = 0; i < this->handler_threads; i++)
				{
					auto *new_ctx = new AcceptConext(service);

					data.operation = PD_OP_ACCEPT;
					data.handle = (HANDLE)listen_sockfd;
					data.context = new_ctx;
					new_ctx->accept_sockfd = this->nonblock_accept(service);
					if (new_ctx->accept_sockfd != INVALID_SOCKET)
					{
						if (this->poller->put_io(&data, service->listen_timeout) >= 0)
							continue;

						closesocket(new_ctx->accept_sockfd);
					}

					delete new_ctx;
					break;
				}

				if (i == this->handler_threads)
				{
					total_fd_cnt++;
					return 0;
				}

				service->listen_sockfd = INVALID_SOCKET;
				service->ref = 0;
			}

			this->poller->unbind_socket(listen_sockfd);
		}

		closesocket(listen_sockfd);
	}

	return -1;
}

void Communicator::unbind(CommService *service)
{
	this->poller->unbind_socket(service->listen_sockfd);
	closesocket(service->listen_sockfd);
	service->listen_sockfd = INVALID_SOCKET;
	this->total_fd_cnt--;
	service->drain(-1);
	service->decref();
}

int Communicator::sleep(SleepSession *session)
{
	struct timespec value;

	if (session->duration(&value) >= 0)
	{
		struct poller_data data;

		data.operation = PD_OP_SLEEP;
		data.handle = NULL;
		data.context = session;
		if (this->poller->put_io(&data, (int)(value.tv_sec * 1000 + value.tv_nsec / 1000000)) >= 0)
		{
			total_fd_cnt++;
			return 0;
		}
	}

	return -1;
}

int Communicator::io_bind(IOService *service)
{
	return -1;
}

void Communicator::io_unbind(IOService *service)
{
}

int Communicator::create_handler_threads(size_t handler_threads)
{
	struct thrdpool_task task = {Communicator::handler_thread_routine, this};
	size_t i;

	this->handler_threads = handler_threads;
	this->thrdpool = thrdpool_create(handler_threads, 0);
	if (this->thrdpool)
	{
		this->stop_flag = false;
		for (i = 0; i < handler_threads; i++)
		{
			if (thrdpool_schedule(&task, this->thrdpool) < 0)
				break;
		}

		if (i == handler_threads)
			return 0;

		this->stop_flag = true;
		this->poller->stop();
		thrdpool_destroy(NULL, this->thrdpool);
	}

	return -1;
}

CommConnEntry *Communicator::accept_conn(CommServiceTarget *target, CommService *service)
{
	SOCKET sockfd = target->accept_sockfd;

	if (sockfd != INVALID_SOCKET)
	{
		if (this->poller->bind((HANDLE)sockfd) >= 0)
		{
			CommConnEntry *entry = new CommConnEntry;

			entry->readbuf = new char[READ_BUFSIZE];
			entry->conn = service->new_connection((int)sockfd);
			if (entry->conn)
			{
				entry->seq = 0;
				entry->sockfd = sockfd;
				entry->state = CONN_STATE_FREE;
				entry->ref = 1;
				entry->ssl = NULL;
				entry->session = NULL;
				entry->target = target;
				entry->service = service;
				entry->poller = this->poller;
				this->total_fd_cnt++;
				return entry;
			}

			delete entry->readbuf;
			delete entry;
			this->poller->unbind_socket(sockfd);
		}

		closesocket(sockfd);
	}

	return NULL;
}

CommConnEntry *Communicator::launch_conn(CommSession *session, CommTarget *target)
{
	SOCKET sockfd = this->nonblock_connect(target);

	if (sockfd != INVALID_SOCKET)
	{
		if (this->poller->bind((HANDLE)sockfd) >= 0)
		{
			if (__bind_any(sockfd, target->addr->sa_family) >= 0)
			{
				CommConnEntry *entry = new CommConnEntry;

				entry->readbuf = new char[READ_BUFSIZE];
				entry->conn = target->new_connection((int)sockfd);
				if (entry->conn)
				{
					entry->seq = 0;
					entry->sockfd = sockfd;
					entry->state = CONN_STATE_FREE;
					entry->ref = 1;
					entry->ssl = NULL;
					entry->session = session;
					entry->target = target;
					entry->service = NULL;
					entry->poller = this->poller;
					this->total_fd_cnt++;
					return entry;
				}

				delete entry->readbuf;
				delete entry;
			}

			this->poller->unbind_socket(sockfd);
		}

		closesocket(sockfd);
	}

	return NULL;
}

void Communicator::release_conn(CommConnEntry *entry)
{
	CommTarget *target = entry->target;
	CommService *service = entry->service;

	closesocket(entry->sockfd);
	this->total_fd_cnt--;
	if (entry->ssl)
		SSL_free(entry->ssl);

	delete entry->conn;
	delete entry->readbuf;
	delete entry;
	if (service)
		((CommServiceTarget *)target)->decref();
}

int Communicator::create_service_session(CommConnEntry *entry)
{
	CommService *service = entry->service;
	CommTarget *target = entry->target;
	CommSession *session;
	int timeout;

	session = service->new_session(entry->seq, entry->conn);
	if (session)
	{
		session->passive = 1;
		session->target = target;
		session->conn = entry->conn;
		session->seq = entry->seq++;
		session->out = NULL;
		session->in = NULL;
		entry->session = session;

		timeout = session->first_timeout();
		if (timeout == 0)
			timeout = this->first_timeout_recv(session);
		else
		{
			session->timeout = -1;
			session->begin_time = -1;
		}
		//timeout = this->first_timeout_recv(session);
		((CommServiceTarget *)target)->incref();
		return 0;
	}

	return -1;
}

void Communicator::handle_incoming_request(struct poller_result *res)
{
	ReadContext *ctx = (ReadContext *)res->data.context;
	CommConnEntry *entry = (CommConnEntry *)ctx->entry;
	CommTarget *target = entry->target;
	CommSession *session = NULL;
	int timeout;
	int cs_state;
	int ret;

	if (ctx->msgsize == 0)
	{
		target->mutex.lock();
		if (entry->state == CONN_STATE_KEEPALIVE)
		{
			entry->service->mutex.lock();
			if (entry->state == CONN_STATE_KEEPALIVE)
			{
				list_del(&entry->list);
				entry->state = CONN_STATE_FREE;
			}

			entry->service->mutex.unlock();
		}

		target->mutex.unlock();
	}
	else
		session = entry->session;

	switch (res->state)
	{
	case PR_ST_SUCCESS:
		if (ctx->msgsize == 0)
		{
			if (create_service_session(entry) < 0)
			{
				cs_state = CS_STATE_ERROR;
				res->error = errno;
				break;
			}

			session = entry->session;
			session->in = session->message_in();
			if (session->in)
				session->in->entry = entry;
			else
			{
				cs_state = CS_STATE_ERROR;
				res->error = errno;
				break;
			}
		}

		ctx->msgsize += res->iobytes;
		{
			size_t sz = res->iobytes;

			ret = entry->session->in->append(ctx->buffer.buf, &sz);
		}

		if (ret < 0)
		{
			cs_state = CS_STATE_ERROR;
			res->error = errno;
		}
		else if (ret == 0)
		{
			//try to continue read
			timeout = this->next_timeout(session);
			ctx->buffer.buf = entry->readbuf;
			ctx->buffer.len = READ_BUFSIZE;
			if (this->poller->put_io(&res->data, timeout) >= 0)
				return;//reuse context

			cs_state = CS_STATE_ERROR;
			res->error = errno;
		}
		else
		{
			//ret > 0
			cs_state = CS_STATE_TOREPLY;
			entry->ref++;
			res->data.operation = PD_OP_READ | TYPE_IDLE;
			ctx->buffer.buf = entry->readbuf;
			ctx->buffer.len = READ_BUFSIZE;
			std::unique_lock<std::mutex> lock(target->mutex);
			if (this->poller->put_io(&res->data, -1) >= 0)
			{
				ctx = NULL;//reuse context
				entry->state = CONN_STATE_IDLE;
				list_add(&entry->list, &target->idle_list);
				break;
			}

			lock.unlock();
			entry->ref--;
		}

		break;

	case PR_ST_FINISHED:
	case PR_ST_ERROR:
	case PR_ST_TIMEOUT:
		cs_state = CS_STATE_ERROR;
		break;

	case PR_ST_STOPPED:
		cs_state = CS_STATE_STOPPED;
		break;

	default:
		assert(0);
		break;
	}

	delete ctx;
	if (session)
		session->handle(cs_state, res->error);

	if (--entry->ref == 0)
		this->release_conn(entry);
}

void Communicator::handle_incoming_reply(struct poller_result *res)
{
	ReadContext *ctx = (ReadContext *)res->data.context;
	CommConnEntry *entry = (CommConnEntry *)ctx->entry;
	CommTarget *target = entry->target;
	CommSession *session = entry->session;
	int timeout;
	int cs_state;
	int ret;

	switch (res->state)
	{
	case PR_ST_SUCCESS:
		if (ctx->msgsize == 0)
		{
			session->in = session->message_in();
			if (session->in)
				session->in->entry = entry;
			else
			{
				cs_state = CS_STATE_ERROR;
				res->error = errno;
				break;
			}
		}

		ctx->msgsize += res->iobytes;
		{
			size_t sz = res->iobytes;

			ret = entry->session->in->append(ctx->buffer.buf, &sz);
		}

		if (ret < 0)
		{
			cs_state = CS_STATE_ERROR;
			res->error = errno;
		}
		else if (ret == 0)
		{
			//try to continue read
			timeout = this->next_timeout(session);
			ctx->buffer.buf = entry->readbuf;
			ctx->buffer.len = READ_BUFSIZE;
			if (this->poller->put_io(&res->data, timeout) >= 0)
				return;//reuse context

			cs_state = CS_STATE_ERROR;
			res->error = errno;
		}
		else
		{
			//ret > 0
			cs_state = CS_STATE_SUCCESS;
			timeout = session->keep_alive_timeout();
			if (timeout != 0 && !stop_flag)
			{
				entry->ref++;
				res->data.operation = PD_OP_READ | TYPE_IDLE;
				ctx->buffer.buf = entry->readbuf;
				ctx->buffer.len = READ_BUFSIZE;
				std::unique_lock<std::mutex> lock(target->mutex);
				if (this->poller->put_io(&res->data, timeout) >= 0)
				{
					ctx = NULL;//reuse context
					entry->state = CONN_STATE_IDLE;
					entry->session = NULL;
					list_add(&entry->list, &target->idle_list);
					break;
				}

				lock.unlock();
				entry->ref--;
			}
		}

		break;

	case PR_ST_FINISHED:
	case PR_ST_ERROR:
	case PR_ST_TIMEOUT:
		cs_state = CS_STATE_ERROR;
		break;

	case PR_ST_STOPPED:
		cs_state = CS_STATE_STOPPED;
		break;

	default:
		assert(0);
		break;
	}

	delete ctx;
	target->release(entry->state == CONN_STATE_IDLE);
	session->handle(cs_state, res->error);
	if (--entry->ref == 0)
		this->release_conn(entry);
}

void Communicator::handle_incoming_idle(struct poller_result *res)
{
	ReadContext *ctx = (ReadContext *)res->data.context;
	CommConnEntry *entry = (CommConnEntry *)ctx->entry;
	CommTarget *target = entry->target;
	CommSession *session = NULL;
	int cs_state;

	target->mutex.lock();
	if (entry->state == CONN_STATE_IDLE)
	{
		list_del(&entry->list);
		entry->state = CONN_STATE_FREE;
	}
	else
		session = entry->session;

	target->mutex.unlock();

	switch (res->state)
	{
	case PR_ST_SUCCESS:
		cs_state = CS_STATE_ERROR;
		res->error = EBADMSG;
		break;

	case PR_ST_FINISHED:
	case PR_ST_ERROR:
		cs_state = CS_STATE_ERROR;
		break;

	case PR_ST_STOPPED://server or client
		session = NULL;
		break;

	case PR_ST_TIMEOUT://only client
		session = NULL;
		break;

	default:
		assert(0);
		break;
	}

	delete ctx;
	if (!entry->service && session)
		session->handle(cs_state, res->error);

	if (--entry->ref == 0)
		this->release_conn(entry);
}

void Communicator::handle_reply_result(struct poller_result *res)
{
	WriteContext *ctx = (WriteContext *)res->data.context;
	CommConnEntry *entry = (CommConnEntry *)ctx->entry;
	CommService *service = entry->service;
	CommSession *session = entry->session;
	CommTarget *target = entry->target;
	int cs_state;
	int timeout;
	ULONG nleft = res->iobytes;
	WSABUF *buffer = ctx->buffers;

	switch (res->state)
	{
	case PR_ST_SUCCESS:
		do
		{
			if (nleft >= buffer->len)
			{
				nleft -= buffer->len;
				buffer++;
				ctx->count--;
			}
			else
			{
				buffer->buf += nleft;
				buffer->len -= nleft;
				break;
			}
		} while (ctx->count > 0);

		ctx->buffers = buffer;
		if (ctx->count > 0)
		{
			//try to continue write
			if (session)
				timeout = this->next_timeout(session);
			else
				timeout = service->ssl_accept_timeout;

			if (this->poller->put_io(&res->data, timeout) >= 0)
				return;//reuse context

			cs_state = CS_STATE_ERROR;
			res->error = errno;
		}
		else
		{
			cs_state = CS_STATE_SUCCESS;
			if (session)
				timeout = session->keep_alive_timeout();
			else
				timeout = -1;

			if (timeout != 0 && service->listen_sockfd != INVALID_SOCKET && !this->stop_flag)
			{
				entry->ref++;
				auto *new_ctx = new ReadContext(entry);

				if (res->data.operation & TYPE_SSL_ACCEPT)
				{
					timeout = service->ssl_accept_timeout;
					res->data.operation = PD_OP_READ | TYPE_SSL_ACCEPT;
				}
				else
					res->data.operation = PD_OP_READ;

				res->data.context = new_ctx;
				new_ctx->buffer.buf = entry->readbuf;
				new_ctx->buffer.len = READ_BUFSIZE;
				std::unique_lock<std::mutex> lock(target->mutex);
				if (this->poller->put_io(&res->data, timeout) >= 0)
				{
					service->mutex.lock();
					entry->state = CONN_STATE_KEEPALIVE;
					list_add_tail(&entry->list, &service->alive_list);
					service->mutex.unlock();
					break;
				}

				lock.unlock();
				delete new_ctx;
				entry->ref--;
			}
		}

		break;

	case PR_ST_FINISHED:
	case PR_ST_ERROR:
	case PR_ST_TIMEOUT:
		cs_state = CS_STATE_ERROR;
		break;

	case PR_ST_STOPPED:
		cs_state = CS_STATE_STOPPED;
		break;

	default:
		assert(0);
		break;
	}

	//delete entry->writebufs;
	delete ctx;
	if (session)
		session->handle(cs_state, res->error);

	if (--entry->ref == 0)
		this->release_conn(entry);
}

void Communicator::handle_request_result(struct poller_result *res)
{
	WriteContext *ctx = (WriteContext *)res->data.context;
	CommConnEntry *entry = (CommConnEntry *)ctx->entry;
	CommSession *session = entry->session;
	int cs_state;
	int timeout;
	ULONG nleft = res->iobytes;
	WSABUF *buffer = ctx->buffers;

	switch (res->state)
	{
	case PR_ST_SUCCESS:
	case PR_ST_FINISHED:
		do
		{
			if (nleft >= buffer->len)
			{
				nleft -= buffer->len;
				buffer++;
				ctx->count--;
			}
			else
			{
				buffer->buf += nleft;
				buffer->len -= nleft;
				break;
			}
		} while (ctx->count > 0);

		ctx->buffers = buffer;
		if (ctx->count > 0)
		{
			//try to continue write
			if (res->data.operation & TYPE_SSL_CONNECT)
				timeout = entry->target->ssl_connect_timeout;
			else
				timeout = this->next_timeout(session);

			if (this->poller->put_io(&res->data, timeout) >= 0)
				return;//reuse context

			cs_state = CS_STATE_ERROR;
			res->error = errno;
		}
		else
		{
			timeout = session->first_timeout();
			if (timeout == 0)
				timeout = this->first_timeout_recv(session);
			else
			{
				session->timeout = -1;
				session->begin_time = -1;
			}

			auto *new_ctx = new ReadContext(entry);

			if (res->data.operation & TYPE_SSL_CONNECT)
			{
				timeout = entry->target->ssl_connect_timeout;
				res->data.operation = PD_OP_READ | TYPE_SSL_CONNECT;
			}
			else
				res->data.operation = PD_OP_READ;

			res->data.context = new_ctx;
			new_ctx->buffer.buf = entry->readbuf;
			new_ctx->buffer.len = READ_BUFSIZE;
			if (this->poller->put_io(&res->data, timeout) >= 0)
			{
				//wait for server response
				//delete entry->writebufs;
				delete ctx;
				return;
			}

			delete new_ctx;
			cs_state = CS_STATE_ERROR;
			res->error = errno;
		}

		break;

	case PR_ST_ERROR:
	case PR_ST_TIMEOUT:
		cs_state = CS_STATE_ERROR;
		break;

	case PR_ST_STOPPED:
		cs_state = CS_STATE_STOPPED;
		break;

	default:
		assert(0);
		break;
	}

	//delete entry->writebufs;
	delete ctx;
	entry->target->release(0);
	session->handle(cs_state, res->error);
	if (--entry->ref == 0)
		this->release_conn(entry);
}

bool Communicator::handle_incoming_ssl_connect(CommConnEntry *entry)
{
	SSL_do_handshake(entry->ssl);
	//printf("...%d send_pending[%d] recv_pending[%d]\n", SSL_is_init_finished(entry->ssl), BIO_pending(entry->bio_send), BIO_pending(entry->bio_recv));
	if (SSL_is_init_finished(entry->ssl))
	{
		if (this->send_message(entry) >= 0)
			return false;

		//todo disconnect
		return true;
	}

	int sz = BIO_pending(entry->bio_send);
	poller_data data;

	if (sz == 0)
	{
		//printf("no more write [%d][%d]\n", BIO_pending(entry->bio_send), BIO_pending(entry->bio_recv));
		//read continue until connect timeout
		return true;//need more
	}

	auto *new_ctx = new WriteContext(entry);

	new_ctx->buf = new char[sz];

	int len = BIO_read(entry->bio_send, new_ctx->buf, sz);

	//entry->writebufs = new WSABUF[1];
	entry->writebufs.resize(1);
	entry->writebufs[0].buf = (CHAR *)new_ctx->buf;
	entry->writebufs[0].len = (ULONG)len;

	data.operation = PD_OP_WRITE | TYPE_SSL_CONNECT;
	data.handle = (HANDLE)entry->sockfd;
	data.context = new_ctx;
	new_ctx->buffers = entry->writebufs.data();
	new_ctx->count = 1;
	if (this->poller->put_io(&data, entry->target->ssl_connect_timeout) >= 0)
		return false;

	//delete entry->writebufs;
	delete new_ctx;
	//todo disconnect
	return true;
}

void Communicator::handle_incoming_ssl_accept(CommConnEntry *entry)
{
	auto *new_ctx = new WriteContext(entry);

	SSL_do_handshake(entry->ssl);
	int sz = BIO_pending(entry->bio_send);

	new_ctx->buf = new char[sz];

	int len = BIO_read(entry->bio_send, new_ctx->buf, sz);

	//entry->writebufs = new WSABUF[1];
	entry->writebufs.resize(1);
	entry->writebufs[0].buf = (CHAR *)new_ctx->buf;
	entry->writebufs[0].len = (ULONG)len;

	poller_data data;
	data.operation = PD_OP_WRITE | TYPE_SSL_ACCEPT;
	data.handle = (HANDLE)entry->sockfd;
	data.context = new_ctx;
	new_ctx->buffers = entry->writebufs.data();
	new_ctx->count = 1;
	if (this->poller->put_io(&data, entry->service->ssl_accept_timeout) >= 0)
		return;

	//delete entry->writebufs;
	delete new_ctx;
}

void Communicator::handle_read_result(struct poller_result *res)
{
	ReadContext *ctx = (ReadContext *)res->data.context;
	CommConnEntry *entry = (CommConnEntry *)ctx->entry;
	bool is_ssl = false;
	int ret;
	std::string buf;

	if (entry->ssl && res->state == PR_ST_SUCCESS && res->iobytes > 0)
	{
		ret = BIO_write(entry->bio_recv, ctx->buffer.buf, res->iobytes);
		if (ret == res->iobytes)
			is_ssl = true;
		else
		{
			res->state = PR_ST_ERROR;
			res->error = errno;
		}
	}

	if (is_ssl)
	{
		//printf("...%d %d\n", BIO_pending(entry->bio_send), BIO_pending(entry->bio_recv));
		if (res->data.operation & TYPE_SSL_CONNECT)
		{
			//int nn = SSL_read(entry->ssl, ctx->buffer.buf, READ_BUFSIZE);
			//printf("%d ?? %d\n", nn, SSL_get_error(entry->ssl, nn));
			bool need_more = this->handle_incoming_ssl_connect(entry);

			if (need_more)
			{
				ctx->buffer.buf = entry->readbuf;
				ctx->buffer.len = READ_BUFSIZE;
				if (this->poller->put_io(&res->data, entry->target->ssl_connect_timeout) >= 0)
					return;//reuse context
			}

			delete ctx;
			return;
		}
		else if (res->data.operation & TYPE_SSL_ACCEPT)
		{
			if (!SSL_is_init_finished(entry->ssl))
			{
				this->handle_incoming_ssl_accept(entry);
				delete ctx;
				return;
			}
		}

		res->state = PR_ST_SUCCESS;
		res->error = 0;
		res->iobytes = 0;
		while (1)
		{
			//printf("...BIO_pending[%d] SSL_pending[%d]\n", BIO_pending(entry->bio_recv), SSL_pending(entry->ssl));
			ret = SSL_read(entry->ssl, ctx->buffer.buf, READ_BUFSIZE);
			//printf("...read[%d]\n", ret);
			if (ret > 0)
			{
				buf.append(ctx->buffer.buf, ret);
				res->iobytes += ret;
			}
			else if (ret < 0)
			{
				int error = SSL_get_error(entry->ssl, ret);

				if (error != SSL_ERROR_WANT_READ)
				{
					res->state = PR_ST_ERROR;
					if (error == SSL_ERROR_SYSCALL)
						res->error = errno;
					else
						res->error = -error;
				}

				break;
			}
			else
				break;
		}

		ctx->buffer.buf = const_cast<char *>(buf.c_str());
	}

	if (res->data.operation & TYPE_IDLE)
		this->handle_incoming_idle(res);
	else if (entry->service)
		this->handle_incoming_request(res);
	else
		this->handle_incoming_reply(res);
}

void Communicator::handle_write_result(struct poller_result *res)
{
	WriteContext *ctx = (WriteContext *)res->data.context;
	CommConnEntry *entry = (CommConnEntry *)ctx->entry;

	if (entry->service)
		this->handle_reply_result(res);
	else
		this->handle_request_result(res);
}

void Communicator::handle_connect_result(struct poller_result *res)
{
	ConnectContext *ctx = (ConnectContext *)res->data.context;
	CommConnEntry *entry = (CommConnEntry *)ctx->entry;

	delete ctx;
	CommTarget *target = entry->target;
	CommSession *session = entry->session;
	int cs_state;

	switch (res->state)
	{
	case PR_ST_SUCCESS://todo error???
	case PR_ST_FINISHED:
		session->out = session->message_out();
		if (session->out && !this->stop_flag)
		{
			if (target->ssl_ctx)
			{
				if (__ssl_connect(target->ssl_ctx, entry) >= 0 &&
					target->init_ssl(entry->ssl) >= 0)
				{
					if (handle_incoming_ssl_connect(entry) == false)
						return;
				}
			}
			else
			{
				if (this->send_message(entry) >= 0)
					return;
			}
		}

		cs_state = CS_STATE_ERROR;
		res->error = errno;
		break;

	case PR_ST_ERROR:
	case PR_ST_TIMEOUT:
		cs_state = CS_STATE_ERROR;
		break;

	case PR_ST_STOPPED:
		cs_state = CS_STATE_STOPPED;
		break;

	default:
		assert(0);
		break;
	}

	target->release(0);
	session->handle(cs_state, res->error);
	this->poller->unbind_socket(entry->sockfd);
	this->release_conn(entry);
}

void Communicator::handle_accept_result(struct poller_result *res)
{
	AcceptConext *ctx = (AcceptConext *)res->data.context;
	CommService *service = (CommService *)ctx->service;
	SOCKET sockfd = ctx->accept_sockfd;
	CommConnEntry *entry;
	CommServiceTarget *target;

	switch (res->state)
	{
	case PR_ST_SUCCESS://todo error???
	case PR_ST_FINISHED:
		target = new CommServiceTarget;
		if (target->init((const struct sockaddr *)ctx->remote, ctx->remote_len, sockfd, service) >= 0)
		{
			entry = this->accept_conn(target, service);
			if (entry)
			{
				struct poller_data data;
				int timeout;
				auto *new_ctx = new ReadContext(entry);

				data.operation = PD_OP_READ;
				data.handle = (HANDLE)entry->sockfd;
				data.context = new_ctx;
				new_ctx->buffer.buf = entry->readbuf;
				new_ctx->buffer.len = READ_BUFSIZE;

				if (service->ssl_ctx)
				{
					data.operation |= TYPE_SSL_ACCEPT;
					timeout = service->ssl_accept_timeout;
				}
				else
					timeout = target->response_timeout;

				if (!service->ssl_ctx ||
					(__ssl_accept(service->ssl_ctx, entry) >= 0 &&
					 service->init_ssl(entry->ssl) >= 0))
				{
					if (this->poller->put_io(&data, timeout) >= 0)
						break;
				}

				delete new_ctx;
				this->poller->unbind_socket(sockfd);
				this->release_conn(entry);
			}
			else
				target->decref();
		}
		else
		{
			closesocket(sockfd);
			delete target;
		}
		
		break;

	case PR_ST_ERROR:
	case PR_ST_STOPPED:
	case PR_ST_TIMEOUT:
		closesocket(sockfd);
		break;

	default:
		assert(0);
		break;
	}

	if (service->listen_sockfd != INVALID_SOCKET && !this->stop_flag)
	{
		ctx->accept_sockfd = nonblock_accept(service);
		if (ctx->accept_sockfd)
		{
			if (this->poller->put_io(&res->data, service->listen_timeout) >= 0)
				return;//reuse context

			closesocket(ctx->accept_sockfd);
		}
	}

	delete ctx;
}

void Communicator::handler_thread_routine(void *context)
{
	Communicator *comm = (Communicator *)context;
	struct poller_result res;
	int ret;

	while (comm->total_fd_cnt > 0 || !comm->stop_flag)
	{
		ret = comm->poller->get_io_result(&res, -1);
		//printf("[%d] iobytes[%d]\n", res.data.operation, res.iobytes);
		if (ret < 0)
			break;
		else if (ret > 0)
		{
			//printf("%lld %d\n", res.data.handle, res.data.operation);
			switch (res.data.operation & 0xFF)
			{
			case PD_OP_READ:
				comm->handle_read_result(&res);
				break;
			case PD_OP_WRITE:
				comm->handle_write_result(&res);
				break;
			case PD_OP_CONNECT:
				comm->handle_connect_result(&res);
				break;
			case PD_OP_ACCEPT:
				comm->handle_accept_result(&res);
				break;
			case PD_OP_SLEEP:
				comm->handle_sleep_result(&res);
				break;
			case PD_OP_USER:
				comm->handle_event_result(&res);
				break;
			default:
				assert(0);
				break;
			}
		}
		//else if (res.error == WAIT_TIMEOUT) { }
	}
}

SOCKET Communicator::nonblock_connect(CommTarget *target)
{
	SOCKET sockfd = target->create_connect_fd();

	if (sockfd != INVALID_SOCKET)
	{
		if (__set_fd_nonblock(sockfd) >= 0)
			return sockfd;

		closesocket(sockfd);
	}

	return INVALID_SOCKET;
}

SOCKET Communicator::nonblock_accept(CommService *service)
{
	SOCKET sockfd = (SOCKET)service->create_accept_fd();

	if (sockfd != INVALID_SOCKET)
	{
		if (__set_fd_nonblock(sockfd) >= 0)
			return sockfd;

		closesocket(sockfd);
	}

	return INVALID_SOCKET;
}

SOCKET Communicator::nonblock_listen(CommService *service)
{
	SOCKET sockfd = (SOCKET)service->create_listen_fd();

	if (sockfd != INVALID_SOCKET)
	{
		if (__set_fd_nonblock(sockfd) >= 0)
			return sockfd;

		closesocket(sockfd);
	}

	return INVALID_SOCKET;
}

CommConnEntry *Communicator::get_idle_conn(CommTarget *target)
{
	CommConnEntry *entry;
	struct list_head *pos;
	std::lock_guard<std::mutex> lock(target->mutex);

	list_for_each(pos, &target->idle_list)
	{
		entry = list_entry(pos, CommConnEntry, list);
		entry->ref++;
		if (this->poller->cancel_pending_io((HANDLE)entry->sockfd) >= 0)
		{
			list_del(&entry->list);
			entry->state = CONN_STATE_FREE;
			return entry;
		}

		entry->ref--;
	}

	errno = ENOENT;
	return NULL;
}

#define ENCODE_IOV_MAX		8192

int Communicator::send_message(CommConnEntry *entry)
{
	struct iovec vectors[ENCODE_IOV_MAX];
	int cnt;

	cnt = entry->session->out->encode(vectors, ENCODE_IOV_MAX);
	if ((unsigned int)cnt > ENCODE_IOV_MAX)
	{
		if (cnt > ENCODE_IOV_MAX)
			errno = EOVERFLOW;

		return -1;
	}

	// cnt should not be zero on Windows platform
	// it will return error INVALID_PARAM by WSASend
	if (cnt == 0)
	{
		vectors[0].iov_base = NULL;
		vectors[0].iov_len = 0;
		cnt = 1;
	}

	return this->send_message_async(vectors, cnt, entry);
}

int Communicator::send_message_async(struct iovec vectors[], int cnt,
									 CommConnEntry *entry)
{
	struct poller_data data;
	int timeout = this->first_timeout_send(entry->session);

	if (entry->ssl)
	{
		for (int i = 0; i < cnt; i++)
		{
			if (vectors[i].iov_len > 0)
			{
				int ret = SSL_write(entry->ssl, vectors[i].iov_base, (int)vectors[i].iov_len);

				if (ret <= 0)
				{
					int error = SSL_get_error(entry->ssl, ret);

					if (error != SSL_ERROR_SYSCALL)
						errno = -error;

					return -1;
				}
			}
		}
	}

	auto *new_ctx = new WriteContext(entry);

	if (entry->ssl)
	{
		int sz = BIO_pending(entry->bio_send);

		cnt = 1;
		new_ctx->buf = new char[sz];
		vectors[0].iov_base = (void *)(new_ctx->buf);
		vectors[0].iov_len = (size_t)sz;
		if (sz != BIO_read(entry->bio_send, new_ctx->buf, sz))
		{
			delete new_ctx;
			return -1;
		}
	}

	//entry->writebufs = new WSABUF[cnt];
	entry->writebufs.resize(cnt);
	for (int i = 0; i < cnt; i++)
	{
		entry->writebufs[i].buf = (CHAR *)vectors[i].iov_base;
		entry->writebufs[i].len = (ULONG)vectors[i].iov_len;
	}

	data.operation = PD_OP_WRITE;
	data.handle = (HANDLE)entry->sockfd;
	data.context = new_ctx;
	new_ctx->buffers = entry->writebufs.data();
	new_ctx->count = cnt;
	if (this->poller->put_io(&data, timeout) >= 0)
		return 0;

	//delete entry->writebufs;
	delete new_ctx;
	return -1;
}

int Communicator::first_timeout_send(CommSession *session)
{
	session->timeout = session->send_timeout();
	return this->first_timeout(session);
}

int Communicator::first_timeout_recv(CommSession *session)
{
	session->timeout = session->receive_timeout();
	return this->first_timeout(session);
}

int Communicator::first_timeout(CommSession *session)
{
	int timeout = session->target->response_timeout;

	if (timeout < 0 || (unsigned int)session->timeout <= (unsigned int)timeout)
	{
		timeout = session->timeout;
		session->timeout = 0;
	}
	else
		session->begin_time = GET_CURRENT_MS;

	return timeout;
}

int Communicator::next_timeout(CommSession *session)
{
	int timeout = session->target->response_timeout;
	int64_t cur_time;
	int time_used, time_left;

	if (session->timeout > 0)
	{
		cur_time = GET_CURRENT_MS;
		time_used = (int)(cur_time - session->begin_time);
		time_left = session->timeout - time_used;
		if (time_left <= timeout) // here timeout >= 0
		{
			timeout = time_left < 0 ? 0 : time_left;
			session->timeout = 0;
		}
	}

	return timeout;
}

void __thrdpool_schedule(const struct thrdpool_task *, void *,
									thrdpool_t *);

int Communicator::increase_handler_thread()
{
	void *buf = new char(4 * sizeof (void *));

	if (buf)
	{
		if (thrdpool_increase(this->thrdpool) >= 0)
		{
			struct thrdpool_task task = {Communicator::handler_thread_routine, this};

			__thrdpool_schedule(&task, buf, this->thrdpool);
			return 0;
		}

		free(buf);
	}

	return -1;
}

/*

void *Communicator::aio_event(const struct io_event *event, void *context)
{
	IOService *service = (IOService *)context;
	IOSession *session = (IOSession *)event->data;

	service->incref();
	session->res = event->res;
	return session;
}

void Communicator::shutdown_io_service(IOService *service)
{
	this->total_fd_cnt--;
	service->mutex.lock();
	closesocket(service->event_fd);
	service->event_fd = -1;
	service->mutex.unlock();
	service->decref();
}

*/
/* Linux async I/O interface from libaio.h */

typedef struct io_context *io_context_t;

typedef enum io_iocb_cmd {
	IO_CMD_PREAD = 0,
	IO_CMD_PWRITE = 1,

	IO_CMD_FSYNC = 2,
	IO_CMD_FDSYNC = 3,

	IO_CMD_NOOP = 6,
	IO_CMD_PREADV = 7,
	IO_CMD_PWRITEV = 8,
} io_iocb_cmd_t;

#if defined(__i386__) /* little endian, 32 bits */
#define PADDED(x, y)	x; unsigned y
#define PADDEDptr(x, y)	x; unsigned y
#define PADDEDul(x, y)	unsigned long x; unsigned y
#elif defined(__ia64__) || defined(__x86_64__) || defined(__alpha__) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ALPHA)
#define PADDED(x, y)	x, y
#define PADDEDptr(x, y)	x
#define PADDEDul(x, y)	unsigned long x
#elif defined(__powerpc64__) /* big endian, 64 bits */
#define PADDED(x, y)	unsigned y; x
#define PADDEDptr(x,y)	x
#define PADDEDul(x, y)	unsigned long x
#elif defined(__PPC__)  /* big endian, 32 bits */
#define PADDED(x, y)	unsigned y; x
#define PADDEDptr(x, y)	unsigned y; x
#define PADDEDul(x, y)	unsigned y; unsigned long x
#elif defined(__s390x__) /* big endian, 64 bits */
#define PADDED(x, y)	unsigned y; x
#define PADDEDptr(x,y)	x
#define PADDEDul(x, y)	unsigned long x
#elif defined(__s390__) /* big endian, 32 bits */
#define PADDED(x, y)	unsigned y; x
#define PADDEDptr(x, y) unsigned y; x
#define PADDEDul(x, y)	unsigned y; unsigned long x
#elif defined(__arm__)
#  if defined (__ARMEB__) /* big endian, 32 bits */
#define PADDED(x, y)	unsigned y; x
#define PADDEDptr(x, y)	unsigned y; x
#define PADDEDul(x, y)	unsigned y; unsigned long x
#  else                   /* little endian, 32 bits */
#define PADDED(x, y)	x; unsigned y
#define PADDEDptr(x, y)	x; unsigned y
#define PADDEDul(x, y)	unsigned long x; unsigned y
#  endif
#elif defined(__aarch64__)
#  if defined (__AARCH64EB__) /* big endian, 64 bits */
#define PADDED(x, y)    unsigned y; x
#define PADDEDptr(x,y)  x
#define PADDEDul(x, y)  unsigned long x
#  elif defined(__AARCH64EL__) /* little endian, 64 bits */
#define PADDED(x, y)    x, y
#define PADDEDptr(x, y) x
#define PADDEDul(x, y)  unsigned long x
#  endif
#else
//#error	endian?
#define PADDED(x, y)	x; unsigned y
#define PADDEDptr(x, y)	x; unsigned y
#define PADDEDul(x, y)	unsigned long x; unsigned y
#endif

struct io_iocb_common {
	PADDEDptr(void *buf, __pad1);
	PADDEDul(nbytes, __pad2);
	long long offset;
	long long __pad3;
	unsigned flags;
	unsigned resfd;
};	/* result code is the amount read or -'ve errno */

struct io_iocb_vector {
	const struct iovec *vec;
	int nr;
	long long offset;
};	/* result code is the amount read or -'ve errno */

struct iocb {
	PADDEDptr(void *data, __pad1);	/* Return in the io completion event */
	PADDED(unsigned key, __pad2);	/* For use in identifying io requests */

	short aio_lio_opcode;	
	short aio_reqprio;
	int aio_fildes;

	union {
		struct io_iocb_common c;
		struct io_iocb_vector v;
	} u;
};

struct io_event {
	PADDEDptr(void *data, __pad1);
	PADDEDptr(struct iocb *obj, __pad2);
	PADDEDul(res, __pad3);
	PADDEDul(res2, __pad4);
};

#undef PADDED
#undef PADDEDptr
#undef PADDEDul

/* Actual syscalls */
static inline int io_setup(unsigned int maxevents, io_context_t *ctxp)
{
	return 0;
}

static inline int io_destroy(io_context_t ctx)
{
	return 0;
}

static inline int io_submit(io_context_t ctx, long nr, struct iocb *ios[])
{
	return 0;
}

static inline int io_cancel(io_context_t ctx, struct iocb *iocb,
							struct io_event *evt)
{
	return 0;
}

static inline int io_getevents(io_context_t ctx_id, long min_nr, long nr,
							   struct io_event *events,
							   struct timespec *timeout)
{
	return 0;
}

static inline void io_set_eventfd(struct iocb *iocb, int eventfd)
{
	iocb->u.c.flags |= (1 << 0) /* IOCB_FLAG_RESFD */;
	iocb->u.c.resfd = eventfd;
}

void IOSession::prep_pread(int fd, void *buf, size_t count, long long offset)
{
	struct iocb *iocb = (struct iocb *)this->iocb_buf;

	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IO_CMD_PREAD;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
}

void IOSession::prep_pwrite(int fd, void *buf, size_t count, long long offset)
{
	struct iocb *iocb = (struct iocb *)this->iocb_buf;

	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IO_CMD_PWRITE;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
}

void IOSession::prep_preadv(int fd, const struct iovec *iov, int iovcnt,
							long long offset)
{
	struct iocb *iocb = (struct iocb *)this->iocb_buf;

	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IO_CMD_PREADV;
	iocb->u.c.buf = (void *)iov;
	iocb->u.c.nbytes = iovcnt;
	iocb->u.c.offset = offset;
}

void IOSession::prep_pwritev(int fd, const struct iovec *iov, int iovcnt,
							 long long offset)
{
	struct iocb *iocb = (struct iocb *)this->iocb_buf;

	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IO_CMD_PWRITEV;
	iocb->u.c.buf = (void *)iov;
	iocb->u.c.nbytes = iovcnt;
	iocb->u.c.offset = offset;
}

void IOSession::prep_fsync(int fd)
{
	struct iocb *iocb = (struct iocb *)this->iocb_buf;

	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IO_CMD_FSYNC;
}

void IOSession::prep_fdsync(int fd)
{
	struct iocb *iocb = (struct iocb *)this->iocb_buf;

	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IO_CMD_FDSYNC;
}

IOSession::IOSession()
{
	struct iocb *iocb = (struct iocb *)this->iocb_buf;

	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = -1;
	iocb->aio_lio_opcode = IO_CMD_NOOP;
}

int IOService::init(unsigned int maxevents)
{
	this->io_ctx = NULL;
	if (io_setup(maxevents, &this->io_ctx) >= 0)
	{
		INIT_LIST_HEAD(&this->session_list);
		this->event_fd = -1;
		return 0;
	}

	return -1;
}

void IOService::deinit()
{
	io_destroy(this->io_ctx);
}

inline void IOService::incref()
{
	this->ref++;
}

void IOService::decref()
{
	struct io_event event;
	IOSession *session;
	int state, error;

	if (--this->ref == 0)
	{
		while (!list_empty(&this->session_list))
		{
			if (io_getevents(this->io_ctx, 1, 1, &event, NULL) > 0)
			{
				session = (IOSession *)event.data;
				list_del(&session->list);
				session->res = event.res;
				if (session->res >= 0)
				{
					state = IOS_STATE_SUCCESS;
					error = 0;
				}
				else
				{
					state = IOS_STATE_ERROR;
					error = -session->res;
				}

				session->handle(state, error);
			}
		}

		this->handle_unbound();
	}
}

int IOService::request(IOSession *session)
{
	struct iocb *iocb = (struct iocb *)session->iocb_buf;
	int ret = -1;

	iocb->data = session;
	this->mutex.lock();
	if (this->event_fd >= 0)
	{
		io_set_eventfd(iocb, this->event_fd);
		if (io_submit(this->io_ctx, 1, &iocb) > 0)
		{
			list_add_tail(&session->list, &this->session_list);
			ret = 0;
		}
	}
	else
		errno = ENOENT;

	this->mutex.unlock();
	if (ret < 0)
		session->res = -errno;

	return ret;
}

