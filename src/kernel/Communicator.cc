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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "list.h"
#include "msgqueue.h"
#include "thrdpool.h"
#include "poller.h"
#include "mpoller.h"
#include "Communicator.h"

struct CommConnEntry
{
	struct list_head list;
	CommConnection *conn;
	long long seq;
	int sockfd;
#define CONN_STATE_CONNECTING	0
#define CONN_STATE_CONNECTED	1
#define CONN_STATE_RECEIVING	2
#define CONN_STATE_SUCCESS		3
#define CONN_STATE_IDLE			4
#define CONN_STATE_KEEPALIVE	5
#define CONN_STATE_CLOSING		6
#define CONN_STATE_ERROR		7
	int state;
	int error;
	int ref;
	struct iovec *write_iov;
	SSL *ssl;
	CommSession *session;
	CommTarget *target;
	CommService *service;
	mpoller_t *mpoller;
	/* Connection entry's mutex is for client session only. */
	pthread_mutex_t mutex;
};

static inline int __set_fd_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags >= 0)
		flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	return flags;
}

static int __bind_and_listen(int sockfd, const struct sockaddr *addr,
							 socklen_t addrlen)
{
	struct sockaddr_storage ss;
	socklen_t len;

	len = sizeof (struct sockaddr_storage);
	if (getsockname(sockfd, (struct sockaddr *)&ss, &len) < 0)
		return -1;

	ss.ss_family = 0;
	while (len != 0)
	{
		if (((char *)&ss)[--len] != 0)
			break;
	}

	if (len == 0)
	{
		if (bind(sockfd, addr, addrlen) < 0)
			return -1;
	}

	return listen(sockfd, SOMAXCONN);
}

static int __create_ssl(SSL_CTX *ssl_ctx, struct CommConnEntry *entry)
{
	BIO *bio = BIO_new_socket(entry->sockfd, BIO_NOCLOSE);

	if (bio)
	{
		entry->ssl = SSL_new(ssl_ctx);
		if (entry->ssl)
		{
			SSL_set_bio(entry->ssl, bio, bio);
			return 0;
		}

		BIO_free(bio);
	}

	return -1;
}

int CommTarget::init(const struct sockaddr *addr, socklen_t addrlen,
					 int connect_timeout, int response_timeout)
{
	int ret;

	this->addr = (struct sockaddr *)malloc(addrlen);
	if (this->addr)
	{
		ret = pthread_mutex_init(&this->mutex, NULL);
		if (ret == 0)
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

		errno = ret;
		free(this->addr);
	}

	return -1;
}

void CommTarget::deinit()
{
	pthread_mutex_destroy(&this->mutex);
	free(this->addr);
}

int CommMessageIn::feedback(const char *buf, size_t size)
{
	struct CommConnEntry *entry = this->entry;
	int error;
	int ret;

	if (!entry->ssl)
		return write(entry->sockfd, buf, size);

	if (size == 0)
		return 0;

	ret = SSL_write(entry->ssl, buf, size);
	if (ret <= 0)
	{
		error = SSL_get_error(entry->ssl, ret);
		if (error != SSL_ERROR_SYSCALL)
			errno = -error;

		ret = -1;
	}

	return ret;
}

int CommService::init(const struct sockaddr *bind_addr, socklen_t addrlen,
					  int listen_timeout, int response_timeout)
{
	int ret;

	this->bind_addr = (struct sockaddr *)malloc(addrlen);
	if (this->bind_addr)
	{
		ret = pthread_mutex_init(&this->mutex, NULL);
		if (ret == 0)
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

		errno = ret;
		free(this->bind_addr);
	}

	return -1;
}

void CommService::deinit()
{
	pthread_mutex_destroy(&this->mutex);
	free(this->bind_addr);
}

int CommService::drain(int max)
{
	struct CommConnEntry *entry;
	struct list_head *pos;
	int errno_bak;
	int cnt = 0;

	errno_bak = errno;
	pthread_mutex_lock(&this->mutex);
	while (cnt != max && !list_empty(&this->alive_list))
	{
		pos = this->alive_list.next;
		entry = list_entry(pos, struct CommConnEntry, list);
		list_del(pos);
		cnt++;

		/* Cannot change the sequence of next two lines. */
		mpoller_del(entry->sockfd, entry->mpoller);
		entry->state = CONN_STATE_CLOSING;
	}

	pthread_mutex_unlock(&this->mutex);
	errno = errno_bak;
	return cnt;
}

inline void CommService::incref()
{
	__sync_add_and_fetch(&this->ref, 1);
}

inline void CommService::decref()
{
	if (__sync_sub_and_fetch(&this->ref, 1) == 0)
		this->handle_unbound();
}

class CommServiceTarget : public CommTarget
{
public:
	void incref()
	{
		__sync_add_and_fetch(&this->ref, 1);
	}

	void decref()
	{
		if (__sync_sub_and_fetch(&this->ref, 1) == 0)
		{
			this->service->decref();
			this->deinit();
			delete this;
		}
	}

private:
	int sockfd;
	int ref;

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
	struct CommConnEntry *entry;
	struct list_head *pos;
	CommTarget *target;
	int errno_bak;

	if (!this->passive)
		return;

	target = this->target;
	if (this->passive == 1)
	{
		pthread_mutex_lock(&target->mutex);
		if (!list_empty(&target->idle_list))
		{
			pos = target->idle_list.next;
			entry = list_entry(pos, struct CommConnEntry, list);
			errno_bak = errno;
			mpoller_del(entry->sockfd, entry->mpoller);
			errno = errno_bak;
		}

		pthread_mutex_unlock(&target->mutex);
	}

	((CommServiceTarget *)target)->decref();
}

inline int Communicator::first_timeout(CommSession *session)
{
	int timeout = session->target->response_timeout;

	if (timeout < 0 || (unsigned int)session->timeout <= (unsigned int)timeout)
	{
		timeout = session->timeout;
		session->timeout = 0;
		session->begin_time.tv_nsec = 0;
	}
	else
		clock_gettime(CLOCK_MONOTONIC, &session->begin_time);

	return timeout;
}

int Communicator::next_timeout(CommSession *session)
{
	int timeout = session->target->response_timeout;
	struct timespec cur_time;
	int time_used, time_left;

	if (session->timeout > 0)
	{
		clock_gettime(CLOCK_MONOTONIC, &cur_time);
		time_used = 1000 * (cur_time.tv_sec - session->begin_time.tv_sec) +
					(cur_time.tv_nsec - session->begin_time.tv_nsec) / 1000000;
		time_left = session->timeout - time_used;
		if (time_left <= timeout) /* here timeout >= 0 */
		{
			timeout = time_left < 0 ? 0 : time_left;
			session->timeout = 0;
		}
	}

	return timeout;
}

int Communicator::first_timeout_send(CommSession *session)
{
	session->timeout = session->send_timeout();
	return Communicator::first_timeout(session);
}

int Communicator::first_timeout_recv(CommSession *session)
{
	session->timeout = session->receive_timeout();
	return Communicator::first_timeout(session);
}

void Communicator::release_conn(struct CommConnEntry *entry)
{
	delete entry->conn;
	if (!entry->service)
		pthread_mutex_destroy(&entry->mutex);

	if (entry->ssl)
		SSL_free(entry->ssl);

	close(entry->sockfd);
	free(entry);
}

void Communicator::shutdown_service(CommService *service)
{
	close(service->listen_fd);
	service->listen_fd = -1;
	service->drain(-1);
	service->decref();
}

#ifndef IOV_MAX
# ifdef UIO_MAXIOV
#  define IOV_MAX	UIO_MAXIOV
# else
#  define IOV_MAX	1024
# endif
#endif

int Communicator::send_message_sync(struct iovec vectors[], int cnt,
									struct CommConnEntry *entry)
{
	CommSession *session = entry->session;
	CommService *service;
	int timeout;
	ssize_t n;
	int i;

	while (1)
	{
		n = writev(entry->sockfd, vectors, cnt <= IOV_MAX ? cnt : IOV_MAX);
		if (n < 0)
			return errno == EAGAIN ? cnt : -1;

		for (i = 0; i < cnt; i++)
		{
			if ((size_t)n >= vectors[i].iov_len)
				n -= vectors[i].iov_len;
			else
			{
				vectors[i].iov_base = (char *)vectors[i].iov_base + n;
				vectors[i].iov_len -= n;
				break;
			}
		}

		cnt -= i;
		if (cnt == 0)
			break;

		if (i < IOV_MAX)
			return cnt;

		vectors += i;
	}

	service = entry->service;
	if (service)
	{
		__sync_add_and_fetch(&entry->ref, 1);
		timeout = session->keep_alive_timeout();
		switch (timeout)
		{
		default:
			mpoller_set_timeout(entry->sockfd, timeout, this->mpoller);
			pthread_mutex_lock(&service->mutex);
			if (service->listen_fd >= 0)
			{
				entry->state = CONN_STATE_KEEPALIVE;
				list_add_tail(&entry->list, &service->alive_list);
				entry = NULL;
			}

			pthread_mutex_unlock(&service->mutex);
			if (entry)
			{
		case 0:
				mpoller_del(entry->sockfd, this->mpoller);
				entry->state = CONN_STATE_CLOSING;
			}
		}
	}
	else
	{
		if (entry->state == CONN_STATE_IDLE)
		{
			timeout = session->first_timeout();
			if (timeout == 0)
				timeout = Communicator::first_timeout_recv(session);
			else
			{
				session->timeout = -1;
				session->begin_time.tv_nsec = -1;
			}

			mpoller_set_timeout(entry->sockfd, timeout, this->mpoller);
		}

		entry->state = CONN_STATE_RECEIVING;
	}

	return 0;
}

int Communicator::send_message_async(struct iovec vectors[], int cnt,
									 struct CommConnEntry *entry)
{
	struct poller_data data;
	int timeout;
	int ret;
	int i;

	entry->write_iov = (struct iovec *)malloc(cnt * sizeof (struct iovec));
	if (entry->write_iov)
	{
		for (i = 0; i < cnt; i++)
			entry->write_iov[i] = vectors[i];
	}
	else
		return -1;

	data.operation = PD_OP_WRITE;
	data.fd = entry->sockfd;
	data.ssl = entry->ssl;
	data.context = entry;
	data.write_iov = entry->write_iov;
	data.iovcnt = cnt;
	timeout = Communicator::first_timeout_send(entry->session);
	if (entry->state == CONN_STATE_IDLE)
	{
		ret = mpoller_mod(&data, timeout, this->mpoller);
		if (ret < 0 && errno == ENOENT)
			entry->state = CONN_STATE_RECEIVING;
	}
	else
	{
		ret = mpoller_add(&data, timeout, this->mpoller);
		if (ret >= 0)
		{
			if (this->stop_flag)
				mpoller_del(data.fd, this->mpoller);
		}
	}

	if (ret < 0)
	{
		free(entry->write_iov);
		if (entry->state != CONN_STATE_RECEIVING)
			return -1;
	}

	return 1;
}

#define ENCODE_IOV_MAX		8192

int Communicator::send_message(struct CommConnEntry *entry)
{
	struct iovec vectors[ENCODE_IOV_MAX];
	struct iovec *end;
	int cnt;

	cnt = entry->session->out->encode(vectors, ENCODE_IOV_MAX);
	if ((unsigned int)cnt > ENCODE_IOV_MAX)
	{
		if (cnt > ENCODE_IOV_MAX)
			errno = EOVERFLOW;
		return -1;
	}

	end = vectors + cnt;
	if (!entry->ssl)
	{
		cnt = this->send_message_sync(vectors, cnt, entry);
		if (cnt <= 0)
			return cnt;
	}

	return this->send_message_async(end - cnt, cnt, entry);
}

void Communicator::handle_incoming_request(struct poller_result *res)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)res->data.context;
	CommTarget *target = entry->target;
	CommSession *session = NULL;
	int state;

	switch (res->state)
	{
	case PR_ST_SUCCESS:
		session = entry->session;
		state = CS_STATE_TOREPLY;
		pthread_mutex_lock(&target->mutex);
		if (entry->state == CONN_STATE_SUCCESS)
		{
			__sync_add_and_fetch(&entry->ref, 1);
			entry->state = CONN_STATE_IDLE;
			list_add(&entry->list, &target->idle_list);
		}

		pthread_mutex_unlock(&target->mutex);
		break;

	case PR_ST_FINISHED:
		res->error = ECONNRESET;
		if (1)
	case PR_ST_ERROR:
			state = CS_STATE_ERROR;
		else
	case PR_ST_DELETED:
	case PR_ST_STOPPED:
			state = CS_STATE_STOPPED;

		pthread_mutex_lock(&target->mutex);
		switch (entry->state)
		{
		case CONN_STATE_KEEPALIVE:
			pthread_mutex_lock(&entry->service->mutex);
			if (entry->state == CONN_STATE_KEEPALIVE)
				list_del(&entry->list);
			pthread_mutex_unlock(&entry->service->mutex);
			break;

		case CONN_STATE_IDLE:
			list_del(&entry->list);
			break;

		case CONN_STATE_ERROR:
			res->error = entry->error;
			state = CS_STATE_ERROR;
		case CONN_STATE_RECEIVING:
			session = entry->session;
			break;

		case CONN_STATE_SUCCESS:
			/* This may happen only if handler_threads > 1. */
			entry->state = CONN_STATE_CLOSING;
			entry = NULL;
			break;
		}

		pthread_mutex_unlock(&target->mutex);
		break;
	}

	if (entry)
	{
		if (session)
			session->handle(state, res->error);

		if (__sync_sub_and_fetch(&entry->ref, 1) == 0)
		{
			this->release_conn(entry);
			((CommServiceTarget *)target)->decref();
		}
	}
}

void Communicator::handle_incoming_reply(struct poller_result *res)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)res->data.context;
	CommTarget *target = entry->target;
	CommSession *session = NULL;
	pthread_mutex_t *mutex;
	int state;

	switch (res->state)
	{
	case PR_ST_SUCCESS:
		session = entry->session;
		state = CS_STATE_SUCCESS;
		pthread_mutex_lock(&target->mutex);
		if (entry->state == CONN_STATE_SUCCESS)
		{
			__sync_add_and_fetch(&entry->ref, 1);
			if (session->timeout != 0) /* This is keep-alive timeout. */
			{
				entry->state = CONN_STATE_IDLE;
				list_add(&entry->list, &target->idle_list);
			}
			else
				entry->state = CONN_STATE_CLOSING;
		}

		pthread_mutex_unlock(&target->mutex);
		break;

	case PR_ST_FINISHED:
		res->error = ECONNRESET;
		if (1)
	case PR_ST_ERROR:
			state = CS_STATE_ERROR;
		else
	case PR_ST_DELETED:
	case PR_ST_STOPPED:
			state = CS_STATE_STOPPED;

		mutex = &entry->mutex;
		pthread_mutex_lock(&target->mutex);
		pthread_mutex_lock(mutex);
		switch (entry->state)
		{
		case CONN_STATE_IDLE:
			list_del(&entry->list);
			break;

		case CONN_STATE_ERROR:
			res->error = entry->error;
			state = CS_STATE_ERROR;
		case CONN_STATE_RECEIVING:
			session = entry->session;
			break;

		case CONN_STATE_SUCCESS:
			/* This may happen only if handler_threads > 1. */
			entry->state = CONN_STATE_CLOSING;
			entry = NULL;
			break;
		}

		pthread_mutex_unlock(&target->mutex);
		pthread_mutex_unlock(mutex);
		break;
	}

	if (entry)
	{
		if (session)
		{
			target->release();
			session->handle(state, res->error);
		}

		if (__sync_sub_and_fetch(&entry->ref, 1) == 0)
			this->release_conn(entry);
	}
}

void Communicator::handle_read_result(struct poller_result *res)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)res->data.context;

	if (res->state != PR_ST_MODIFIED)
	{
		if (entry->service)
			this->handle_incoming_request(res);
		else
			this->handle_incoming_reply(res);
	}
}

void Communicator::handle_reply_result(struct poller_result *res)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)res->data.context;
	CommService *service = entry->service;
	CommSession *session = entry->session;
	CommTarget *target = entry->target;
	int timeout;
	int state;

	switch (res->state)
	{
	case PR_ST_FINISHED:
		timeout = session->keep_alive_timeout();
		if (timeout != 0)
		{
			__sync_add_and_fetch(&entry->ref, 1);
			res->data.operation = PD_OP_READ;
			res->data.message = NULL;
			pthread_mutex_lock(&target->mutex);
			if (mpoller_add(&res->data, timeout, this->mpoller) >= 0)
			{
				pthread_mutex_lock(&service->mutex);
				if (!this->stop_flag && service->listen_fd >= 0)
				{
					entry->state = CONN_STATE_KEEPALIVE;
					list_add_tail(&entry->list, &service->alive_list);
				}
				else
				{
					mpoller_del(res->data.fd, this->mpoller);
					entry->state = CONN_STATE_CLOSING;
				}

				pthread_mutex_unlock(&service->mutex);
			}
			else
				__sync_sub_and_fetch(&entry->ref, 1);

			pthread_mutex_unlock(&target->mutex);
		}

		if (1)
			state = CS_STATE_SUCCESS;
		else if (1)
	case PR_ST_ERROR:
			state = CS_STATE_ERROR;
		else
	case PR_ST_DELETED:		/* DELETED seems not possible. */
	case PR_ST_STOPPED:
			state = CS_STATE_STOPPED;

		session->handle(state, res->error);
		if (__sync_sub_and_fetch(&entry->ref, 1) == 0)
		{
			this->release_conn(entry);
			((CommServiceTarget *)target)->decref();
		}

		break;
	}
}

void Communicator::handle_request_result(struct poller_result *res)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)res->data.context;
	CommSession *session = entry->session;
	int timeout;
	int state;

	switch (res->state)
	{
	case PR_ST_FINISHED:
		entry->state = CONN_STATE_RECEIVING;
		res->data.operation = PD_OP_READ;
		res->data.message = NULL;
		timeout = session->first_timeout();
		if (timeout == 0)
			timeout = Communicator::first_timeout_recv(session);
		else
		{
			session->timeout = -1;
			session->begin_time.tv_nsec = -1;
		}

		if (mpoller_add(&res->data, timeout, this->mpoller) >= 0)
		{
			if (this->stop_flag)
				mpoller_del(res->data.fd, this->mpoller);
			break;
		}

		res->error = errno;
		if (1)
	case PR_ST_ERROR:
			state = CS_STATE_ERROR;
		else
	case PR_ST_DELETED:
	case PR_ST_STOPPED:
			state = CS_STATE_STOPPED;

		entry->target->release();
		session->handle(state, res->error);
		pthread_mutex_lock(&entry->mutex);
		/* do nothing */
		pthread_mutex_unlock(&entry->mutex);
		if (__sync_sub_and_fetch(&entry->ref, 1) == 0)
			this->release_conn(entry);

		break;
	}
}

void Communicator::handle_write_result(struct poller_result *res)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)res->data.context;

	free(entry->write_iov);
	if (entry->service)
		this->handle_reply_result(res);
	else
		this->handle_request_result(res);
}

struct CommConnEntry *Communicator::accept_conn(CommServiceTarget *target,
												CommService *service)
{
	struct CommConnEntry *entry;
	size_t size;

	if (__set_fd_nonblock(target->sockfd) >= 0)
	{
		size = offsetof(struct CommConnEntry, mutex);
		entry = (struct CommConnEntry *)malloc(size);
		if (entry)
		{
			entry->conn = service->new_connection(target->sockfd);
			if (entry->conn)
			{
				entry->seq = 0;
				entry->mpoller = this->mpoller;
				entry->service = service;
				entry->target = target;
				entry->ssl = NULL;
				entry->sockfd = target->sockfd;
				entry->state = CONN_STATE_CONNECTED;
				entry->ref = 1;
				return entry;
			}

			free(entry);
		}
	}

	return NULL;
}

void Communicator::handle_listen_result(struct poller_result *res)
{
	CommService *service = (CommService *)res->data.context;
	struct CommConnEntry *entry;
	CommServiceTarget *target;
	struct poller_data data;
	int timeout;
	int ret;

	switch (res->state)
	{
	case PR_ST_SUCCESS:
		target = (CommServiceTarget *)res->data.result;
		entry = this->accept_conn(target, service);
		if (entry)
		{
			if (service->ssl_ctx)
			{
				ret = __create_ssl(service->ssl_ctx, entry);
				if (ret >= 0)
				{
					data.operation = PD_OP_SSL_ACCEPT;
					timeout = service->ssl_accept_timeout;
				}
			}
			else
			{
				ret = 0;
				data.operation = PD_OP_READ;
				data.message = NULL;
				timeout = target->response_timeout;
			}

			if (ret >= 0)
			{
				data.fd = entry->sockfd;
				data.ssl = entry->ssl;
				data.context = entry;
				if (mpoller_add(&data, timeout, this->mpoller) >= 0)
				{
					if (this->stop_flag)
						mpoller_del(data.fd, this->mpoller);
					break;
				}
			}

			this->release_conn(entry);
		}
		else
			close(target->sockfd);

		target->decref();
		break;

	case PR_ST_DELETED:
		this->shutdown_service(service);
		break;

	case PR_ST_ERROR:
	case PR_ST_STOPPED:
		service->handle_stop(res->error);
		break;
	}
}

void Communicator::handle_connect_result(struct poller_result *res)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)res->data.context;
	CommSession *session = entry->session;
	CommTarget *target = entry->target;
	int timeout;
	int state;
	int ret;

	switch (res->state)
	{
	case PR_ST_FINISHED:
		if (target->ssl_ctx && !entry->ssl)
		{
			ret = __create_ssl(target->ssl_ctx, entry);
			if (ret >= 0)
			{
				res->data.operation = PD_OP_SSL_CONNECT;
				res->data.ssl = entry->ssl;
				timeout = target->ssl_connect_timeout;
			}
		}
		else if ((session->out = session->message_out()) != NULL)
		{
			ret = this->send_message(entry);
			if (ret == 0)
			{
				res->data.operation = PD_OP_READ;
				res->data.message = NULL;
				timeout = session->first_timeout();
				if (timeout == 0)
					timeout = Communicator::first_timeout_recv(session);
				else
				{
					session->timeout = -1;
					session->begin_time.tv_nsec = -1;
				}
			}
			else if (ret > 0)
				break;
		}
		else
			ret = -1;

		if (ret >= 0)
		{
			if (mpoller_add(&res->data, timeout, this->mpoller) >= 0)
			{
				if (this->stop_flag)
					mpoller_del(res->data.fd, this->mpoller);
				break;
			}
		}

		res->error = errno;
		if (1)
	case PR_ST_ERROR:
			state = CS_STATE_ERROR;
		else
	case PR_ST_DELETED:
	case PR_ST_STOPPED:
			state = CS_STATE_STOPPED;

		target->release();
		session->handle(state, res->error);
		this->release_conn(entry);
		break;
	}
}

void Communicator::handle_ssl_accept_result(struct poller_result *res)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)res->data.context;
	CommTarget *target = entry->target;
	int timeout;

	switch (res->state)
	{
	case PR_ST_FINISHED:
		res->data.operation = PD_OP_READ;
		res->data.message = NULL;
		timeout = target->response_timeout;
		if (mpoller_add(&res->data, timeout, this->mpoller) >= 0)
		{
			if (this->stop_flag)
				mpoller_del(res->data.fd, this->mpoller);
			break;
		}

	case PR_ST_DELETED:
	case PR_ST_ERROR:
	case PR_ST_STOPPED:
		this->release_conn(entry);
		((CommServiceTarget *)target)->decref();
		break;
	}
}

void Communicator::handle_sleep_result(struct poller_result *res)
{
	SleepSession *session = (SleepSession *)res->data.context;
	int state;

	if (res->state == PR_ST_STOPPED)
		state = SS_STATE_DISRUPTED;
	else
		state = SS_STATE_COMPLETE;

	session->handle(state, 0);
}

void Communicator::handle_aio_result(struct poller_result *res)
{
	IOService *service = (IOService *)res->data.context;
	IOSession *session;
	int state, error;

	switch (res->state)
	{
	case PR_ST_SUCCESS:
		session = (IOSession *)res->data.result;
		pthread_mutex_lock(&service->mutex);
		list_del(&session->list);
		pthread_mutex_unlock(&service->mutex);
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
		service->decref();
		break;

	case PR_ST_DELETED:
		this->shutdown_io_service(service);
		break;

	case PR_ST_ERROR:
	case PR_ST_STOPPED:
		service->handle_stop(res->error);
		break;
	}
}

void Communicator::handler_thread_routine(void *context)
{
	Communicator *comm = (Communicator *)context;
	struct poller_result *res;

	while ((res = (struct poller_result *)msgqueue_get(comm->queue)) != NULL)
	{
		switch (res->data.operation)
		{
		case PD_OP_READ:
			comm->handle_read_result(res);
			break;
		case PD_OP_WRITE:
			comm->handle_write_result(res);
			break;
		case PD_OP_CONNECT:
		case PD_OP_SSL_CONNECT:
			comm->handle_connect_result(res);
			break;
		case PD_OP_LISTEN:
			comm->handle_listen_result(res);
			break;
		case PD_OP_SSL_ACCEPT:
			comm->handle_ssl_accept_result(res);
			break;
		case PD_OP_EVENT:
		case PD_OP_NOTIFY:
			comm->handle_aio_result(res);
			break;
		case PD_OP_TIMER:
			comm->handle_sleep_result(res);
			break;
		}

		free(res);
	}
}

int Communicator::append(const void *buf, size_t *size, poller_message_t *msg)
{
	CommMessageIn *in = (CommMessageIn *)msg;
	struct CommConnEntry *entry = in->entry;
	CommSession *session = entry->session;
	int timeout;
	int ret;

	ret = in->append(buf, size);
	if (ret > 0)
	{
		entry->state = CONN_STATE_SUCCESS;
		if (entry->service)
			timeout = -1;
		else
		{
			timeout = session->keep_alive_timeout();
			session->timeout = timeout; /* Reuse session's timeout field. */
			if (timeout == 0)
			{
				mpoller_del(entry->sockfd, entry->mpoller);
				return ret;
			}
		}
	}
	else if (ret == 0 && session->timeout != 0)
	{
		if (session->begin_time.tv_nsec == -1)
			timeout = Communicator::first_timeout_recv(session);
		else
			timeout = Communicator::next_timeout(session);
	}
	else
		return ret;

	/* This set_timeout() never fails, which is very important. */
	mpoller_set_timeout(entry->sockfd, timeout, entry->mpoller);
	return ret;
}

int Communicator::create_service_session(struct CommConnEntry *entry)
{
	CommService *service = entry->service;
	CommTarget *target = entry->target;
	CommSession *session;
	int timeout;

	pthread_mutex_lock(&service->mutex);
	if (entry->state == CONN_STATE_KEEPALIVE)
		list_del(&entry->list);
	else if (entry->state != CONN_STATE_CONNECTED)
		entry = NULL;

	pthread_mutex_unlock(&service->mutex);
	if (!entry)
	{
		errno = ENOENT;
		return -1;
	}

	session = service->new_session(entry->seq, entry->conn);
	if (session)
	{
		session->passive = 1;
		entry->session = session;
		session->target = target;
		session->conn = entry->conn;
		session->seq = entry->seq++;
		session->out = NULL;
		session->in = NULL;

		timeout = Communicator::first_timeout_recv(session);
		mpoller_set_timeout(entry->sockfd, timeout, entry->mpoller);
		entry->state = CONN_STATE_RECEIVING;

		((CommServiceTarget *)target)->incref();
		return 0;
	}

	return -1;
}

poller_message_t *Communicator::create_message(void *context)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)context;
	CommSession *session;

	if (entry->state == CONN_STATE_IDLE)
	{
		pthread_mutex_t *mutex;

		if (entry->service)
			mutex = &entry->target->mutex;
		else
			mutex = &entry->mutex;

		pthread_mutex_lock(mutex);
		/* do nothing */
		pthread_mutex_unlock(mutex);
	}

	if (entry->state == CONN_STATE_CONNECTED ||
		entry->state == CONN_STATE_KEEPALIVE)
	{
		if (Communicator::create_service_session(entry) < 0)
			return NULL;
	}
	else if (entry->state != CONN_STATE_RECEIVING)
	{
		errno = EBADMSG;
		return NULL;
	}

	session = entry->session;
	session->in = session->message_in();
	if (session->in)
	{
		session->in->poller_message_t::append = Communicator::append;
		session->in->entry = entry;
	}

	return session->in;
}

int Communicator::partial_written(size_t n, void *context)
{
	struct CommConnEntry *entry = (struct CommConnEntry *)context;
	CommSession *session = entry->session;
	int timeout;

	timeout = Communicator::next_timeout(session);
	mpoller_set_timeout(entry->sockfd, timeout, entry->mpoller);
	return 0;
}

void Communicator::callback(struct poller_result *res, void *context)
{
	Communicator *comm = (Communicator *)context;
	msgqueue_put(res, comm->queue);
}

void *Communicator::accept(const struct sockaddr *addr, socklen_t addrlen,
						   int sockfd, void *context)
{
	CommService *service = (CommService *)context;
	CommServiceTarget *target = new CommServiceTarget;

	if (target)
	{
		if (target->init(addr, addrlen, 0, service->response_timeout) >= 0)
		{
			service->incref();
			target->service = service;
			target->sockfd = sockfd;
			target->ref = 1;
			return target;
		}

		delete target;
	}

	close(sockfd);
	return NULL;
}

int Communicator::create_handler_threads(size_t handler_threads)
{
	struct thrdpool_task task = {
		.routine	=	Communicator::handler_thread_routine,
		.context	=	this
	};
	size_t i;

	this->thrdpool = thrdpool_create(handler_threads, 0);
	if (this->thrdpool)
	{
		for (i = 0; i < handler_threads; i++)
		{
			if (thrdpool_schedule(&task, this->thrdpool) < 0)
				break;
		}

		if (i == handler_threads)
			return 0;

		msgqueue_set_nonblock(this->queue);
		thrdpool_destroy(NULL, this->thrdpool);
	}

	return -1;
}

int Communicator::create_poller(size_t poller_threads)
{
	struct poller_params params = {
		.max_open_files		=	65536,
		.create_message		=	Communicator::create_message,
		.partial_written	=	Communicator::partial_written,
		.callback			=	Communicator::callback,
		.context			=	this
	};

	this->queue = msgqueue_create(4096, sizeof (struct poller_result));
	if (this->queue)
	{
		this->mpoller = mpoller_create(&params, poller_threads);
		if (this->mpoller)
		{
			if (mpoller_start(this->mpoller) >= 0)
				return 0;

			mpoller_destroy(this->mpoller);
		}

		msgqueue_destroy(this->queue);
	}

	return -1;
}

int Communicator::init(size_t poller_threads, size_t handler_threads)
{
	if (poller_threads == 0 || handler_threads == 0)
	{
		errno = EINVAL;
		return -1;
	}

	if (this->create_poller(poller_threads) >= 0)
	{
		if (this->create_handler_threads(handler_threads) >= 0)
		{
			this->stop_flag = 0;
			return 0;
		}

		mpoller_stop(this->mpoller);
		mpoller_destroy(this->mpoller);
		msgqueue_destroy(this->queue);
	}

	return -1;
}

void Communicator::deinit()
{
	this->stop_flag = 1;
	mpoller_stop(this->mpoller);
	msgqueue_set_nonblock(this->queue);
	thrdpool_destroy(NULL, this->thrdpool);
	mpoller_destroy(this->mpoller);
	msgqueue_destroy(this->queue);
}

int Communicator::nonblock_connect(CommTarget *target)
{
	int sockfd = target->create_connect_fd();

	if (sockfd >= 0)
	{
		if (__set_fd_nonblock(sockfd) >= 0)
		{
			if (connect(sockfd, target->addr, target->addrlen) >= 0 ||
				errno == EINPROGRESS)
			{
				return sockfd;
			}
		}

		close(sockfd);
	}

	return -1;
}

struct CommConnEntry *Communicator::launch_conn(CommSession *session,
												CommTarget *target)
{
	struct CommConnEntry *entry;
	int sockfd;
	int ret;

	sockfd = this->nonblock_connect(target);
	if (sockfd >= 0)
	{
		entry = (struct CommConnEntry *)malloc(sizeof (struct CommConnEntry));
		if (entry)
		{
			ret = pthread_mutex_init(&entry->mutex, NULL);
			if (ret == 0)
			{
				entry->conn = target->new_connection(sockfd);
				if (entry->conn)
				{
					entry->seq = 0;
					entry->mpoller = this->mpoller;
					entry->service = NULL;
					entry->target = target;
					entry->session = session;
					entry->ssl = NULL;
					entry->sockfd = sockfd;
					entry->state = CONN_STATE_CONNECTING;
					entry->ref = 1;
					return entry;
				}

				pthread_mutex_destroy(&entry->mutex);
			}
			else
				errno = ret;

			free(entry);
		}

		close(sockfd);
	}

	return NULL;
}

struct CommConnEntry *Communicator::get_idle_conn(CommTarget *target)
{
	struct CommConnEntry *entry;
	struct list_head *pos;

	list_for_each(pos, &target->idle_list)
	{
		entry = list_entry(pos, struct CommConnEntry, list);
		if (mpoller_set_timeout(entry->sockfd, -1, this->mpoller) >= 0)
		{
			list_del(pos);
			return entry;
		}
	}

	errno = ENOENT;
	return NULL;
}

int Communicator::request_idle_conn(CommSession *session, CommTarget *target)
{
	struct CommConnEntry *entry;
	int ret = -1;

	pthread_mutex_lock(&target->mutex);
	entry = this->get_idle_conn(target);
	if (entry)
		pthread_mutex_lock(&entry->mutex);
	pthread_mutex_unlock(&target->mutex);
	if (entry)
	{
		entry->session = session;
		session->conn = entry->conn;
		session->seq = entry->seq++;
		session->out = session->message_out();
		if (session->out)
			ret = this->send_message(entry);

		if (ret < 0)
		{
			entry->error = errno;
			mpoller_del(entry->sockfd, this->mpoller);
			entry->state = CONN_STATE_ERROR;
			ret = 1;
		}

		pthread_mutex_unlock(&entry->mutex);
	}

	return ret;
}

int Communicator::request(CommSession *session, CommTarget *target)
{
	struct CommConnEntry *entry;
	struct poller_data data;
	int errno_bak;
	int ret;

	if (session->passive)
	{
		errno = EINVAL;
		return -1;
	}

	errno_bak = errno;
	session->target = target;
	session->out = NULL;
	session->in = NULL;
	ret = this->request_idle_conn(session, target);
	while (ret < 0)
	{
		entry = this->launch_conn(session, target);
		if (entry)
		{
			session->conn = entry->conn;
			session->seq = entry->seq++;
			data.operation = PD_OP_CONNECT;
			data.fd = entry->sockfd;
			data.ssl = NULL;
			data.context = entry;
			if (mpoller_add(&data, target->connect_timeout, this->mpoller) >= 0)
				break;

			this->release_conn(entry);
		}

		session->conn = NULL;
		session->seq = 0;
		return -1;
	}

	errno = errno_bak;
	return 0;
}

int Communicator::nonblock_listen(CommService *service)
{
	int sockfd = service->create_listen_fd();

	if (sockfd >= 0)
	{
		if (__set_fd_nonblock(sockfd) >= 0)
		{
			if (__bind_and_listen(sockfd, service->bind_addr,
								  service->addrlen) >= 0)
			{
				return sockfd;
			}
		}

		close(sockfd);
	}

	return -1;
}

int Communicator::bind(CommService *service)
{
	struct poller_data data;
	int sockfd;

	sockfd = this->nonblock_listen(service);
	if (sockfd >= 0)
	{
		service->listen_fd = sockfd;
		service->ref = 1;
		data.operation = PD_OP_LISTEN;
		data.fd = sockfd;
		data.accept = Communicator::accept;
		data.context = service;
		data.result = NULL;
		if (mpoller_add(&data, service->listen_timeout, this->mpoller) >= 0)
			return 0;

		close(sockfd);
	}

	return -1;
}

void Communicator::unbind(CommService *service)
{
	int errno_bak = errno;

	if (mpoller_del(service->listen_fd, this->mpoller) < 0)
	{
		/* Error occurred on listen_fd or Communicator::deinit() called. */
		this->shutdown_service(service);
		errno = errno_bak;
	}
}

int Communicator::reply_idle_conn(CommSession *session, CommTarget *target)
{
	struct CommConnEntry *entry;
	int ret = -1;

	pthread_mutex_lock(&target->mutex);
	if (!list_empty(&target->idle_list))
	{
		entry = list_entry(target->idle_list.next, struct CommConnEntry, list);
		list_del(&entry->list);

		session->out = session->message_out();
		if (session->out)
			ret = this->send_message(entry);

		if (ret < 0)
		{
			entry->error = errno;
			mpoller_del(entry->sockfd, this->mpoller);
			entry->state = CONN_STATE_ERROR;
			ret = 1;
		}
	}
	else
		errno = ENOENT;

	pthread_mutex_unlock(&target->mutex);
	return ret;
}

int Communicator::reply(CommSession *session)
{
	struct CommConnEntry *entry;
	CommTarget *target;
	int errno_bak;
	int ret;

	if (session->passive != 1)
	{
		errno = session->passive ? ENOENT : EINVAL;
		return -1;
	}

	errno_bak = errno;
	session->passive = 2;
	target = session->target;
	ret = this->reply_idle_conn(session, target);
	if (ret < 0)
		return -1;

	if (ret == 0)
	{
		entry = session->in->entry;
		session->handle(CS_STATE_SUCCESS, 0);
		if (__sync_sub_and_fetch(&entry->ref, 1) == 0)
		{
			this->release_conn(entry);
			((CommServiceTarget *)target)->decref();
		}
	}

	errno = errno_bak;
	return 0;
}

int Communicator::sleep(SleepSession *session)
{
	struct timespec value;

	if (session->duration(&value) >= 0)
	{
		if (mpoller_add_timer(&value, session, this->mpoller) >= 0)
			return 0;
	}

	return -1;
}

int Communicator::is_handler_thread()
{
	return thrdpool_in_pool(this->thrdpool);
}

extern "C" void __thrdpool_schedule(const struct thrdpool_task *, void *,
									thrdpool_t *);

int Communicator::increase_handler_thread()
{
	void *buf = malloc(4 * sizeof (void *));

	if (buf)
	{
		if (thrdpool_increase(this->thrdpool) >= 0)
		{
			struct thrdpool_task task = {
				.routine	=	Communicator::handler_thread_routine,
				.context	=	this
			};
			__thrdpool_schedule(&task, buf, this->thrdpool);
			return 0;
		}

		free(buf);
	}

	return -1;
}

#ifdef __linux__

void Communicator::shutdown_io_service(IOService *service)
{
	pthread_mutex_lock(&service->mutex);
	close(service->event_fd);
	service->event_fd = -1;
	pthread_mutex_unlock(&service->mutex);
	service->decref();
}

int Communicator::io_bind(IOService *service)
{
	struct poller_data data;
	int event_fd;

	event_fd = service->create_event_fd();
	if (event_fd >= 0)
	{
		if (__set_fd_nonblock(event_fd) >= 0)
		{
			service->ref = 1;
			data.operation = PD_OP_EVENT;
			data.fd = event_fd;
			data.event = IOService::aio_finish;
			data.context = service;
			data.result = NULL;
			if (mpoller_add(&data, -1, this->mpoller) >= 0)
			{
				service->event_fd = event_fd;
				return 0;
			}
		}

		close(event_fd);
	}

	return -1;
}

void Communicator::io_unbind(IOService *service)
{
	int errno_bak = errno;

	if (mpoller_del(service->event_fd, this->mpoller) < 0)
	{
		/* Error occurred on event_fd or Communicator::deinit() called. */
		this->shutdown_io_service(service);
		errno = errno_bak;
	}
}

#else

void Communicator::shutdown_io_service(IOService *service)
{
	pthread_mutex_lock(&service->mutex);
	close(service->pipe_fd[0]);
	close(service->pipe_fd[1]);
	service->pipe_fd[0] = -1;
	service->pipe_fd[1] = -1;
	pthread_mutex_unlock(&service->mutex);
	service->decref();
}

int Communicator::io_bind(IOService *service)
{
	struct poller_data data;
	int pipe_fd[2];

	if (service->create_pipe_fd(pipe_fd) >= 0)
	{
		if (__set_fd_nonblock(pipe_fd[0]) >= 0)
		{
			service->ref = 1;
			data.operation = PD_OP_NOTIFY;
			data.fd = pipe_fd[0];
			data.notify = IOService::aio_finish;
			data.context = service;
			data.result = NULL;
			if (mpoller_add(&data, -1, this->mpoller) >= 0)
			{
				service->pipe_fd[0] = pipe_fd[0];
				service->pipe_fd[1] = pipe_fd[1];
				return 0;
			}
		}

		close(pipe_fd[0]);
		close(pipe_fd[1]);
	}

	return -1;
}

void Communicator::io_unbind(IOService *service)
{
	int errno_bak = errno;

	if (mpoller_del(service->pipe_fd[0], this->mpoller) < 0)
	{
		/* Error occurred on pipe_fd or Communicator::deinit() called. */
		this->shutdown_io_service(service);
		errno = errno_bak;
	}
}

#endif

