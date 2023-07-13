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

#ifndef _COMMUNICATOR_H_
#define _COMMUNICATOR_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <stddef.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include "list.h"
#include "poller.h"

class CommConnection
{
protected:
	virtual ~CommConnection() { }
	friend class Communicator;
};

class CommTarget
{
public:
	int init(const struct sockaddr *addr, socklen_t addrlen,
			 int connect_timeout, int response_timeout);
	void deinit();

public:
	void get_addr(const struct sockaddr **addr, socklen_t *addrlen) const
	{
		*addr = this->addr;
		*addrlen = this->addrlen;
	}

	int has_idle_conn() const { return !list_empty(&this->idle_list); }

protected:
	void set_ssl(SSL_CTX *ssl_ctx, int ssl_connect_timeout)
	{
		this->ssl_ctx = ssl_ctx;
		this->ssl_connect_timeout = ssl_connect_timeout;
	}

	SSL_CTX *get_ssl_ctx() const { return this->ssl_ctx; }

private:
	virtual int create_connect_fd()
	{
		return socket(this->addr->sa_family, SOCK_STREAM, 0);
	}

	virtual CommConnection *new_connection(int connect_fd)
	{
		return new CommConnection;
	}

	virtual int init_ssl(SSL *ssl) { return 0; }

public:
	virtual void release() { }

private:
	struct sockaddr *addr;
	socklen_t addrlen;
	int connect_timeout;
	int response_timeout;
	int ssl_connect_timeout;
	SSL_CTX *ssl_ctx;

private:
	struct list_head idle_list;
	pthread_mutex_t mutex;

public:
	virtual ~CommTarget() { }
	friend class CommSession;
	friend class Communicator;
};

class CommMessageOut
{
private:
	virtual int encode(struct iovec vectors[], int max) = 0;

public:
	virtual ~CommMessageOut() { }
	friend class Communicator;
};

class CommMessageIn : private poller_message_t
{
private:
	virtual int append(const void *buf, size_t *size) = 0;

protected:
	/* Send small packet while receiving. Call only in append(). */
	virtual int feedback(const void *buf, size_t size);

	/* In append(), reset the begin time of receiving to current time. */
	virtual void renew();

private:
	struct CommConnEntry *entry;

public:
	virtual ~CommMessageIn() { }
	friend class Communicator;
};

#define CS_STATE_SUCCESS	0
#define CS_STATE_ERROR		1
#define CS_STATE_STOPPED	2
#define CS_STATE_TOREPLY	3	/* for service session only. */

class CommSession
{
private:
	virtual CommMessageOut *message_out() = 0;
	virtual CommMessageIn *message_in() = 0;
	virtual int send_timeout() { return -1; }
	virtual int receive_timeout() { return -1; }
	virtual int keep_alive_timeout() { return 0; }
	virtual int first_timeout() { return 0; }	/* for client session only. */
	virtual void handle(int state, int error) = 0;

protected:
	CommTarget *get_target() const { return this->target; }
	CommConnection *get_connection() const { return this->conn; }
	CommMessageOut *get_message_out() const { return this->out; }
	CommMessageIn *get_message_in() const { return this->in; }
	long long get_seq() const { return this->seq; }

private:
	CommTarget *target;
	CommConnection *conn;
	CommMessageOut *out;
	CommMessageIn *in;
	long long seq;

private:
	struct timespec begin_time;
	int timeout;
	int passive;

public:
	CommSession() { this->passive = 0; }
	virtual ~CommSession();
	friend class CommMessageIn;
	friend class Communicator;
};

class CommService
{
public:
	int init(const struct sockaddr *bind_addr, socklen_t addrlen,
			 int listen_timeout, int response_timeout);
	void deinit();

	int drain(int max);

public:
	void get_addr(const struct sockaddr **addr, socklen_t *addrlen) const
	{
		*addr = this->bind_addr;
		*addrlen = this->addrlen;
	}

protected:
	void set_ssl(SSL_CTX *ssl_ctx, int ssl_accept_timeout)
	{
		this->ssl_ctx = ssl_ctx;
		this->ssl_accept_timeout = ssl_accept_timeout;
	}

	SSL_CTX *get_ssl_ctx() const { return this->ssl_ctx; }

private:
	virtual CommSession *new_session(long long seq, CommConnection *conn) = 0;
	virtual void handle_stop(int error) { }
	virtual void handle_unbound() = 0;

private:
	virtual int create_listen_fd()
	{
		return socket(this->bind_addr->sa_family, SOCK_STREAM, 0);
	}

	virtual CommConnection *new_connection(int accept_fd)
	{
		return new CommConnection;
	}

	virtual int init_ssl(SSL *ssl) { return 0; }

private:
	struct sockaddr *bind_addr;
	socklen_t addrlen;
	int listen_timeout;
	int response_timeout;
	int ssl_accept_timeout;
	SSL_CTX *ssl_ctx;

private:
	void incref();
	void decref();

private:
	int listen_fd;
	int ref;

private:
	struct list_head alive_list;
	pthread_mutex_t mutex;

public:
	virtual ~CommService() { }
	friend class CommServiceTarget;
	friend class Communicator;
};

#define SS_STATE_COMPLETE	0
#define SS_STATE_ERROR		1
#define SS_STATE_DISRUPTED	2

class SleepSession
{
private:
	virtual int duration(struct timespec *value) = 0;
	virtual void handle(int state, int error) = 0;

public:
	virtual ~SleepSession() { }
	friend class Communicator;
};

#ifdef __linux__
# include "IOService_linux.h"
#else
# include "IOService_thread.h"
#endif

class Communicator
{
public:
	int init(size_t poller_threads, size_t handler_threads);
	void deinit();

	int request(CommSession *session, CommTarget *target);
	int reply(CommSession *session);

	int push(const void *buf, size_t size, CommSession *session);

	int bind(CommService *service);
	void unbind(CommService *service);

	int sleep(SleepSession *session);

	int io_bind(IOService *service);
	void io_unbind(IOService *service);

public:
	int is_handler_thread() const;
	int increase_handler_thread();

private:
	struct __mpoller *mpoller;
	struct __msgqueue *msgqueue;
	struct __thrdpool *thrdpool;
	int stop_flag;

private:
	int create_poller(size_t poller_threads);

	int create_handler_threads(size_t handler_threads);

	int nonblock_connect(CommTarget *target);
	int nonblock_listen(CommService *service);

	struct CommConnEntry *launch_conn(CommSession *session,
									  CommTarget *target);
	struct CommConnEntry *accept_conn(class CommServiceTarget *target,
									  CommService *service);

	void release_conn(struct CommConnEntry *entry);

	void shutdown_service(CommService *service);

	void shutdown_io_service(IOService *service);

	int send_message_sync(struct iovec vectors[], int cnt,
						  struct CommConnEntry *entry);
	int send_message_async(struct iovec vectors[], int cnt,
						   struct CommConnEntry *entry);

	int send_message(struct CommConnEntry *entry);

	int request_idle_conn(CommSession *session, CommTarget *target);
	int reply_idle_conn(CommSession *session, CommTarget *target);

	int request_new_conn(CommSession *session, CommTarget *target);

	void handle_incoming_request(struct poller_result *res);
	void handle_incoming_reply(struct poller_result *res);

	void handle_request_result(struct poller_result *res);
	void handle_reply_result(struct poller_result *res);

	void handle_write_result(struct poller_result *res);
	void handle_read_result(struct poller_result *res);

	void handle_connect_result(struct poller_result *res);
	void handle_listen_result(struct poller_result *res);

	void handle_ssl_accept_result(struct poller_result *res);

	void handle_sleep_result(struct poller_result *res);

	void handle_aio_result(struct poller_result *res);

	static void handler_thread_routine(void *context);

	static int first_timeout(CommSession *session);
	static int next_timeout(CommSession *session);

	static int first_timeout_send(CommSession *session);
	static int first_timeout_recv(CommSession *session);

	static int append_request(const void *buf, size_t *size,
							  poller_message_t *msg);
	static int append_reply(const void *buf, size_t *size,
							poller_message_t *msg);

	static poller_message_t *create_request(void *context);
	static poller_message_t *create_reply(void *context);

	static int partial_written(size_t n, void *context);

	static void *accept(const struct sockaddr *addr, socklen_t addrlen,
						int sockfd, void *context);

	static void callback(struct poller_result *res, void *context);

public:
	virtual ~Communicator() { }
};

#endif

