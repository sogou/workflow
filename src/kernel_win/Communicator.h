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

#ifndef _COMMUNICATOR_H_
#define _COMMUNICATOR_H_

#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>
#include <mutex>
#include <atomic>
#include "PlatformSocket.h"
#include "list.h"
#include "thrdpool.h"
#include "WinPoller.h"

struct CommConnEntry;
class CommServiceTarget;

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
		return (int)socket(this->addr->sa_family, SOCK_STREAM, 0);
	}

	virtual CommConnection *new_connection(int connect_fd)
	{
		return new CommConnection;
	}

	virtual int init_ssl(SSL *ssl) { return 0; }

public:
	virtual void release(int keep_alive) { }

private:
	struct sockaddr *addr;
	socklen_t addrlen;
	int connect_timeout;
	int response_timeout;
	int ssl_connect_timeout;
	SSL_CTX *ssl_ctx;

private:
	struct list_head idle_list;
	std::mutex mutex;

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

class CommMessageIn
{
private:
	virtual int append(const void *buf, size_t *size) = 0;

protected:
	/* Send small packet while receiving. Call only in append(). */
	virtual int feedback(const void *buf, size_t size);

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
	int64_t begin_time;
	int timeout;
	int passive;

public:
	CommSession() { this->passive = 0; }
	virtual ~CommSession();
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
		return (int)socket(this->bind_addr->sa_family, SOCK_STREAM, 0);
	}

	virtual CommConnection *new_connection(int accept_fd)
	{
		return new CommConnection;
	}

	virtual int create_accept_fd()
	{
		return (int)socket(this->bind_addr->sa_family, SOCK_STREAM, 0);
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
	SOCKET listen_sockfd;
	std::atomic<int> ref;

private:
	struct list_head alive_list;
	std::mutex mutex;

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

#define IOS_STATE_SUCCESS	0
#define IOS_STATE_ERROR		1

class IOSession
{
public:
	void prep_pread(int fd, void *buf, size_t count, long long offset);
	void prep_pwrite(int fd, void *buf, size_t count, long long offset);
	void prep_preadv(int fd, const struct iovec *iov, int iovcnt,
					 long long offset);
	void prep_pwritev(int fd, const struct iovec *iov, int iovcnt,
					  long long offset);
	void prep_fsync(int fd);
	void prep_fdsync(int fd);

private:
	virtual void handle(int state, int error) = 0;

protected:
	long get_res() const { return this->res; }

private:
	char iocb_buf[64];
	long res;

private:
	struct list_head list;

public:
	IOSession();
	virtual ~IOSession() { }
	friend class IOService;
	friend class Communicator;
};

class IOService
{
public:
	int init(unsigned int maxevents);
	void deinit();

	int request(IOSession *session);

private:
	virtual void handle_stop(int error) { }
	virtual void handle_unbound() = 0;

private:
	struct io_context *io_ctx;

private:
	void incref();
	void decref();

private:
	int event_fd;
	int ref;

private:
	struct list_head session_list;
	std::mutex mutex;

public:
	virtual ~IOService() { }
	friend class Communicator;
};

//#endif

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
	int is_handler_thread() const { return thrdpool_in_pool(this->thrdpool); }
	int increase_handler_thread();

private:
	WinPoller *poller;
	thrdpool_t *thrdpool;
	std::atomic<size_t> total_fd_cnt;
	volatile bool stop_flag;
	size_t handler_threads;

private:
	static void handler_thread_routine(void *context);

	int create_handler_threads(size_t handler_threads);

	SOCKET nonblock_connect(CommTarget *target);
	SOCKET nonblock_accept(CommService *service);
	SOCKET nonblock_listen(CommService *service);

	CommConnEntry *accept_conn(CommServiceTarget *target, CommService *service);
	CommConnEntry *launch_conn(CommSession *session, CommTarget *target);
	void release_conn(CommConnEntry *entry);

	CommConnEntry *get_idle_conn(CommTarget *target);

	int send_message(CommConnEntry *entry);
	int send_message_async(struct iovec vectors[], int cnt,
						   CommConnEntry *entry);

	int first_timeout_send(CommSession *session);
	int first_timeout_recv(CommSession *session);
	int first_timeout(CommSession *session);
	int next_timeout(CommSession *session);

	int create_service_session(CommConnEntry *entry);

	void handle_read_result(struct poller_result *res);
	void handle_write_result(struct poller_result *res);
	void handle_connect_result(struct poller_result *res);
	void handle_accept_result(struct poller_result *res);
	void handle_sleep_result(struct poller_result *res);
	void handle_event_result(struct poller_result *res);

	bool handle_incoming_ssl_connect(CommConnEntry *entry);
	void handle_incoming_ssl_accept(CommConnEntry *entry);
	void handle_incoming_idle(struct poller_result *res);
	void handle_incoming_request(struct poller_result *res);
	void handle_incoming_reply(struct poller_result *res);
	void handle_request_result(struct poller_result *res);
	void handle_reply_result(struct poller_result *res);

/*

//#ifdef __linux__
	void shutdown_io_service(IOService *service);

	static void *aio_event(const struct io_event *event, void *context);
//#endif
*/
public:
	virtual ~Communicator() { }
};

#endif

