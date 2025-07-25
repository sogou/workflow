/*
  Copyright (c) 2020 Sogou, Inc.

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

#include <sys/uio.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include "list.h"
#include "IOService_thread.h"

typedef enum io_iocb_cmd {
	IO_CMD_PREAD = 0,
	IO_CMD_PWRITE = 1,

	IO_CMD_FSYNC = 2,
	IO_CMD_FDSYNC = 3,

	IO_CMD_NOOP = 6,
	IO_CMD_PREADV = 7,
	IO_CMD_PWRITEV = 8,
} io_iocb_cmd_t;

void IOSession::prep_pread(int fd, void *buf, size_t count, long long offset)
{
	this->fd = fd;
	this->op = IO_CMD_PREAD;
	this->buf = buf;
	this->count = count;
	this->offset = offset;
}

void IOSession::prep_pwrite(int fd, void *buf, size_t count, long long offset)
{
	this->fd = fd;
	this->op = IO_CMD_PWRITE;
	this->buf = buf;
	this->count = count;
	this->offset = offset;
}

void IOSession::prep_preadv(int fd, const struct iovec *iov, int iovcnt,
							long long offset)
{
	this->fd = fd;
	this->op = IO_CMD_PREADV;
	this->buf = (void *)iov;
	this->count = iovcnt;
	this->offset = offset;
}

void IOSession::prep_pwritev(int fd, const struct iovec *iov, int iovcnt,
							 long long offset)
{
	this->fd = fd;
	this->op = IO_CMD_PWRITEV;
	this->buf = (void *)iov;
	this->count = iovcnt;
	this->offset = offset;
}

void IOSession::prep_fsync(int fd)
{
	this->fd = fd;
	this->op = IO_CMD_FSYNC;
}

void IOSession::prep_fdsync(int fd)
{
	this->fd = fd;
	this->op = IO_CMD_FDSYNC;
}

int IOService::init(int maxevents)
{
	void *p;
	int ret;

	if (maxevents <= 0)
	{
		errno = EINVAL;
		return -1;
	}

	ret = pthread_mutex_init(&this->mutex, NULL);
	if (ret)
	{
		errno = ret;
		return -1;
	}

	p = dlsym(RTLD_DEFAULT, "preadv");
	if (p)
		this->preadv = (ssize_t (*)(int, const struct iovec *, int, off_t))p;
	else
		this->preadv = IOService::preadv_emul;

	p = dlsym(RTLD_DEFAULT, "pwritev");
	if (p)
		this->pwritev = (ssize_t (*)(int, const struct iovec *, int, off_t))p;
	else
		this->pwritev = IOService::pwritev_emul;

	this->maxevents = maxevents;
	this->nevents = 0;
	INIT_LIST_HEAD(&this->session_list);
	this->pipe_fd[0] = -1;
	this->pipe_fd[1] = -1;
	return 0;
}

void IOService::deinit()
{
	pthread_mutex_destroy(&this->mutex);
}

inline void IOService::incref()
{
	__sync_add_and_fetch(&this->ref, 1);
}

void IOService::decref()
{
	IOSession *session;
	int state, error;

	if (__sync_sub_and_fetch(&this->ref, 1) == 0)
	{
		while (!list_empty(&this->session_list))
		{
			session = list_entry(this->session_list.next, IOSession, list);
			pthread_join(session->tid, NULL);
			list_del(&session->list);
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

		pthread_mutex_lock(&this->mutex);
		/* Wait for detached threads. */
		pthread_mutex_unlock(&this->mutex);
		this->handle_unbound();
	}
}

int IOService::request(IOSession *session)
{
	pthread_t tid;
	int ret = -1;

	pthread_mutex_lock(&this->mutex);
	if (this->pipe_fd[0] < 0)
		errno = ENOENT;
	else if (this->nevents >= this->maxevents)
		errno = EAGAIN;
	else if (session->prepare() >= 0)
	{
		session->service = this;
		ret = pthread_create(&tid, NULL, IOService::io_routine, session);
		if (ret == 0)
		{
			session->tid = tid;
			list_add_tail(&session->list, &this->session_list);
			this->nevents++;
		}
		else
		{
			errno = ret;
			ret = -1;
		}
	}

	pthread_mutex_unlock(&this->mutex);
	if (ret < 0)
		session->res = -errno;

	return ret;
}

void *IOService::io_routine(void *arg)
{
	IOSession *session = (IOSession *)arg;
	IOService *service = session->service;
	int fd = session->fd;
	ssize_t ret;

	switch (session->op)
	{
	case IO_CMD_PREAD:
		ret = pread(fd, session->buf, session->count, session->offset);
		break;
	case IO_CMD_PWRITE:
		ret = pwrite(fd, session->buf, session->count, session->offset);
		break;
		ret = fsync(fd);
		break;
	case IO_CMD_FDSYNC:
#if _POSIX_SYNCHRONIZED_IO > 0
		ret = fdatasync(fd);
		break;
#endif
	case IO_CMD_FSYNC:
		ret = fsync(fd);
		break;
	case IO_CMD_PREADV:
		ret = service->preadv(fd, (const struct iovec *)session->buf,
							  session->count, session->offset);
		break;
	case IO_CMD_PWRITEV:
		ret = service->pwritev(fd, (const struct iovec *)session->buf,
							   session->count, session->offset);
		break;
	default:
		errno = EINVAL;
		ret = -1;
		break;
	}

	if (ret < 0)
		ret = -errno;

	session->res = ret;
	pthread_mutex_lock(&service->mutex);
	if (service->pipe_fd[1] >= 0)
		write(service->pipe_fd[1], &session, sizeof (void *));

	service->nevents--;
	pthread_mutex_unlock(&service->mutex);
	return NULL;
}

void *IOService::aio_finish(void *ptr, void *context)
{
	IOService *service = (IOService *)context;
	IOSession *session = (IOSession *)ptr;

	service->incref();
	pthread_detach(session->tid);
	return session;
}

ssize_t IOService::preadv_emul(int fd, const struct iovec *iov, int iovcnt,
							   off_t offset)
{
	size_t total = 0;
	ssize_t n;
	int i;

	for (i = 0; i < iovcnt; i++)
	{
		n = pread(fd, iov[i].iov_base, iov[i].iov_len, offset);
		if (n < 0)
			return total == 0 ? -1 : total;

		total += n;
		if ((size_t)n < iov[i].iov_len)
			return total;

		offset += n;
	}

	return total;
}

ssize_t IOService::pwritev_emul(int fd, const struct iovec *iov, int iovcnt,
								off_t offset)
{
	size_t total = 0;
	ssize_t n;
	int i;

	for (i = 0; i < iovcnt; i++)
	{
		n = pwrite(fd, iov[i].iov_base, iov[i].iov_len, offset);
		if (n < 0)
			return total == 0 ? -1 : total;

		total += n;
		if ((size_t)n < iov[i].iov_len)
			return total;

		offset += n;
	}

	return total;
}

