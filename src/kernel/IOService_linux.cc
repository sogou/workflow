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

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include "list.h"
#include "IOService_linux.h"

/* Linux async I/O interface from libaio.h */

typedef struct io_context *io_context_t;

typedef enum io_iocb_cmd {
	IO_CMD_PREAD = 0,
	IO_CMD_PWRITE = 1,

	IO_CMD_FSYNC = 2,
	IO_CMD_FDSYNC = 3,

	IO_CMD_POLL = 5,
	IO_CMD_NOOP = 6,
	IO_CMD_PREADV = 7,
	IO_CMD_PWRITEV = 8,
} io_iocb_cmd_t;

/* little endian, 32 bits */
#if defined(__i386__) || (defined(__arm__) && !defined(__ARMEB__)) || \
    defined(__sh__) || defined(__bfin__) || defined(__MIPSEL__) || \
    defined(__cris__) || (defined(__riscv) && __riscv_xlen == 32) || \
    (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
         __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && __SIZEOF_LONG__ == 4)
#define PADDED(x, y)	x; unsigned y
#define PADDEDptr(x, y)	x; unsigned y
#define PADDEDul(x, y)	unsigned long x; unsigned y

/* little endian, 64 bits */
#elif defined(__ia64__) || defined(__x86_64__) || defined(__alpha__) || \
      (defined(__aarch64__) && defined(__AARCH64EL__)) || \
      (defined(__riscv) && __riscv_xlen == 64) || \
      (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
          __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && __SIZEOF_LONG__ == 8)
#define PADDED(x, y)	x, y
#define PADDEDptr(x, y)	x
#define PADDEDul(x, y)	unsigned long x

/* big endian, 64 bits */
#elif defined(__powerpc64__) || defined(__s390x__) || \
      (defined(__sparc__) && defined(__arch64__)) || \
      (defined(__aarch64__) && defined(__AARCH64EB__)) || \
      (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
           __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && __SIZEOF_LONG__ == 8)
#define PADDED(x, y)	unsigned y; x
#define PADDEDptr(x,y)	x
#define PADDEDul(x, y)	unsigned long x

/* big endian, 32 bits */
#elif defined(__PPC__) || defined(__s390__) || \
      (defined(__arm__) && defined(__ARMEB__)) || \
      defined(__sparc__) || defined(__MIPSEB__) || defined(__m68k__) || \
      defined(__hppa__) || defined(__frv__) || defined(__avr32__) || \
      (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
           __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && __SIZEOF_LONG__ == 4)
#define PADDED(x, y)	unsigned y; x
#define PADDEDptr(x, y)	unsigned y; x
#define PADDEDul(x, y)	unsigned y; unsigned long x

#else
#error	endian?
#endif

struct io_iocb_poll {
	PADDED(int events, __pad1);
};	/* result code is the set of result flags or -'ve errno */

struct io_iocb_sockaddr {
	struct sockaddr *addr;
	int		len;
};	/* result code is the length of the sockaddr, or -'ve errno */

struct io_iocb_common {
	PADDEDptr(void	*buf, __pad1);
	PADDEDul(nbytes, __pad2);
	long long	offset;
	long long	__pad3;
	unsigned	flags;
	unsigned	resfd;
};	/* result code is the amount read or -'ve errno */

struct io_iocb_vector {
	const struct iovec	*vec;
	int			nr;
	long long		offset;
};	/* result code is the amount read or -'ve errno */

struct iocb {
	PADDEDptr(void *data, __pad1);	/* Return in the io completion event */
	/* key: For use in identifying io requests */
	/* aio_rw_flags: RWF_* flags (such as RWF_NOWAIT) */
	PADDED(unsigned key, aio_rw_flags);

	short		aio_lio_opcode;	
	short		aio_reqprio;
	int		aio_fildes;

	union {
		struct io_iocb_common		c;
		struct io_iocb_vector		v;
		struct io_iocb_poll		poll;
		struct io_iocb_sockaddr	saddr;
	} u;
};

struct io_event {
	PADDEDptr(void *data, __pad1);
	PADDEDptr(struct iocb *obj,  __pad2);
	PADDEDul(res,  __pad3);
	PADDEDul(res2, __pad4);
};

#undef PADDED
#undef PADDEDptr
#undef PADDEDul

/* Actual syscalls */
static inline int io_setup(int maxevents, io_context_t *ctxp)
{
	return syscall(__NR_io_setup, maxevents, ctxp);
}

static inline int io_destroy(io_context_t ctx)
{
	return syscall(__NR_io_destroy, ctx);
}

static inline int io_submit(io_context_t ctx, long nr, struct iocb *ios[])
{
	return syscall(__NR_io_submit, ctx, nr, ios);
}

static inline int io_cancel(io_context_t ctx, struct iocb *iocb,
							struct io_event *evt)
{
	return syscall(__NR_io_cancel, ctx, iocb, evt);
}

static inline int io_getevents(io_context_t ctx_id, long min_nr, long nr,
							   struct io_event *events,
							   struct timespec *timeout)
{
	return syscall(__NR_io_getevents, ctx_id, min_nr, nr, events, timeout);
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

int IOService::init(int maxevents)
{
	int ret;

	if (maxevents < 0)
	{
		errno = EINVAL;
		return -1;
	}

	this->io_ctx = NULL;
	if (io_setup(maxevents, &this->io_ctx) >= 0)
	{
		ret = pthread_mutex_init(&this->mutex, NULL);
		if (ret == 0)
		{
			INIT_LIST_HEAD(&this->session_list);
			this->event_fd = -1;
			return 0;
		}

		errno = ret;
		io_destroy(this->io_ctx);
	}

	return -1;
}

void IOService::deinit()
{
	pthread_mutex_destroy(&this->mutex);
	io_destroy(this->io_ctx);
}

inline void IOService::incref()
{
	__sync_add_and_fetch(&this->ref, 1);
}

void IOService::decref()
{
	IOSession *session;
	struct io_event event;
	int state, error;

	if (__sync_sub_and_fetch(&this->ref, 1) == 0)
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

	pthread_mutex_lock(&this->mutex);
	if (this->event_fd < 0)
		errno = ENOENT;
	else if (session->prepare() >= 0)
	{
		io_set_eventfd(iocb, this->event_fd);
		iocb->data = session;
		if (io_submit(this->io_ctx, 1, &iocb) > 0)
		{
			list_add_tail(&session->list, &this->session_list);
			ret = 0;
		}
	}

	pthread_mutex_unlock(&this->mutex);
	if (ret < 0)
		session->res = -errno;

	return ret;
}

void *IOService::aio_finish(void *context)
{
	IOService *service = (IOService *)context;
	IOSession *session;
	struct io_event event;

	if (io_getevents(service->io_ctx, 1, 1, &event, NULL) > 0)
	{
		service->incref();
		session = (IOSession *)event.data;
		session->res = event.res;
		return session;
	}

	return NULL;
}

