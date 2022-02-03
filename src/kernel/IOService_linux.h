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

#ifndef _IOSERVICE_LINUX_H_
#define _IOSERVICE_LINUX_H_

#include <sys/uio.h>
#include <sys/eventfd.h>
#include <stddef.h>
#include <pthread.h>
#include "list.h"

#define IOS_STATE_SUCCESS	0
#define IOS_STATE_ERROR		1

class IOSession
{
private:
	virtual int prepare() = 0;
	virtual void handle(int state, int error) = 0;

protected:
	/* prepare() has to call one of the the prep_ functions. */
	void prep_pread(int fd, void *buf, size_t count, long long offset);
	void prep_pwrite(int fd, void *buf, size_t count, long long offset);
	void prep_preadv(int fd, const struct iovec *iov, int iovcnt,
					 long long offset);
	void prep_pwritev(int fd, const struct iovec *iov, int iovcnt,
					  long long offset);
	void prep_fsync(int fd);
	void prep_fdsync(int fd);

protected:
	long get_res() const { return this->res; }

private:
	char iocb_buf[64];
	long res;

private:
	struct list_head list;

public:
	virtual ~IOSession() { }
	friend class IOService;
	friend class Communicator;
};

class IOService
{
public:
	int init(int maxevents);
	void deinit();

	int request(IOSession *session);

private:
	virtual void handle_stop(int error) { }
	virtual void handle_unbound() = 0;

private:
	virtual int create_event_fd()
	{
		return eventfd(0, 0);
	}

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
	pthread_mutex_t mutex;

private:
	static void *aio_finish(void *context);

public:
	virtual ~IOService() { }
	friend class Communicator;
};

#endif

