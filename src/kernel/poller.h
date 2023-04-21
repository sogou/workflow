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

#ifndef _POLLER_H_
#define _POLLER_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <openssl/ssl.h>

typedef struct __poller poller_t;
typedef struct __poller_message poller_message_t;

struct __poller_message
{
	int (*append)(const void *, size_t *, poller_message_t *);
	char data[0];
};

struct poller_data
{
#define PD_OP_TIMER			0
#define PD_OP_READ			1
#define PD_OP_WRITE			2
#define PD_OP_LISTEN		3
#define PD_OP_CONNECT		4
#define PD_OP_SSL_READ		PD_OP_READ
#define PD_OP_SSL_WRITE		PD_OP_WRITE
#define PD_OP_SSL_ACCEPT	5
#define PD_OP_SSL_CONNECT	6
#define PD_OP_SSL_SHUTDOWN	7
#define PD_OP_EVENT			8
#define PD_OP_NOTIFY		9
#define PD_OP_RECVFROM		10
	short operation;
	unsigned short iovcnt;
	int fd;
	SSL *ssl;
	union
	{
		poller_message_t *(*create_message)(void *);
		int (*partial_written)(size_t, void *);
		void *(*accept)(const struct sockaddr *, socklen_t, int, void *);
		void *(*event)(void *);
		void *(*notify)(void *, void *);
		void *(*recvfrom)(const struct sockaddr *, socklen_t,
						  const void *, size_t, void *);
	};
	void *context;
	union
	{
		poller_message_t *message;
		struct iovec *write_iov;
		void *result;
	};
};

struct poller_result
{
#define PR_ST_SUCCESS		0
#define PR_ST_FINISHED		1
#define PR_ST_ERROR			2
#define PR_ST_DELETED		3
#define PR_ST_MODIFIED		4
#define PR_ST_STOPPED		5
	int state;
	int error;
	struct poller_data data;
	/* In callback, spaces of six pointers are available from here. */
};

struct poller_params
{
	size_t max_open_files;
	void (*callback)(struct poller_result *, void *);
	void *context;
};

#ifdef __cplusplus
extern "C"
{
#endif

poller_t *poller_create(const struct poller_params *params);
int poller_start(poller_t *poller);
int poller_add(const struct poller_data *data, int timeout, poller_t *poller);
int poller_del(int fd, poller_t *poller);
int poller_mod(const struct poller_data *data, int timeout, poller_t *poller);
int poller_set_timeout(int fd, int timeout, poller_t *poller);
int poller_add_timer(const struct timespec *value, void *context,
					 poller_t *poller);
void poller_stop(poller_t *poller);
void poller_destroy(poller_t *poller);

#ifdef __cplusplus
}
#endif

#endif

