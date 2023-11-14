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
#ifdef __linux__
# include <sys/epoll.h>
# include <sys/timerfd.h>
#else
# include <sys/event.h>
# undef LIST_HEAD
# undef SLIST_HEAD
#endif
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include "list.h"
#include "rbtree.h"
#include "poller.h"

#define POLLER_BUFSIZE			(256 * 1024)
#define POLLER_EVENTS_MAX		256

struct __poller_node
{
	int state;
	int error;
	struct poller_data data;
#pragma pack(1)
	union
	{
		struct list_head list;
		struct rb_node rb;
	};
#pragma pack()
	char in_rbtree;
	char removed;
	int event;
	struct timespec timeout;
	struct __poller_node *res;
};

struct __poller
{
	size_t max_open_files;
	void (*callback)(struct poller_result *, void *);
	void *context;

	pthread_t tid;
	int pfd;
	int timerfd;
	int pipe_rd;
	int pipe_wr;
	int stopped;
	struct rb_root timeo_tree;
	struct rb_node *tree_first;
	struct rb_node *tree_last;
	struct list_head timeo_list;
	struct list_head no_timeo_list;
	struct __poller_node **nodes;
	pthread_mutex_t mutex;
	char buf[POLLER_BUFSIZE];
};

#ifdef __linux__

static inline int __poller_create_pfd()
{
	return epoll_create(1);
}

static inline int __poller_add_fd(int fd, int event, void *data,
								  poller_t *poller)
{
	struct epoll_event ev = {
		.events		=	event,
		.data		=	{
			.ptr	=	data
		}
	};
	return epoll_ctl(poller->pfd, EPOLL_CTL_ADD, fd, &ev);
}

static inline int __poller_del_fd(int fd, int event, poller_t *poller)
{
	return epoll_ctl(poller->pfd, EPOLL_CTL_DEL, fd, NULL);
}

static inline int __poller_mod_fd(int fd, int old_event,
								  int new_event, void *data,
								  poller_t *poller)
{
	struct epoll_event ev = {
		.events		=	new_event,
		.data		=	{
			.ptr	=	data
		}
	};
	return epoll_ctl(poller->pfd, EPOLL_CTL_MOD, fd, &ev);
}

static inline int __poller_create_timerfd()
{
	return timerfd_create(CLOCK_MONOTONIC, 0);
}

static inline int __poller_close_timerfd(int fd)
{
	return close(fd);
}

static inline int __poller_add_timerfd(int fd, poller_t *poller)
{
	struct epoll_event ev = {
		.events		=	EPOLLIN | EPOLLET,
		.data		=	{
			.ptr	=	NULL
		}
	};
	return epoll_ctl(poller->pfd, EPOLL_CTL_ADD, fd, &ev);
}

static inline int __poller_set_timerfd(int fd, const struct timespec *abstime,
									   poller_t *poller)
{
	struct itimerspec timer = {
		.it_interval	=	{ },
		.it_value		=	*abstime
	};
	return timerfd_settime(fd, TFD_TIMER_ABSTIME, &timer, NULL);
}

typedef struct epoll_event __poller_event_t;

static inline int __poller_wait(__poller_event_t *events, int maxevents,
								poller_t *poller)
{
	return epoll_wait(poller->pfd, events, maxevents, -1);
}

static inline void *__poller_event_data(const __poller_event_t *event)
{
	return event->data.ptr;
}

#else /* BSD, macOS */

static inline int __poller_create_pfd()
{
	return kqueue();
}

static inline int __poller_add_fd(int fd, int event, void *data,
								  poller_t *poller)
{
	struct kevent ev;
	EV_SET(&ev, fd, event, EV_ADD, 0, 0, data);
	return kevent(poller->pfd, &ev, 1, NULL, 0, NULL);
}

static inline int __poller_del_fd(int fd, int event, poller_t *poller)
{
	struct kevent ev;
	EV_SET(&ev, fd, event, EV_DELETE, 0, 0, NULL);
	return kevent(poller->pfd, &ev, 1, NULL, 0, NULL);
}

static inline int __poller_mod_fd(int fd, int old_event,
								  int new_event, void *data,
								  poller_t *poller)
{
	struct kevent ev[2];
	EV_SET(&ev[0], fd, old_event, EV_DELETE, 0, 0, NULL);
	EV_SET(&ev[1], fd, new_event, EV_ADD, 0, 0, data);
	return kevent(poller->pfd, ev, 2, NULL, 0, NULL);
}

static inline int __poller_create_timerfd()
{
	return 0;
}

static inline int __poller_close_timerfd(int fd)
{
	return 0;
}

static inline int __poller_add_timerfd(int fd, poller_t *poller)
{
	return 0;
}

static int __poller_set_timerfd(int fd, const struct timespec *abstime,
								poller_t *poller)
{
	struct timespec curtime;
	long long nseconds;
	struct kevent ev;
	int flags;

	if (abstime->tv_sec || abstime->tv_nsec)
	{
		clock_gettime(CLOCK_MONOTONIC, &curtime);
		nseconds = 1000000000LL * (abstime->tv_sec - curtime.tv_sec);
		nseconds += abstime->tv_nsec - curtime.tv_nsec;
		flags = EV_ADD;
	}
	else
	{
		nseconds = 0;
		flags = EV_DELETE;
	}

	EV_SET(&ev, fd, EVFILT_TIMER, flags, NOTE_NSECONDS, nseconds, NULL);
	return kevent(poller->pfd, &ev, 1, NULL, 0, NULL);
}

typedef struct kevent __poller_event_t;

static inline int __poller_wait(__poller_event_t *events, int maxevents,
								poller_t *poller)
{
	return kevent(poller->pfd, NULL, 0, events, maxevents, NULL);
}

static inline void *__poller_event_data(const __poller_event_t *event)
{
	return event->udata;
}

#define EPOLLIN		EVFILT_READ
#define EPOLLOUT	EVFILT_WRITE
#define EPOLLET		0

#endif

static inline long __timeout_cmp(const struct __poller_node *node1,
								 const struct __poller_node *node2)
{
	long ret = node1->timeout.tv_sec - node2->timeout.tv_sec;

	if (ret == 0)
		ret = node1->timeout.tv_nsec - node2->timeout.tv_nsec;

	return ret;
}

static void __poller_tree_insert(struct __poller_node *node, poller_t *poller)
{
	struct rb_node **p = &poller->timeo_tree.rb_node;
	struct rb_node *parent = NULL;
	struct __poller_node *entry;

	entry = rb_entry(poller->tree_last, struct __poller_node, rb);
	if (!*p)
	{
		poller->tree_first = &node->rb;
		poller->tree_last = &node->rb;
	}
	else if (__timeout_cmp(node, entry) >= 0)
	{
		parent = poller->tree_last;
		p = &parent->rb_right;
		poller->tree_last = &node->rb;
	}
	else
	{
		do
		{
			parent = *p;
			entry = rb_entry(*p, struct __poller_node, rb);
			if (__timeout_cmp(node, entry) < 0)
				p = &(*p)->rb_left;
			else
				p = &(*p)->rb_right;
		} while (*p);

		if (p == &poller->tree_first->rb_left)
			poller->tree_first = &node->rb;
	}

	node->in_rbtree = 1;
	rb_link_node(&node->rb, parent, p);
	rb_insert_color(&node->rb, &poller->timeo_tree);
}

static inline void __poller_tree_erase(struct __poller_node *node,
									   poller_t *poller)
{
	if (&node->rb == poller->tree_first)
		poller->tree_first = rb_next(&node->rb);

	if (&node->rb == poller->tree_last)
		poller->tree_last = rb_prev(&node->rb);

	rb_erase(&node->rb, &poller->timeo_tree);
	node->in_rbtree = 0;
}

static int __poller_remove_node(struct __poller_node *node, poller_t *poller)
{
	int removed;

	pthread_mutex_lock(&poller->mutex);
	removed = node->removed;
	if (!removed)
	{
		poller->nodes[node->data.fd] = NULL;

		if (node->in_rbtree)
			__poller_tree_erase(node, poller);
		else
			list_del(&node->list);

		__poller_del_fd(node->data.fd, node->event, poller);
	}

	pthread_mutex_unlock(&poller->mutex);
	return removed;
}

static int __poller_append_message(const void *buf, size_t *n,
								   struct __poller_node *node,
								   poller_t *poller)
{
	poller_message_t *msg = node->data.message;
	struct __poller_node *res;
	int ret;

	if (!msg)
	{
		res = (struct __poller_node *)malloc(sizeof (struct __poller_node));
		if (!res)
			return -1;

		msg = node->data.create_message(node->data.context);
		if (!msg)
		{
			free(res);
			return -1;
		}

		node->data.message = msg;
		node->res = res;
	}
	else
		res = node->res;

	ret = msg->append(buf, n, msg);
	if (ret > 0)
	{
		res->data = node->data;
		res->error = 0;
		res->state = PR_ST_SUCCESS;
		poller->callback((struct poller_result *)res, poller->context);

		node->data.message = NULL;
		node->res = NULL;
	}

	return ret;
}

static int __poller_handle_ssl_error(struct __poller_node *node, int ret,
									 poller_t *poller)
{
	int error = SSL_get_error(node->data.ssl, ret);
	int event;

	switch (error)
	{
	case SSL_ERROR_WANT_READ:
		event = EPOLLIN | EPOLLET;
		break;
	case SSL_ERROR_WANT_WRITE:
		event = EPOLLOUT | EPOLLET;
		break;
	default:
		errno = -error;
	case SSL_ERROR_SYSCALL:
		return -1;
	}

	if (event == node->event)
		return 0;

	pthread_mutex_lock(&poller->mutex);
	if (!node->removed)
	{
		ret = __poller_mod_fd(node->data.fd, node->event, event, node, poller);
		if (ret >= 0)
			node->event = event;
	}
	else
		ret = 0;

	pthread_mutex_unlock(&poller->mutex);
	return ret;
}

static void __poller_handle_read(struct __poller_node *node,
								 poller_t *poller)
{
	ssize_t nleft;
	size_t n;
	char *p;

	while (1)
	{
		p = poller->buf;
		if (!node->data.ssl)
		{
			nleft = read(node->data.fd, p, POLLER_BUFSIZE);
			if (nleft < 0)
			{
				if (errno == EAGAIN)
					return;
			}
		}
		else
		{
			nleft = SSL_read(node->data.ssl, p, POLLER_BUFSIZE);
			if (nleft < 0)
			{
				if (__poller_handle_ssl_error(node, nleft, poller) >= 0)
					return;
			}
		}

		if (nleft <= 0)
			break;

		do
		{
			n = nleft;
			if (__poller_append_message(p, &n, node, poller) >= 0)
			{
				nleft -= n;
				p += n;
			}
			else
				nleft = -1;
		} while (nleft > 0);

		if (nleft < 0)
			break;
	}

	if (__poller_remove_node(node, poller))
		return;

	if (nleft == 0)
	{
		node->error = 0;
		node->state = PR_ST_FINISHED;
	}
	else
	{
		node->error = errno;
		node->state = PR_ST_ERROR;
	}

	free(node->res);
	poller->callback((struct poller_result *)node, poller->context);
}

#ifndef IOV_MAX
# ifdef UIO_MAXIOV
#  define IOV_MAX	UIO_MAXIOV
# else
#  define IOV_MAX	1024
# endif
#endif

static void __poller_handle_write(struct __poller_node *node,
								  poller_t *poller)
{
	struct iovec *iov = node->data.write_iov;
	size_t count = 0;
	ssize_t nleft;
	int iovcnt;
	int ret;

	while (node->data.iovcnt > 0)
	{
		if (!node->data.ssl)
		{
			iovcnt = node->data.iovcnt;
			if (iovcnt > IOV_MAX)
				iovcnt = IOV_MAX;

			nleft = writev(node->data.fd, iov, iovcnt);
			if (nleft < 0)
			{
				ret = errno == EAGAIN ? 0 : -1;
				break;
			}
		}
		else if (iov->iov_len > 0)
		{
			nleft = SSL_write(node->data.ssl, iov->iov_base, iov->iov_len);
			if (nleft <= 0)
			{
				ret = __poller_handle_ssl_error(node, nleft, poller);
				break;
			}
		}
		else
			nleft = 0;

		count += nleft;
		do
		{
			if (nleft >= iov->iov_len)
			{
				nleft -= iov->iov_len;
				iov->iov_base = (char *)iov->iov_base + iov->iov_len;
				iov->iov_len = 0;
				iov++;
				node->data.iovcnt--;
			}
			else
			{
				iov->iov_base = (char *)iov->iov_base + nleft;
				iov->iov_len -= nleft;
				break;
			}
		} while (node->data.iovcnt > 0);
	}

	node->data.write_iov = iov;
	if (node->data.iovcnt > 0 && ret >= 0)
	{
		if (count == 0)
			return;

		if (node->data.partial_written(count, node->data.context) >= 0)
			return;
	}

	if (__poller_remove_node(node, poller))
		return;

	if (node->data.iovcnt == 0)
	{
		node->error = 0;
		node->state = PR_ST_FINISHED;
	}
	else
	{
		node->error = errno;
		node->state = PR_ST_ERROR;
	}

	poller->callback((struct poller_result *)node, poller->context);
}

static void __poller_handle_listen(struct __poller_node *node,
								   poller_t *poller)
{
	struct __poller_node *res = node->res;
	struct sockaddr_storage ss;
	struct sockaddr *addr = (struct sockaddr *)&ss;
	socklen_t addrlen;
	void *result;
	int sockfd;

	while (1)
	{
		addrlen = sizeof (struct sockaddr_storage);
		sockfd = accept(node->data.fd, addr, &addrlen);
		if (sockfd < 0)
		{
			if (errno == EAGAIN || errno == EMFILE || errno == ENFILE)
				return;
			else if (errno == ECONNABORTED)
				continue;
			else
				break;
		}

		result = node->data.accept(addr, addrlen, sockfd, node->data.context);
		if (!result)
			break;

		res->data = node->data;
		res->data.result = result;
		res->error = 0;
		res->state = PR_ST_SUCCESS;
		poller->callback((struct poller_result *)res, poller->context);

		res = (struct __poller_node *)malloc(sizeof (struct __poller_node));
		node->res = res;
		if (!res)
			break;
	}

	if (__poller_remove_node(node, poller))
		return;

	node->error = errno;
	node->state = PR_ST_ERROR;
	free(node->res);
	poller->callback((struct poller_result *)node, poller->context);
}

static void __poller_handle_connect(struct __poller_node *node,
									poller_t *poller)
{
	socklen_t len = sizeof (int);
	int error;

	if (getsockopt(node->data.fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
		error = errno;

	if (__poller_remove_node(node, poller))
		return;

	if (error == 0)
	{
		node->error = 0;
		node->state = PR_ST_FINISHED;
	}
	else
	{
		node->error = error;
		node->state = PR_ST_ERROR;
	}

	poller->callback((struct poller_result *)node, poller->context);
}

static void __poller_handle_ssl_accept(struct __poller_node *node,
									   poller_t *poller)
{
	int ret = SSL_accept(node->data.ssl);

	if (ret <= 0)
	{
		if (__poller_handle_ssl_error(node, ret, poller) >= 0)
			return;
	}

	if (__poller_remove_node(node, poller))
		return;

	if (ret > 0)
	{
		node->error = 0;
		node->state = PR_ST_FINISHED;
	}
	else
	{
		node->error = errno;
		node->state = PR_ST_ERROR;
	}

	poller->callback((struct poller_result *)node, poller->context);
}

static void __poller_handle_ssl_connect(struct __poller_node *node,
										poller_t *poller)
{
	int ret = SSL_connect(node->data.ssl);

	if (ret <= 0)
	{
		if (__poller_handle_ssl_error(node, ret, poller) >= 0)
			return;
	}

	if (__poller_remove_node(node, poller))
		return;

	if (ret > 0)
	{
		node->error = 0;
		node->state = PR_ST_FINISHED;
	}
	else
	{
		node->error = errno;
		node->state = PR_ST_ERROR;
	}

	poller->callback((struct poller_result *)node, poller->context);
}

static void __poller_handle_ssl_shutdown(struct __poller_node *node,
										 poller_t *poller)
{
	int ret = SSL_shutdown(node->data.ssl);

	if (ret <= 0)
	{
		if (__poller_handle_ssl_error(node, ret, poller) >= 0)
			return;
	}

	if (__poller_remove_node(node, poller))
		return;

	if (ret > 0)
	{
		node->error = 0;
		node->state = PR_ST_FINISHED;
	}
	else
	{
		node->error = errno;
		node->state = PR_ST_ERROR;
	}

	poller->callback((struct poller_result *)node, poller->context);
}

static void __poller_handle_event(struct __poller_node *node,
								  poller_t *poller)
{
	struct __poller_node *res = node->res;
	unsigned long long cnt = 0;
	unsigned long long value;
	void *result;
	ssize_t n;

	while (1)
	{
		n = read(node->data.fd, &value, sizeof (unsigned long long));
		if (n == sizeof (unsigned long long))
			cnt += value;
		else
		{
			if (n >= 0)
				errno = EINVAL;
			break;
		}
	}

	if (errno == EAGAIN)
	{
		while (1)
		{
			if (cnt == 0)
				return;

			cnt--;
			result = node->data.event(node->data.context);
			if (!result)
				break;

			res->data = node->data;
			res->data.result = result;
			res->error = 0;
			res->state = PR_ST_SUCCESS;
			poller->callback((struct poller_result *)res, poller->context);

			res = (struct __poller_node *)malloc(sizeof (struct __poller_node));
			node->res = res;
			if (!res)
				break;
		}
	}

	if (cnt != 0)
		write(node->data.fd, &cnt, sizeof (unsigned long long));

	if (__poller_remove_node(node, poller))
		return;

	node->error = errno;
	node->state = PR_ST_ERROR;
	free(node->res);
	poller->callback((struct poller_result *)node, poller->context);
}

static void __poller_handle_notify(struct __poller_node *node,
								   poller_t *poller)
{
	struct __poller_node *res = node->res;
	void *result;
	ssize_t n;

	while (1)
	{
		n = read(node->data.fd, &result, sizeof (void *));
		if (n == sizeof (void *))
		{
			result = node->data.notify(result, node->data.context);
			if (!result)
				break;

			res->data = node->data;
			res->data.result = result;
			res->error = 0;
			res->state = PR_ST_SUCCESS;
			poller->callback((struct poller_result *)res, poller->context);

			res = (struct __poller_node *)malloc(sizeof (struct __poller_node));
			node->res = res;
			if (!res)
				break;
		}
		else if (n < 0 && errno == EAGAIN)
			return;
		else
		{
			if (n > 0)
				errno = EINVAL;
			break;
		}
	}

	if (__poller_remove_node(node, poller))
		return;

	if (n == 0)
	{
		node->error = 0;
		node->state = PR_ST_FINISHED;
	}
	else
	{
		node->error = errno;
		node->state = PR_ST_ERROR;
	}

	free(node->res);
	poller->callback((struct poller_result *)node, poller->context);
}

static void __poller_handle_recvfrom(struct __poller_node *node,
									 poller_t *poller)
{
	struct __poller_node *res = node->res;
	struct sockaddr_storage ss;
	struct sockaddr *addr = (struct sockaddr *)&ss;
	socklen_t addrlen;
	void *result;
	ssize_t n;

	while (1)
	{
		addrlen = sizeof (struct sockaddr_storage);
		n = recvfrom(node->data.fd, poller->buf, POLLER_BUFSIZE, 0,
					 addr, &addrlen);
		if (n < 0)
		{
			if (errno == EAGAIN)
				return;
			else
				break;
		}

		result = node->data.recvfrom(addr, addrlen, poller->buf, n,
									 node->data.context);
		if (!result)
			break;

		res->data = node->data;
		res->data.result = result;
		res->error = 0;
		res->state = PR_ST_SUCCESS;
		poller->callback((struct poller_result *)res, poller->context);

		res = (struct __poller_node *)malloc(sizeof (struct __poller_node));
		node->res = res;
		if (!res)
			break;
	}

	if (__poller_remove_node(node, poller))
		return;

	node->error = errno;
	node->state = PR_ST_ERROR;
	free(node->res);
	poller->callback((struct poller_result *)node, poller->context);
}

static int __poller_handle_pipe(poller_t *poller)
{
	struct __poller_node **node = (struct __poller_node **)poller->buf;
	int stop = 0;
	int n;
	int i;

	n = read(poller->pipe_rd, node, POLLER_BUFSIZE) / sizeof (void *);
	for (i = 0; i < n; i++)
	{
		if (node[i])
		{
			free(node[i]->res);
			poller->callback((struct poller_result *)node[i], poller->context);
		}
		else
			stop = 1;
	}

	return stop;
}

static void __poller_handle_timeout(const struct __poller_node *time_node,
									poller_t *poller)
{
	struct __poller_node *node;
	struct list_head *pos, *tmp;
	LIST_HEAD(timeo_list);

	pthread_mutex_lock(&poller->mutex);
	list_for_each_safe(pos, tmp, &poller->timeo_list)
	{
		node = list_entry(pos, struct __poller_node, list);
		if (__timeout_cmp(node, time_node) > 0)
			break;

		if (node->data.fd >= 0)
		{
			poller->nodes[node->data.fd] = NULL;
			__poller_del_fd(node->data.fd, node->event, poller);
		}
		else
			node->removed = 1;

		list_move_tail(pos, &timeo_list);
	}

	while (poller->tree_first)
	{
		node = rb_entry(poller->tree_first, struct __poller_node, rb);
		if (__timeout_cmp(node, time_node) > 0)
			break;

		if (node->data.fd >= 0)
		{
			poller->nodes[node->data.fd] = NULL;
			__poller_del_fd(node->data.fd, node->event, poller);
		}
		else
			node->removed = 1;

		poller->tree_first = rb_next(poller->tree_first);
		rb_erase(&node->rb, &poller->timeo_tree);
		list_add_tail(&node->list, &timeo_list);
		if (!poller->tree_first)
			poller->tree_last = NULL;
	}

	pthread_mutex_unlock(&poller->mutex);
	list_for_each_safe(pos, tmp, &timeo_list)
	{
		node = list_entry(pos, struct __poller_node, list);
		if (node->data.fd >= 0)
		{
			node->error = ETIMEDOUT;
			node->state = PR_ST_ERROR;
		}
		else
		{
			node->error = 0;
			node->state = PR_ST_FINISHED;
		}

		free(node->res);
		poller->callback((struct poller_result *)node, poller->context);
	}
}

static void __poller_set_timer(poller_t *poller)
{
	struct __poller_node *node = NULL;
	struct __poller_node *first;
	struct timespec abstime;

	pthread_mutex_lock(&poller->mutex);
	if (!list_empty(&poller->timeo_list))
		node = list_entry(poller->timeo_list.next, struct __poller_node, list);

	if (poller->tree_first)
	{
		first = rb_entry(poller->tree_first, struct __poller_node, rb);
		if (!node || __timeout_cmp(first, node) < 0)
			node = first;
	}

	if (node)
		abstime = node->timeout;
	else
	{
		abstime.tv_sec = 0;
		abstime.tv_nsec = 0;
	}

	__poller_set_timerfd(poller->timerfd, &abstime, poller);
	pthread_mutex_unlock(&poller->mutex);
}

static void *__poller_thread_routine(void *arg)
{
	poller_t *poller = (poller_t *)arg;
	__poller_event_t events[POLLER_EVENTS_MAX];
	struct __poller_node time_node;
	struct __poller_node *node;
	int has_pipe_event;
	int nevents;
	int i;

	while (1)
	{
		__poller_set_timer(poller);
		nevents = __poller_wait(events, POLLER_EVENTS_MAX, poller);
		clock_gettime(CLOCK_MONOTONIC, &time_node.timeout);
		has_pipe_event = 0;
		for (i = 0; i < nevents; i++)
		{
			node = (struct __poller_node *)__poller_event_data(&events[i]);
			if (node <= (struct __poller_node *)1)
			{
				if (node == (struct __poller_node *)1)
					has_pipe_event = 1;
				continue;
			}

			switch (node->data.operation)
			{
			case PD_OP_READ:
				__poller_handle_read(node, poller);
				break;
			case PD_OP_WRITE:
				__poller_handle_write(node, poller);
				break;
			case PD_OP_LISTEN:
				__poller_handle_listen(node, poller);
				break;
			case PD_OP_CONNECT:
				__poller_handle_connect(node, poller);
				break;
			case PD_OP_SSL_ACCEPT:
				__poller_handle_ssl_accept(node, poller);
				break;
			case PD_OP_SSL_CONNECT:
				__poller_handle_ssl_connect(node, poller);
				break;
			case PD_OP_SSL_SHUTDOWN:
				__poller_handle_ssl_shutdown(node, poller);
				break;
			case PD_OP_EVENT:
				__poller_handle_event(node, poller);
				break;
			case PD_OP_NOTIFY:
				__poller_handle_notify(node, poller);
				break;
			case PD_OP_RECVFROM:
				__poller_handle_recvfrom(node, poller);
				break;
			}
		}

		if (has_pipe_event)
		{
			if (__poller_handle_pipe(poller))
				break;
		}

		__poller_handle_timeout(&time_node, poller);
	}

	return NULL;
}

static int __poller_open_pipe(poller_t *poller)
{
	int pipefd[2];

	if (pipe(pipefd) >= 0)
	{
		if (__poller_add_fd(pipefd[0], EPOLLIN, (void *)1, poller) >= 0)
		{
			poller->pipe_rd = pipefd[0];
			poller->pipe_wr = pipefd[1];
			return 0;
		}

		close(pipefd[0]);
		close(pipefd[1]);
	}

	return -1;
}

static int __poller_create_timer(poller_t *poller)
{
	int timerfd = __poller_create_timerfd();

	if (timerfd >= 0)
	{
		if (__poller_add_timerfd(timerfd, poller) >= 0)
		{
			poller->timerfd = timerfd;
			return 0;
		}

		__poller_close_timerfd(timerfd);
	}

	return -1;
}

poller_t *__poller_create(void **nodes_buf, const struct poller_params *params)
{
	poller_t *poller = (poller_t *)malloc(sizeof (poller_t));
	int ret;

	if (!poller)
		return NULL;

	poller->pfd = __poller_create_pfd();
	if (poller->pfd >= 0)
	{
		if (__poller_create_timer(poller) >= 0)
		{
			ret = pthread_mutex_init(&poller->mutex, NULL);
			if (ret == 0)
			{
				poller->nodes = (struct __poller_node **)nodes_buf;
				poller->max_open_files = params->max_open_files;
				poller->callback = params->callback;
				poller->context = params->context;

				poller->timeo_tree.rb_node = NULL;
				poller->tree_first = NULL;
				poller->tree_last = NULL;
				INIT_LIST_HEAD(&poller->timeo_list);
				INIT_LIST_HEAD(&poller->no_timeo_list);

				poller->stopped = 1;
				return poller;
			}

			errno = ret;
			close(poller->timerfd);
		}

		close(poller->pfd);
	}

	free(poller);
	return NULL;
}

poller_t *poller_create(const struct poller_params *params)
{
	void **nodes_buf = (void **)calloc(params->max_open_files, sizeof (void *));
	poller_t *poller;

	if (nodes_buf)
	{
		poller = __poller_create(nodes_buf, params);
		if (poller)
			return poller;

		free(nodes_buf);
	}

	return NULL;
}

void __poller_destroy(poller_t *poller)
{
	pthread_mutex_destroy(&poller->mutex);
	__poller_close_timerfd(poller->timerfd);
	close(poller->pfd);
	free(poller);
}

void poller_destroy(poller_t *poller)
{
	free(poller->nodes);
	__poller_destroy(poller);
}

int poller_start(poller_t *poller)
{
	pthread_t tid;
	int ret;

	pthread_mutex_lock(&poller->mutex);
	if (__poller_open_pipe(poller) >= 0)
	{
		ret = pthread_create(&tid, NULL, __poller_thread_routine, poller);
		if (ret == 0)
		{
			poller->tid = tid;
			poller->stopped = 0;
		}
		else
		{
			errno = ret;
			close(poller->pipe_wr);
			close(poller->pipe_rd);
		}
	}

	pthread_mutex_unlock(&poller->mutex);
	return -poller->stopped;
}

static void __poller_insert_node(struct __poller_node *node,
								 poller_t *poller)
{
	struct __poller_node *end;

	end = list_entry(poller->timeo_list.prev, struct __poller_node, list);
	if (list_empty(&poller->timeo_list))
	{
		list_add(&node->list, &poller->timeo_list);
		end = rb_entry(poller->tree_first, struct __poller_node, rb);
	}
	else if (__timeout_cmp(node, end) >= 0)
	{
		list_add_tail(&node->list, &poller->timeo_list);
		return;
	}
	else
	{
		__poller_tree_insert(node, poller);
		if (&node->rb != poller->tree_first)
			return;

		end = list_entry(poller->timeo_list.next, struct __poller_node, list);
	}

	if (!poller->tree_first || __timeout_cmp(node, end) < 0)
		__poller_set_timerfd(poller->timerfd, &node->timeout, poller);
}

static void __poller_node_set_timeout(int timeout, struct __poller_node *node)
{
	clock_gettime(CLOCK_MONOTONIC, &node->timeout);
	node->timeout.tv_sec += timeout / 1000;
	node->timeout.tv_nsec += timeout % 1000 * 1000000;
	if (node->timeout.tv_nsec >= 1000000000)
	{
		node->timeout.tv_nsec -= 1000000000;
		node->timeout.tv_sec++;
	}
}

static int __poller_data_get_event(int *event, const struct poller_data *data)
{
	switch (data->operation)
	{
	case PD_OP_READ:
		*event = EPOLLIN | EPOLLET;
		return !!data->message;
	case PD_OP_WRITE:
		*event = EPOLLOUT | EPOLLET;
		return 0;
	case PD_OP_LISTEN:
		*event = EPOLLIN;
		return 1;
	case PD_OP_CONNECT:
		*event = EPOLLOUT | EPOLLET;
		return 0;
	case PD_OP_SSL_ACCEPT:
		*event = EPOLLIN | EPOLLET;
		return 0;
	case PD_OP_SSL_CONNECT:
		*event = EPOLLOUT | EPOLLET;
		return 0;
	case PD_OP_SSL_SHUTDOWN:
		*event = EPOLLOUT | EPOLLET;
		return 0;
	case PD_OP_EVENT:
		*event = EPOLLIN | EPOLLET;
		return 1;
	case PD_OP_NOTIFY:
		*event = EPOLLIN | EPOLLET;
		return 1;
	case PD_OP_RECVFROM:
		*event = EPOLLIN | EPOLLET;
		return 1;
	default:
		errno = EINVAL;
		return -1;
	}
}

static struct __poller_node *__poller_new_node(const struct poller_data *data,
											   int timeout, poller_t *poller)
{
	struct __poller_node *res = NULL;
	struct __poller_node *node;
	int need_res;
	int event;

	if ((size_t)data->fd >= poller->max_open_files)
	{
		errno = data->fd < 0 ? EBADF : EMFILE;
		return NULL;
	}

	need_res = __poller_data_get_event(&event, data);
	if (need_res < 0)
		return NULL;

	if (need_res)
	{
		res = (struct __poller_node *)malloc(sizeof (struct __poller_node));
		if (!res)
			return NULL;
	}

	node = (struct __poller_node *)malloc(sizeof (struct __poller_node));
	if (node)
	{
		node->data = *data;
		node->event = event;
		node->in_rbtree = 0;
		node->removed = 0;
		node->res = res;
		if (timeout >= 0)
			__poller_node_set_timeout(timeout, node);
	}

	return node;
}

int poller_add(const struct poller_data *data, int timeout, poller_t *poller)
{
	struct __poller_node *node;

	node = __poller_new_node(data, timeout, poller);
	if (!node)
		return -1;

	pthread_mutex_lock(&poller->mutex);
	if (!poller->nodes[data->fd])
	{
		if (__poller_add_fd(data->fd, node->event, node, poller) >= 0)
		{
			if (timeout >= 0)
				__poller_insert_node(node, poller);
			else
				list_add_tail(&node->list, &poller->no_timeo_list);

			poller->nodes[data->fd] = node;
			node = NULL;
		}
	}
	else
		errno = EEXIST;

	pthread_mutex_unlock(&poller->mutex);
	if (node == NULL)
		return 0;

	free(node->res);
	free(node);
	return -1;
}

int poller_del(int fd, poller_t *poller)
{
	struct __poller_node *node;
	int stopped = 0;

	if ((size_t)fd >= poller->max_open_files)
	{
		errno = fd < 0 ? EBADF : EMFILE;
		return -1;
	}

	pthread_mutex_lock(&poller->mutex);
	node = poller->nodes[fd];
	if (node)
	{
		poller->nodes[fd] = NULL;

		if (node->in_rbtree)
			__poller_tree_erase(node, poller);
		else
			list_del(&node->list);

		__poller_del_fd(fd, node->event, poller);

		node->error = 0;
		node->state = PR_ST_DELETED;
		stopped = poller->stopped;
		if (!stopped)
		{
			node->removed = 1;
			write(poller->pipe_wr, &node, sizeof (void *));
		}
	}
	else
		errno = ENOENT;

	pthread_mutex_unlock(&poller->mutex);
	if (stopped)
	{
		free(node->res);
		poller->callback((struct poller_result *)node, poller->context);
	}

	return -!node;
}

int poller_mod(const struct poller_data *data, int timeout, poller_t *poller)
{
	struct __poller_node *node;
	struct __poller_node *orig;
	int stopped = 0;

	node = __poller_new_node(data, timeout, poller);
	if (!node)
		return -1;

	pthread_mutex_lock(&poller->mutex);
	orig = poller->nodes[data->fd];
	if (orig)
	{
		if (__poller_mod_fd(data->fd, orig->event, node->event, node, poller) >= 0)
		{
			if (orig->in_rbtree)
				__poller_tree_erase(orig, poller);
			else
				list_del(&orig->list);

			orig->error = 0;
			orig->state = PR_ST_MODIFIED;
			stopped = poller->stopped;
			if (!stopped)
			{
				orig->removed = 1;
				write(poller->pipe_wr, &orig, sizeof (void *));
			}

			if (timeout >= 0)
				__poller_insert_node(node, poller);
			else
				list_add_tail(&node->list, &poller->no_timeo_list);

			poller->nodes[data->fd] = node;
			node = NULL;
		}
	}
	else
		errno = ENOENT;

	pthread_mutex_unlock(&poller->mutex);
	if (stopped)
	{
		free(orig->res);
		poller->callback((struct poller_result *)orig, poller->context);
	}

	if (node == NULL)
		return 0;

	free(node->res);
	free(node);
	return -1;
}

int poller_set_timeout(int fd, int timeout, poller_t *poller)
{
	struct __poller_node time_node;
	struct __poller_node *node;

	if ((size_t)fd >= poller->max_open_files)
	{
		errno = fd < 0 ? EBADF : EMFILE;
		return -1;
	}

	if (timeout >= 0)
		__poller_node_set_timeout(timeout, &time_node);

	pthread_mutex_lock(&poller->mutex);
	node = poller->nodes[fd];
	if (node)
	{
		if (node->in_rbtree)
			__poller_tree_erase(node, poller);
		else
			list_del(&node->list);

		if (timeout >= 0)
		{
			node->timeout = time_node.timeout;
			__poller_insert_node(node, poller);
		}
		else
			list_add_tail(&node->list, &poller->no_timeo_list);
	}
	else
		errno = ENOENT;

	pthread_mutex_unlock(&poller->mutex);
	return -!node;
}

int poller_add_timer(const struct timespec *value, void *context, void **timer,
					 poller_t *poller)
{
	struct __poller_node *node;

	node = (struct __poller_node *)malloc(sizeof (struct __poller_node));
	if (node)
	{
		memset(&node->data, 0, sizeof (struct poller_data));
		node->data.operation = PD_OP_TIMER;
		node->data.fd = -1;
		node->data.context = context;
		node->in_rbtree = 0;
		node->removed = 0;
		node->res = NULL;

		clock_gettime(CLOCK_MONOTONIC, &node->timeout);
		node->timeout.tv_sec += value->tv_sec;
		node->timeout.tv_nsec += value->tv_nsec;
		if (node->timeout.tv_nsec >= 1000000000)
		{
			node->timeout.tv_nsec -= 1000000000;
			node->timeout.tv_sec++;
		}

		*timer = node;
		pthread_mutex_lock(&poller->mutex);
		__poller_insert_node(node, poller);
		pthread_mutex_unlock(&poller->mutex);
		return 0;
	}

	return -1;
}

int poller_del_timer(void *timer, poller_t *poller)
{
	struct __poller_node *node = (struct __poller_node *)timer;

	pthread_mutex_lock(&poller->mutex);
	if (!node->removed)
	{
		node->removed = 1;

		if (node->in_rbtree)
			__poller_tree_erase(node, poller);
		else
			list_del(&node->list);
	}
	else
	{
		errno = ENOENT;
		node = NULL;
	}

	pthread_mutex_unlock(&poller->mutex);
	if (node)
	{
		node->error = 0;
		node->state = PR_ST_DELETED;
		poller->callback((struct poller_result *)node, poller->context);
		return 0;
	}

	return -1;
}

void poller_stop(poller_t *poller)
{
	struct __poller_node *node;
	struct list_head *pos, *tmp;
	LIST_HEAD(node_list);
	void *p = NULL;

	write(poller->pipe_wr, &p, sizeof (void *));
	pthread_join(poller->tid, NULL);
	poller->stopped = 1;

	pthread_mutex_lock(&poller->mutex);
	close(poller->pipe_wr);
	__poller_handle_pipe(poller);
	close(poller->pipe_rd);

	poller->tree_first = NULL;
	poller->tree_last = NULL;
	while (poller->timeo_tree.rb_node)
	{
		node = rb_entry(poller->timeo_tree.rb_node, struct __poller_node, rb);
		rb_erase(&node->rb, &poller->timeo_tree);
		list_add(&node->list, &node_list);
	}

	list_splice_init(&poller->timeo_list, &node_list);
	list_splice_init(&poller->no_timeo_list, &node_list);
	list_for_each(pos, &node_list)
	{
		node = list_entry(pos, struct __poller_node, list);
		if (node->data.fd >= 0)
		{
			poller->nodes[node->data.fd] = NULL;
			__poller_del_fd(node->data.fd, node->event, poller);
		}
		else
			node->removed = 1;
	}

	pthread_mutex_unlock(&poller->mutex);
	list_for_each_safe(pos, tmp, &node_list)
	{
		node = list_entry(pos, struct __poller_node, list);
		node->error = 0;
		node->state = PR_ST_STOPPED;
		free(node->res);
		poller->callback((struct poller_result *)node, poller->context);
	}
}

