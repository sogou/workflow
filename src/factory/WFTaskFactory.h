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

#ifndef _WFTASKFACTORY_H_
#define _WFTASKFACTORY_H_

#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <utility>
#include <functional>
#include "URIParser.h"
#include "RedisMessage.h"
#include "HttpMessage.h"
#include "MySQLMessage.h"
#include "DnsMessage.h"
#include "Workflow.h"
#include "WFTask.h"
#include "WFGraphTask.h"
#include "EndpointParams.h"

// Network Client/Server tasks

using WFHttpTask = WFNetworkTask<protocol::HttpRequest,
								 protocol::HttpResponse>;
using http_callback_t = std::function<void (WFHttpTask *)>;

using WFRedisTask = WFNetworkTask<protocol::RedisRequest,
								  protocol::RedisResponse>;
using redis_callback_t = std::function<void (WFRedisTask *)>;

using WFMySQLTask = WFNetworkTask<protocol::MySQLRequest,
								  protocol::MySQLResponse>;
using mysql_callback_t = std::function<void (WFMySQLTask *)>;

using WFDnsTask = WFNetworkTask<protocol::DnsRequest,
								protocol::DnsResponse>;
using dns_callback_t = std::function<void (WFDnsTask *)>;

// File IO tasks

struct FileIOArgs
{
	int fd;
	void *buf;
	size_t count;
	off_t offset;
};

struct FileVIOArgs
{
	int fd;
	const struct iovec *iov;
	int iovcnt;
	off_t offset;
};

struct FileSyncArgs
{
	int fd;
};

using WFFileIOTask = WFFileTask<struct FileIOArgs>;
using fio_callback_t = std::function<void (WFFileIOTask *)>;

using WFFileVIOTask = WFFileTask<struct FileVIOArgs>;
using fvio_callback_t = std::function<void (WFFileVIOTask *)>;

using WFFileSyncTask = WFFileTask<struct FileSyncArgs>;
using fsync_callback_t = std::function<void (WFFileSyncTask *)>;

// Timer and counter
using timer_callback_t = std::function<void (WFTimerTask *)>;
using counter_callback_t = std::function<void (WFCounterTask *)>;

// Mailbox is like counter with data passing
using mailbox_callback_t = std::function<void (WFMailboxTask *)>;

// Graph (DAG) task.
using graph_callback_t = std::function<void (WFGraphTask *)>;

using WFEmptyTask = WFGenericTask;

using WFDynamicTask = WFGenericTask;
using dynamic_create_t = std::function<SubTask *(WFDynamicTask *)>;

using repeated_create_t = std::function<SubTask *(WFRepeaterTask *)>;
using repeater_callback_t = std::function<void (WFRepeaterTask *)>;

using module_callback_t = std::function<void (const WFModuleTask *)>;

class WFTaskFactory
{
public:
	static WFHttpTask *create_http_task(const std::string& url,
										int redirect_max,
										int retry_max,
										http_callback_t callback);

	static WFHttpTask *create_http_task(const ParsedURI& uri,
										int redirect_max,
										int retry_max,
										http_callback_t callback);

	static WFHttpTask *create_http_task(const std::string& url,
										const std::string& proxy_url,
										int redirect_max,
										int retry_max,
										http_callback_t callback);

	static WFHttpTask *create_http_task(const ParsedURI& uri,
										const ParsedURI& proxy_uri,
										int redirect_max,
										int retry_max,
										http_callback_t callback);

	static WFRedisTask *create_redis_task(const std::string& url,
										  int retry_max,
										  redis_callback_t callback);

	static WFRedisTask *create_redis_task(const ParsedURI& uri,
										  int retry_max,
										  redis_callback_t callback);

	static WFMySQLTask *create_mysql_task(const std::string& url,
										  int retry_max,
										  mysql_callback_t callback);

	static WFMySQLTask *create_mysql_task(const ParsedURI& uri,
										  int retry_max,
										  mysql_callback_t callback);

	static WFDnsTask *create_dns_task(const std::string& url,
									  int retry_max,
									  dns_callback_t callback);

	static WFDnsTask *create_dns_task(const ParsedURI& uri,
									  int retry_max,
									  dns_callback_t callback);

public:
	static WFFileIOTask *create_pread_task(int fd,
										   void *buf,
										   size_t count,
										   off_t offset,
										   fio_callback_t callback);

	static WFFileIOTask *create_pwrite_task(int fd,
											const void *buf,
											size_t count,
											off_t offset,
											fio_callback_t callback);

	/* preadv and pwritev tasks are supported by Linux aio only.
	 * On macOS or others, you will get an ENOSYS error in callback. */

	static WFFileVIOTask *create_preadv_task(int fd,
											 const struct iovec *iov,
											 int iovcnt,
											 off_t offset,
											 fvio_callback_t callback);

	static WFFileVIOTask *create_pwritev_task(int fd,
											  const struct iovec *iov,
											  int iovcnt,
											  off_t offset,
											  fvio_callback_t callback);

	static WFFileSyncTask *create_fsync_task(int fd,
											 fsync_callback_t callback);

	/* On systems that do not support fdatasync(), like macOS,
	 * fdsync task is equal to fsync task. */
	static WFFileSyncTask *create_fdsync_task(int fd,
											  fsync_callback_t callback);

	/* File tasks with path name. */
public:
	static WFFileIOTask *create_pread_task(const std::string& pathname,
										   void *buf,
										   size_t count,
										   off_t offset,
										   fio_callback_t callback);

	static WFFileIOTask *create_pwrite_task(const std::string& pathname,
											const void *buf,
											size_t count,
											off_t offset,
											fio_callback_t callback);

	static WFFileVIOTask *create_preadv_task(const std::string& pathname,
											 const struct iovec *iov,
											 int iovcnt,
											 off_t offset,
											 fvio_callback_t callback);

	static WFFileVIOTask *create_pwritev_task(const std::string& pathname,
											  const struct iovec *iov,
											  int iovcnt,
											  off_t offset,
											  fvio_callback_t callback);

public:
	static WFTimerTask *create_timer_task(time_t seconds, long nanoseconds,
										  timer_callback_t callback);

	/* create a named timer. */
	static WFTimerTask *create_timer_task(const std::string& timer_name,
										  time_t seconds, long nanoseconds,
										  timer_callback_t callback);

	/* cancel all timers under the name. */
	static void cancel_by_name(const std::string& timer_name)
	{
		WFTaskFactory::cancel_by_name(timer_name, (size_t)-1);
	}

	/* cancel at most 'max' timers under the name. */
	static void cancel_by_name(const std::string& timer_name, size_t max);

	/* timer in microseconds (deprecated) */
	static WFTimerTask *create_timer_task(unsigned int microseconds,
										  timer_callback_t callback);

public:
	/* Create an unnamed counter. Call counter->count() directly.
	 * NOTE: never call count() exceeding target_value. */
	static WFCounterTask *create_counter_task(unsigned int target_value,
											  counter_callback_t callback)
	{
		return new WFCounterTask(target_value, std::move(callback));
	}

	/* Create a named counter. */
	static WFCounterTask *create_counter_task(const std::string& counter_name,
											  unsigned int target_value,
											  counter_callback_t callback);

	/* Count by a counter's name. When count_by_name(), it's safe to count
	 * exceeding target_value. When multiple counters share a same name,
	 * this operation will be performed on the first created. If no counter
	 * matches the name, nothing is performed. */
	static void count_by_name(const std::string& counter_name)
	{
		WFTaskFactory::count_by_name(counter_name, 1);
	}

	/* Count by name with a value n. When multiple counters share this name,
	 * the operation is performed on the counters in the sequence of its
	 * creation, and more than one counter may reach target value. */
	static void count_by_name(const std::string& counter_name, unsigned int n);

public:
	static WFMailboxTask *create_mailbox_task(void **mailbox,
											  mailbox_callback_t callback)
	{
		return new WFMailboxTask(mailbox, std::move(callback));
	}

	/* Use 'user_data' as mailbox. */
	static WFMailboxTask *create_mailbox_task(mailbox_callback_t callback)
	{
		return new WFMailboxTask(std::move(callback));
	}

	static WFMailboxTask *create_mailbox_task(const std::string& mailbox_name,
											  void **mailbox,
											  mailbox_callback_t callback);

	static WFMailboxTask *create_mailbox_task(const std::string& mailbox_name,
											  mailbox_callback_t callback);

	/* The 'msg' will be sent to the all mailbox tasks under the name, and
	 * would be lost if no task matched. */
	static void send_by_name(const std::string& mailbox_name, void *msg)
	{
		WFTaskFactory::send_by_name(mailbox_name, msg, (size_t)-1);
	}

	static void send_by_name(const std::string& mailbox_name, void *msg,
							 size_t max);

public:
	static WFConditional *create_conditional(SubTask *task, void **msgbuf)
	{
		return new WFConditional(task, msgbuf);
	}

	static WFConditional *create_conditional(SubTask *task)
	{
		return new WFConditional(task);
	}

	static WFConditional *create_conditional(const std::string& cond_name,
											 SubTask *task, void **msgbuf);

	static WFConditional *create_conditional(const std::string& cond_name,
											 SubTask *task);

	static void signal_by_name(const std::string& cond_name, void *msg)
	{
		WFTaskFactory::signal_by_name(cond_name, msg, (size_t)-1);
	}

	static void signal_by_name(const std::string& cond_name, void *msg,
							   size_t max);

public:
	static WFConditional *create_guard(const std::string& resource_name,
									   SubTask *task);

	static WFConditional *create_guard(const std::string& resource_name,
									   SubTask *task, void **msgbuf);

	/* The 'guard' is acquired after started, so call 'release_guard' after
	   and only after the task is finished, typically in its callback.
	   The function returns 1 if another is signaled, otherwise returns 0. */
	static int release_guard(const std::string& resource_name)
	{
		return WFTaskFactory::release_guard(resource_name, NULL);
	}

	static int release_guard(const std::string& resaource_name, void *msg);

	static int release_guard_safe(const std::string& resource_name)
	{
		return WFTaskFactory::release_guard_safe(resource_name, NULL);
	}

	static int release_guard_safe(const std::string& resource_name, void *msg);

public:
	template<class FUNC, class... ARGS>
	static WFGoTask *create_go_task(const std::string& queue_name,
									FUNC&& func, ARGS&&... args);

	/* Create 'Go' task with running time limit in seconds plus nanoseconds.
	 * If time exceeded, state WFT_STATE_SYS_ERROR and error ETIMEDOUT
	 * will be got in callback. */
	template<class FUNC, class... ARGS>
	static WFGoTask *create_timedgo_task(time_t seconds, long nanoseconds,
										 const std::string& queue_name,
										 FUNC&& func, ARGS&&... args);

	/* Create 'Go' task on user's executor and execution queue. */
	template<class FUNC, class... ARGS>
	static WFGoTask *create_go_task(ExecQueue *queue, Executor *executor,
									FUNC&& func, ARGS&&... args);

	template<class FUNC, class... ARGS>
	static WFGoTask *create_timedgo_task(time_t seconds, long nanoseconds,
										 ExecQueue *queue, Executor *executor,
										 FUNC&& func, ARGS&&... args);

	/* For capturing 'task' itself in go task's running function. */
	template<class FUNC, class... ARGS>
	static void reset_go_task(WFGoTask *task, FUNC&& func, ARGS&&... args);

public:
	static WFGraphTask *create_graph_task(graph_callback_t callback)
	{
		return new WFGraphTask(std::move(callback));
	}

public:
	static WFEmptyTask *create_empty_task()
	{
		return new WFEmptyTask;
	}

	static WFDynamicTask *create_dynamic_task(dynamic_create_t create);

	static WFRepeaterTask *create_repeater_task(repeated_create_t create,
												repeater_callback_t callback)
	{
		return new WFRepeaterTask(std::move(create), std::move(callback));
	}

public:
	static WFModuleTask *create_module_task(SubTask *first,
											module_callback_t callback)
	{
		return new WFModuleTask(first, std::move(callback));
	}

	static WFModuleTask *create_module_task(SubTask *first, SubTask *last,
											module_callback_t callback)
	{
		WFModuleTask *task = new WFModuleTask(first, std::move(callback));
		task->sub_series()->set_last_task(last);
		return task;
	}
};

template<class REQ, class RESP>
class WFNetworkTaskFactory
{
private:
	using T = WFNetworkTask<REQ, RESP>;

public:
	static T *create_client_task(enum TransportType type,
								 const std::string& host,
								 unsigned short port,
								 int retry_max,
								 std::function<void (T *)> callback);

	static T *create_client_task(enum TransportType type,
								 const std::string& url,
								 int retry_max,
								 std::function<void (T *)> callback);

	static T *create_client_task(enum TransportType type,
								 const ParsedURI& uri,
								 int retry_max,
								 std::function<void (T *)> callback);

	static T *create_client_task(enum TransportType type,
								 const struct sockaddr *addr,
								 socklen_t addrlen,
								 int retry_max,
								 std::function<void (T *)> callback);

public:
	static T *create_server_task(CommService *service,
								 std::function<void (T *)>& process);
};

template<class INPUT, class OUTPUT>
class WFThreadTaskFactory
{
private:
	using T = WFThreadTask<INPUT, OUTPUT>;

public:
	static T *create_thread_task(const std::string& queue_name,
								std::function<void (INPUT *, OUTPUT *)> routine,
								std::function<void (T *)> callback);

	/* Create thread task with running time limit. */
	static T *create_thread_task(time_t seconds, long nanoseconds,
								const std::string& queue_name,
								std::function<void (INPUT *, OUTPUT *)> routine,
								std::function<void (T *)> callback);

public:
	/* Create thread task on user's executor and execution queue. */
	static T *create_thread_task(ExecQueue *queue, Executor *executor,
								std::function<void (INPUT *, OUTPUT *)> routine,
								std::function<void (T *)> callback);

	/* With running time limit. */
	static T *create_thread_task(time_t seconds, long nanoseconds,
								ExecQueue *queue, Executor *executor,
								std::function<void (INPUT *, OUTPUT *)> routine,
								std::function<void (T *)> callback);
};

#include "WFTaskFactory.inl"

#endif

