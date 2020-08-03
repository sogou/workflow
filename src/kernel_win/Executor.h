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

#ifndef _EXECUTOR_H_
#define _EXECUTOR_H_

#include <stddef.h>
#include <mutex>
#include "list.h"
#include "thrdpool.h"

class ExecQueue
{
public:
	int init();
	void deinit() { }

private:
	struct list_head task_list;
	std::mutex mutex;

public:
	virtual ~ExecQueue() { }
	friend class Executor;
};

#define ES_STATE_FINISHED	0
#define ES_STATE_ERROR		1
#define ES_STATE_CANCELED	2

class ExecSession
{
private:
	virtual void execute() = 0;
	virtual void handle(int state, int error) = 0;

protected:
	ExecQueue *get_queue() { return this->queue; }

private:
	ExecQueue *queue;

public:
	virtual ~ExecSession() { }
	friend class Executor;
};

class Executor
{
public:
	int init(size_t nthreads);
	void deinit();

	int request(ExecSession *session, ExecQueue *queue);

private:
	thrdpool_t *thrdpool;

private:
	static void executor_thread_routine(void *context);
	static void executor_cancel_tasks(const struct thrdpool_task *task);

public:
	virtual ~Executor() { }
};

#endif

