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

#ifndef _EXECUTOR_H_
#define _EXECUTOR_H_

#include <stddef.h>
#include <pthread.h>
#include "list.h"

class ExecQueue
{
public:
	int init();
	void deinit();

private:
	struct list_head session_list;
	pthread_mutex_t mutex;

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
	ExecQueue *get_queue() const { return this->queue; }

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

public:
	int increase_thread();
	int decrease_thread();

private:
	struct __thrdpool *thrdpool;

private:
	static void executor_thread_routine(void *context);
	static void executor_cancel(const struct thrdpool_task *task);

public:
	virtual ~Executor() { }
};

#endif

