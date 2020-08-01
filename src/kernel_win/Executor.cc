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

#include <errno.h>
#include <stdlib.h>
#include "list.h"
#include "thrdpool.h"
#include "Executor.h"

struct ExecTaskEntry
{
	struct list_head list;
	ExecSession *session;
	thrdpool_t *thrdpool;
};

int ExecQueue::init()
{
	INIT_LIST_HEAD(&this->task_list);
	return 0;
}

int Executor::init(size_t nthreads)
{
	if (nthreads == 0)
	{
		errno = EINVAL;
		return -1;
	}

	this->thrdpool = thrdpool_create(nthreads, 0);
	if (this->thrdpool)
		return 0;

	return -1;
}

void Executor::deinit()
{
	thrdpool_destroy(Executor::executor_cancel_tasks, this->thrdpool);
}

void __thrdpool_schedule(const struct thrdpool_task *, void *, thrdpool_t *);

void Executor::executor_thread_routine(void *context)
{
	ExecQueue *queue = (ExecQueue *)context;
	ExecTaskEntry *entry;
	ExecSession *session;

	queue->mutex.lock();
	entry = list_entry(queue->task_list.next, ExecTaskEntry, list);
	list_del(&entry->list);
	session = entry->session;
	if (!list_empty(&queue->task_list))
	{
		struct thrdpool_task task = {Executor::executor_thread_routine, queue};
		/*
		{
			.routine	=	Executor::executor_thread_routine,
			.context	=	queue
		};
		*/
		__thrdpool_schedule(&task, entry, entry->thrdpool);
	}
	else
		delete entry;

	queue->mutex.unlock();
	session->execute();
	session->handle(ES_STATE_FINISHED, 0);
}

void Executor::executor_cancel_tasks(const struct thrdpool_task *task)
{
	ExecQueue *queue = (ExecQueue *)task->context;
	ExecTaskEntry *entry;
	struct list_head *pos, *tmp;
	ExecSession *session;

	list_for_each_safe(pos, tmp, &queue->task_list)
	{
		entry = list_entry(pos, ExecTaskEntry, list);
		list_del(pos);
		session = entry->session;
		delete entry;

		session->handle(ES_STATE_CANCELED, 0);
	}
}

int Executor::request(ExecSession *session, ExecQueue *queue)
{
	ExecTaskEntry *entry = new ExecTaskEntry;

	session->queue = queue;
	entry->session = session;
	entry->thrdpool = this->thrdpool;
	queue->mutex.lock();
	list_add_tail(&entry->list, &queue->task_list);
	if (queue->task_list.next == &entry->list)
	{
		struct thrdpool_task task = {Executor::executor_thread_routine, queue};
		/*
		{
			.routine	=	Executor::executor_thread_routine,
			.context	=	queue
		};
		*/
		if (thrdpool_schedule(&task, this->thrdpool) < 0)
		{
			list_del(&entry->list);
			delete entry;
			entry = NULL;
		}
	}

	queue->mutex.unlock();
	return -!entry;
}

