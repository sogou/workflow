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

#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include "list.h"
#include "thrdpool.h"
#include "Executor.h"

struct ExecSessionEntry
{
	struct list_head list;
	ExecSession *session;
	thrdpool_t *thrdpool;
};

int ExecQueue::init()
{
	int ret;

	ret = pthread_mutex_init(&this->mutex, NULL);
	if (ret == 0)
	{
		INIT_LIST_HEAD(&this->session_list);
		return 0;
	}

	errno = ret;
	return -1;
}

void ExecQueue::deinit()
{
	pthread_mutex_destroy(&this->mutex);
}

int Executor::init(size_t nthreads)
{
	this->thrdpool = thrdpool_create(nthreads, 0);
	if (this->thrdpool)
		return 0;

	return -1;
}

void Executor::deinit()
{
	thrdpool_destroy(Executor::executor_cancel, this->thrdpool);
}

extern "C" void __thrdpool_schedule(const struct thrdpool_task *, void *,
									thrdpool_t *);

void Executor::executor_thread_routine(void *context)
{
	ExecQueue *queue = (ExecQueue *)context;
	struct ExecSessionEntry *entry;
	ExecSession *session;
	int empty;

	entry = list_entry(queue->session_list.next, struct ExecSessionEntry, list);
	pthread_mutex_lock(&queue->mutex);
	list_del(&entry->list);
	empty = list_empty(&queue->session_list);
	pthread_mutex_unlock(&queue->mutex);

	session = entry->session;
	if (!empty)
	{
		struct thrdpool_task task = {
			.routine	=	Executor::executor_thread_routine,
			.context	=	queue
		};
		__thrdpool_schedule(&task, entry, entry->thrdpool);
	}
	else
		free(entry);

	session->execute();
	session->handle(ES_STATE_FINISHED, 0);
}

void Executor::executor_cancel(const struct thrdpool_task *task)
{
	ExecQueue *queue = (ExecQueue *)task->context;
	struct ExecSessionEntry *entry;
	struct list_head *pos, *tmp;
	ExecSession *session;

	list_for_each_safe(pos, tmp, &queue->session_list)
	{
		entry = list_entry(pos, struct ExecSessionEntry, list);
		list_del(pos);
		session = entry->session;
		free(entry);

		session->handle(ES_STATE_CANCELED, 0);
	}
}

int Executor::request(ExecSession *session, ExecQueue *queue)
{
	struct ExecSessionEntry *entry;

	session->queue = queue;
	entry = (struct ExecSessionEntry *)malloc(sizeof (struct ExecSessionEntry));
	if (entry)
	{
		entry->session = session;
		entry->thrdpool = this->thrdpool;
		pthread_mutex_lock(&queue->mutex);
		list_add_tail(&entry->list, &queue->session_list);
		if (queue->session_list.next == &entry->list)
		{
			struct thrdpool_task task = {
				.routine	=	Executor::executor_thread_routine,
				.context	=	queue
			};
			if (thrdpool_schedule(&task, this->thrdpool) < 0)
			{
				list_del(&entry->list);
				free(entry);
				entry = NULL;
			}
		}

		pthread_mutex_unlock(&queue->mutex);
	}

	return -!entry;
}

int Executor::increase_thread()
{
	return thrdpool_increase(this->thrdpool);
}

int Executor::decrease_thread()
{
	return thrdpool_decrease(this->thrdpool);
}

