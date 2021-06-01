/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <time.h>
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFGlobal.h"
#include "WFCondition.h"

class WFTimedWaitTask;

class WFWaitTask : public WFCounterTask
{
public:
	WFWaitTask(std::function<void (WFCounterTask *)>&& cb) :
		WFCounterTask(1, std::move(cb))
	{
		this->timer = NULL;
		this->entry.list.next = NULL;
		this->entry.ptr = this;
	}

protected:
	virtual SubTask *done();

public:
	void set_timer(WFTimedWaitTask *timer) { this->timer = timer; }
	void clear_timer_waiter();

	struct task_entry
	{
		struct list_head list;
		WFWaitTask *ptr;
	} entry;

private:
	WFTimedWaitTask *timer;
};

class WFTimedWaitTask : public __WFTimerTask
{
public:
	WFTimedWaitTask(WFWaitTask *wait_task, pthread_mutex_t *mutex,
					const struct timespec *value,
					CommScheduler *scheduler,
					std::function<void (WFTimerTask *)> cb) :
		__WFTimerTask(value, scheduler, std::move(cb))
	{
		this->mutex = mutex;
		this->wait_task = wait_task;
	}

	void clear_wait_task();

protected:
	virtual SubTask *done();

private:
	pthread_mutex_t *mutex;
	WFWaitTask *wait_task;
};

SubTask *WFWaitTask::done()
{
	SeriesWork *series = series_of(this);

	WFTimerTask *switch_task = WFTaskFactory::create_timer_task(0,
		[this](WFTimerTask *task){
			if (this->callback)
				this->callback(this);
			delete this;
	});
	series->push_front(switch_task);

	return series->pop();
}

void WFWaitTask::clear_timer_waiter()
{
	if (this->timer)
		timer->clear_wait_task();
}

SubTask *WFTimedWaitTask::done()
{
	pthread_mutex_lock(this->mutex);
	if (this->wait_task && this->wait_task->entry.list.next)
	{
		list_del(&this->wait_task->entry.list);
		this->wait_task->entry.list.next = NULL;//
		this->wait_task->count();
	}
	pthread_mutex_unlock(this->mutex);

	SeriesWork *series = series_of(this);
	
	if (this->callback)
		this->callback(this);

	delete this;
	return series->pop();
}

void WFTimedWaitTask::clear_wait_task()
{
	pthread_mutex_lock(this->mutex);
	this->wait_task = NULL;
	pthread_mutex_unlock(this->mutex);
}

WFCounterTask *WFCondition::create_wait_task(counter_callback_t cb)
{
	WFWaitTask *task = new WFWaitTask(std::move(cb));
	pthread_mutex_lock(&this->mutex);
	list_add_tail(&task->entry.list, &this->waiter_list);
	pthread_mutex_unlock(&this->mutex);
	return task;
}

WFCounterTask *WFCondition::create_timedwait_task(unsigned int microseconds,
												  counter_callback_t cb)
{
	WFWaitTask *waiter = new WFWaitTask(std::move(cb));
	struct timespec value = {
		.tv_sec     =   (time_t)(microseconds / 1000000),
		.tv_nsec    =   (long)(microseconds % 1000000 * 1000)
	};

	WFTimedWaitTask *task = new WFTimedWaitTask(waiter, &this->mutex, &value,
												WFGlobal::get_scheduler(),
												nullptr); //
	waiter->set_timer(task);

	pthread_mutex_lock(&this->mutex);
	list_add_tail(&waiter->entry.list, &this->waiter_list);
	pthread_mutex_unlock(&this->mutex);

	task->dispatch();

	return waiter;
}

void WFCondition::signal()
{
	WFWaitTask *task;
	struct list_head *pos;
	struct WFWaitTask::task_entry *entry;

	pthread_mutex_lock(&this->mutex);

	if (!list_empty(&this->waiter_list))
	{
		pos = this->waiter_list.next;
		entry = list_entry(pos, struct WFWaitTask::task_entry, list);
		task = entry->ptr;
		list_del(pos);
		//task->list.next = NULL;
		task->clear_timer_waiter();
		task->count();
	}

	pthread_mutex_unlock(&this->mutex);
}

void WFCondition::broadcast()
{
	WFWaitTask *task;
	struct list_head *pos, *tmp;
	struct WFWaitTask::task_entry *entry;

	pthread_mutex_lock(&this->mutex);
	if (!list_empty(&this->waiter_list))
	{
		list_for_each_safe(pos, tmp, &this->waiter_list)
		{
			entry = list_entry(pos, struct WFWaitTask::task_entry, list);
			task = entry->ptr;
			list_del(pos);
			//task->list.next = NULL;	
			task->count();
		}
	}
	pthread_mutex_unlock(&this->mutex);
}

