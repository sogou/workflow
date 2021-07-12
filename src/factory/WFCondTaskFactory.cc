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

#include <mutex>
#include <time.h>
#include <string>
#include <functional>
#include "list.h"
#include "rbtree.h"
#include "WFTask.h"
#include "WFCondTask.h"
#include "WFTaskFactory.h"
#include "WFCondTaskFactory.h"
#include "WFGlobal.h"

class __WFCondition : public WFCondition
{
public:
	__WFCondition(const std::string& str) :
		name(str)
	{ }

public:
	struct rb_node rb;
	std::string name;
};

class __ConditionMap
{
public:
	void signal(const std::string& name, void *msg);
	void broadcast(const std::string& name, void *msg);

	WFWaitTask *create(const std::string& name, wait_callback_t&& cb);
	WFWaitTask *create(const std::string& name,
					   const struct timespec *timeout,
					   wait_callback_t&& cb);
	WFWaitTask *create_switch(const std::string& name,
							  wait_callback_t&& cb);

public:
	static __ConditionMap *get_instance()
	{
		static __ConditionMap kInstance;
		return &kInstance;
	}

	virtual ~__ConditionMap();

private:
	__ConditionMap()
	{
		this->condition_map.rb_node = NULL;
	}

	__WFCondition *find_condition(const std::string& name);
	struct rb_root condition_map;
	std::mutex mutex;
};

void __ConditionMap::signal(const std::string& name, void *msg)
{
	__WFCondition *cond = this->find_condition(name);

	cond->signal(msg);
}

void __ConditionMap::broadcast(const std::string& name, void *msg)
{
	__WFCondition *cond = this->find_condition(name);

	cond->broadcast(msg);
}

WFWaitTask *__ConditionMap::create(const std::string& name,
								   wait_callback_t&& cb)
{
	__WFCondition *cond = this->find_condition(name);

	return WFCondTaskFactory::create_wait_task(cond, std::move(cb));
}

WFWaitTask *__ConditionMap::create(const std::string& name,
								   const struct timespec *timeout,
								   wait_callback_t&& cb)
{
	__WFCondition *cond = this->find_condition(name);

	return WFCondTaskFactory::create_timedwait_task(cond, timeout,
													std::move(cb));
}

WFWaitTask *__ConditionMap::create_switch(const std::string& name,
										  wait_callback_t&& cb)
{
	__WFCondition *cond = this->find_condition(name);

	return WFCondTaskFactory::create_swait_task(cond, std::move(cb));
}

__ConditionMap::~__ConditionMap()
{
	__WFCondition *cond;
	WFCondWaitTask *task;
	struct list_head *pos;
	struct list_head *tmp;

	while (this->condition_map.rb_node)
	{
		cond = rb_entry(this->condition_map.rb_node,
						__WFCondition, rb);

		list_for_each_safe(pos, tmp, &cond->wait_list)
		{
			task = list_entry(pos, WFCondWaitTask, list);
			list_del(pos);
			delete task;
		}

		rb_erase(this->condition_map.rb_node, &this->condition_map);
		delete cond;
	}
}

__WFCondition *__ConditionMap::find_condition(const std::string& name)
{
	__WFCondition *cond;
	struct rb_node **p = &this->condition_map.rb_node;
	struct rb_node *parent = NULL;

	this->mutex.lock();

	while (*p)
	{
		parent = *p;
		cond = rb_entry(*p, __WFCondition, rb);

		if (name < cond->name)
			p = &(*p)->rb_left;
		else if (name > cond->name)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (*p == NULL)
	{
		cond = new __WFCondition(name);
		rb_link_node(&cond->rb, parent, p);
		rb_insert_color(&cond->rb, &this->condition_map);
	}

	this->mutex.unlock();

	return cond;
}

class WFTimedWaitTask : public WFCondWaitTask
{
public:
	void set_timer(__WFWaitTimerTask *timer) { this->timer = timer; }
	virtual void count();
	virtual void clear_locked();

protected:
	virtual void dispatch();

private:
	__WFWaitTimerTask *timer;

public:
	WFTimedWaitTask(wait_callback_t&& cb) :
		WFCondWaitTask(std::move(cb))
	{
		this->timer = NULL;
	}

	virtual ~WFTimedWaitTask();
};

class __WFWaitTimerTask : public __WFTimerTask
{
public:
	void clear_wait_task() // must called within this mutex
	{
		this->wait_task = NULL;
	}

	__WFWaitTimerTask(WFTimedWaitTask *wait_task, const struct timespec *timeout,
					  std::mutex *mutex, std::atomic<int> *ref,
					  CommScheduler *scheduler) :
		__WFTimerTask(timeout, scheduler, nullptr)
	{
		this->ref = ref;
		++*this->ref;
		this->mutex = mutex;
		this->wait_task = wait_task;
	}

	virtual ~__WFWaitTimerTask();

protected:
	virtual SubTask *done();

private:
	std::mutex *mutex;
	std::atomic<int> *ref;
	WFTimedWaitTask *wait_task;
};

class WFSwitchWaitTask : public WFCondWaitTask
{
public:
	WFSwitchWaitTask(wait_callback_t&& cb) :
		WFCondWaitTask(std::move(cb))
	{ }

protected:
	SubTask *done();
};

void WFTimedWaitTask::clear_locked()
{
	this->timer->clear_wait_task();
	this->timer = NULL;
}

void WFTimedWaitTask::count()
{
	if (--this->value == 0)
	{
		if (this->state == WFT_STATE_UNDEFINED)
			this->state = WFT_STATE_SUCCESS;
		this->subtask_done();
	}
}

void WFTimedWaitTask::dispatch()
{
	if (this->timer)
		timer->dispatch();

	this->WFMailboxTask::count();
}

WFTimedWaitTask::~WFTimedWaitTask()
{
	if (this->state != WFT_STATE_SUCCESS)
		delete this->timer;
}

SubTask *WFSwitchWaitTask::done()
{
	SeriesWork *series = series_of(this);

	WFTimerTask *switch_task = WFTaskFactory::create_timer_task(0,
		[this](WFTimerTask *task) {
			if (this->callback)
				this->callback(this);
			delete this;
	});
	series->push_front(switch_task);

	return series->pop();
}

SubTask *__WFWaitTimerTask::done()
{
	WFTimedWaitTask *waiter = NULL;

	this->mutex->lock();
	if (this->wait_task)
	{
		list_del(&this->wait_task->list);
		this->wait_task->state = WFT_STATE_SYS_ERROR;
		this->wait_task->error = ETIMEDOUT;
		waiter = this->wait_task;
		waiter->set_timer(NULL);
	}
	this->mutex->unlock();

	if (waiter)
		waiter->count();
	delete this;
	return NULL;
}

__WFWaitTimerTask::~__WFWaitTimerTask()
{
	if (--*this->ref == 0)
	{
		delete this->mutex;
		delete this->ref;
	}
}

/////////////// WFSemaphore impl ///////////////

WFConditional *WFSemaphore::get(SubTask *task, void **psem)
{
	WFConditional *cond;
	WFSemaphoreTask *sem_task;

	if (--this->value >= 0)
	{
		cond = new WFConditional(task, psem);
		cond->signal(this->sems[--this->index]);
		return cond;
	}

	sem_task = new WFSemaphoreTask(task, psem);
	this->mutex.lock();
	list_add_tail(&sem_task->list, &this->wait_list);
	this->mutex.unlock();

	return sem_task;
}

void WFSemaphore::post(void *sem)
{
	WFSemaphoreTask *task = NULL;

	if (++this->value <= 0)
	{
		this->mutex.lock();
		task = list_entry(this->wait_list.next, WFSemaphoreTask, list);
		list_del(&task->list);
		this->mutex.unlock();
	}
	else
		this->sems[this->index++] = sem;

	if (task)
		task->signal(sem);
}

/////////////// factory impl ///////////////

void WFCondTaskFactory::signal_by_name(const std::string& name, void *msg)
{
	return __ConditionMap::get_instance()->signal(name, msg);
}

void WFCondTaskFactory::broadcast_by_name(const std::string& name, void *msg)
{
	return __ConditionMap::get_instance()->broadcast(name, msg);
}

WFWaitTask *WFCondTaskFactory::create_wait_task(const std::string& name,
												wait_callback_t callback)
{
	return __ConditionMap::get_instance()->create(name, std::move(callback));
}

WFWaitTask *WFCondTaskFactory::create_swait_task(const std::string& name,
												 wait_callback_t callback)
{
	return __ConditionMap::get_instance()->create_switch(name,
														 std::move(callback));
}

WFWaitTask *WFCondTaskFactory::create_timedwait_task(const std::string& name,
													 const struct timespec *timeout,
													 wait_callback_t callback)
{
	return __ConditionMap::get_instance()->create(name, timeout,
												  std::move(callback));
}

WFWaitTask *WFCondTaskFactory::create_wait_task(WFCondition *cond,
												wait_callback_t callback)
{
	WFCondWaitTask *task = new WFCondWaitTask(std::move(callback));

	cond->mutex->lock();
	list_add_tail(&task->list, &cond->wait_list);
	cond->mutex->unlock();

	return task;
}

WFWaitTask *WFCondTaskFactory::create_timedwait_task(WFCondition *cond,
													 const struct timespec *timeout,
													 wait_callback_t callback)
{
	WFTimedWaitTask *waiter = new WFTimedWaitTask(std::move(callback));
	__WFWaitTimerTask *task = new __WFWaitTimerTask(waiter, timeout,
													cond->mutex, cond->ref,
													WFGlobal::get_scheduler());
	waiter->set_timer(task);

	cond->mutex->lock();
	list_add_tail(&waiter->list, &cond->wait_list);
	cond->mutex->unlock();

	return waiter;
}

WFWaitTask *WFCondTaskFactory::create_swait_task(WFCondition *cond,
												 wait_callback_t callback)
{
	WFSwitchWaitTask *task = new WFSwitchWaitTask(std::move(callback));

	cond->mutex->lock();
	list_add_tail(&task->list, &cond->wait_list);
	cond->mutex->unlock();

	return task;
}

