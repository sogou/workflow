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
*/

#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <utility>
#include <string>
#include <mutex>
#include <atomic>
#include "list.h"
#include "rbtree.h"
#include "WFGlobal.h"
#include "WFTaskFactory.h"

class __WFTimerTask : public WFTimerTask
{
protected:
	virtual int duration(struct timespec *value)
	{
		value->tv_sec = this->seconds;
		value->tv_nsec = this->nanoseconds;
		return 0;
	}

protected:
	time_t seconds;
	long nanoseconds;

public:
	__WFTimerTask(time_t seconds, long nanoseconds, CommScheduler *scheduler,
				  timer_callback_t&& cb) :
		WFTimerTask(scheduler, std::move(cb))
	{
		this->seconds = seconds;
		this->nanoseconds = nanoseconds;
	}
};

WFTimerTask *WFTaskFactory::create_timer_task(time_t seconds, long nanoseconds,
											  timer_callback_t callback)
{
	return new __WFTimerTask(seconds, nanoseconds, WFGlobal::get_scheduler(),
							 std::move(callback));
}

/* Deprecated. */
WFTimerTask *WFTaskFactory::create_timer_task(unsigned int microseconds,
											  timer_callback_t callback)
{
	return WFTaskFactory::create_timer_task(microseconds / 1000000,
											microseconds % 1000000 * 1000,
											std::move(callback));
}

/****************** Named Tasks ******************/

template<typename T>
struct __NamedObjectList
{
	__NamedObjectList(const std::string& str):
		name(str)
	{
		INIT_LIST_HEAD(&this->head);
	}

	void push_back(T *node)
	{
		list_add_tail(&node->list, &this->head);
	}

	bool empty() const
	{
		return list_empty(&this->head);
	}

	void del(T *node, rb_root *root)
	{
		list_del(&node->list);
		if (this->empty())
		{
			rb_erase(&this->rb, root);
			delete this;
		}
	}

	struct rb_node rb;
	struct list_head head;
	std::string name;
};

template<typename T>
static T *__get_object_list(const std::string& name, struct rb_root *root,
							bool insert)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	T *objs;

	while (*p)
	{
		parent = *p;
		objs = rb_entry(*p, T, rb);
		if (name < objs->name)
			p = &(*p)->rb_left;
		else if (name > objs->name)
			p = &(*p)->rb_right;
		else
			return objs;
	}

	if (insert)
	{
		objs = new T(name);
		rb_link_node(&objs->rb, parent, p);
		rb_insert_color(&objs->rb, root);
		return objs;
	}

	return NULL;
}

/****************** Named Timer ******************/

class __WFNamedTimerTask;

struct __timer_node
{
	struct list_head list;
	__WFNamedTimerTask *task;
};

static class __NamedTimerMap
{
public:
	using TimerList = struct __NamedObjectList<struct __timer_node>;

public:
	WFTimerTask *create(const std::string& name,
						time_t seconds, long nanoseconds,
						CommScheduler *scheduler,
						timer_callback_t&& cb);

public:
	void cancel(const std::string& name, size_t max);

private:
	struct rb_root root_;
	std::mutex mutex_;

public:
	__NamedTimerMap()
	{
		root_.rb_node = NULL;
	}

	friend class __WFNamedTimerTask;
} __timer_map;

class __WFNamedTimerTask : public __WFTimerTask
{
public:
	__WFNamedTimerTask(time_t seconds, long nanoseconds,
					   CommScheduler *scheduler,
					   timer_callback_t&& cb) :
		__WFTimerTask(seconds, nanoseconds, scheduler, std::move(cb)),
		flag_(false)
	{
		node_.task = this;
	}

	void push_to(__NamedTimerMap::TimerList *timers)
	{
		timers->push_back(&node_);
		timers_ = timers;
	}

	virtual ~__WFNamedTimerTask()
	{
		if (node_.task)
		{
			std::lock_guard<std::mutex> lock(__timer_map.mutex_);
			if (node_.task)
				timers_->del(&node_, &__timer_map.root_);
		}
	}

protected:
	virtual void dispatch();
	virtual void handle(int state, int error);

private:
	struct __timer_node node_;
	__NamedTimerMap::TimerList *timers_;
	std::atomic<bool> flag_;
	std::mutex mutex_;
	friend class __NamedTimerMap;
};

void __WFNamedTimerTask::dispatch()
{
	int ret;

	mutex_.lock();
	ret = this->scheduler->sleep(this);
	if (ret >= 0 && flag_.exchange(true))
		this->cancel();

	mutex_.unlock();
	if (ret < 0)
		this->handle(SS_STATE_ERROR, errno);
}

void __WFNamedTimerTask::handle(int state, int error)
{
	if (node_.task)
	{
		std::lock_guard<std::mutex> lock(__timer_map.mutex_);
		if (node_.task)
		{
			timers_->del(&node_, &__timer_map.root_);
			node_.task = NULL;
		}
	}

	mutex_.lock();
	mutex_.unlock();
	this->__WFTimerTask::handle(state, error);
}

WFTimerTask *__NamedTimerMap::create(const std::string& name,
									 time_t seconds, long nanoseconds,
									 CommScheduler *scheduler,
									 timer_callback_t&& cb)
{
	auto *task = new __WFNamedTimerTask(seconds, nanoseconds, scheduler,
										std::move(cb));
	mutex_.lock();
	task->push_to(__get_object_list<TimerList>(name, &root_, true));
	mutex_.unlock();
	return task;
}

void __NamedTimerMap::cancel(const std::string& name, size_t max)
{
	struct __timer_node *node;
	TimerList *timers;

	std::lock_guard<std::mutex> lock(mutex_);
	timers = __get_object_list<TimerList>(name, &root_, false);
	if (timers)
	{
		do
		{
			if (max == 0)
				return;

			node = list_entry(timers->head.next, struct __timer_node, list);
			list_del(&node->list);
			if (node->task->flag_.exchange(true))
				node->task->cancel();

			node->task = NULL;
			max--;
		} while (!timers->empty());

		rb_erase(&timers->rb, &root_);
		delete timers;
	}
}

WFTimerTask *WFTaskFactory::create_timer_task(const std::string& timer_name,
											  time_t seconds, long nanoseconds,
											  timer_callback_t callback)
{
	return __timer_map.create(timer_name, seconds, nanoseconds,
							  WFGlobal::get_scheduler(),
							  std::move(callback));
}

void WFTaskFactory::cancel_by_name(const std::string& timer_name, size_t max)
{
	__timer_map.cancel(timer_name, max);
}

/****************** Named Counter ******************/

class __WFNamedCounterTask;

struct __counter_node
{
	struct list_head list;
	unsigned int target_value;
	__WFNamedCounterTask *task;
};

static class __NamedCounterMap
{
public:
	using CounterList = struct __NamedObjectList<struct __counter_node>;

public:
	WFCounterTask *create(const std::string& name, unsigned int target_value,
						  counter_callback_t&& cb);

	void count_n(const std::string& name, unsigned int n);
	void count(CounterList *counters, struct __counter_node *node);

	void remove(CounterList *counters, struct __counter_node *node)
	{
		mutex_.lock();
		counters->del(node, &root_);
		mutex_.unlock();
	}

private:
	void count_n_locked(CounterList *counters, unsigned int n,
						struct list_head *task_list);
	struct rb_root root_;
	std::mutex mutex_;

public:
	__NamedCounterMap()
	{
		root_.rb_node = NULL;
	}
} __counter_map;

class __WFNamedCounterTask : public WFCounterTask
{
public:
	__WFNamedCounterTask(unsigned int target_value, counter_callback_t&& cb) :
		WFCounterTask(1, std::move(cb))
	{
		node_.target_value = target_value;
		node_.task = this;
	}

	void push_to(__NamedCounterMap::CounterList *counters)
	{
		counters->push_back(&node_);
		counters_ = counters;
	}

	virtual void count()
	{
		__counter_map.count(counters_, &node_);
	}

	virtual ~__WFNamedCounterTask()
	{
		if (this->value != 0)
			__counter_map.remove(counters_, &node_);
	}

private:
	struct __counter_node node_;
	__NamedCounterMap::CounterList *counters_;
};

WFCounterTask *__NamedCounterMap::create(const std::string& name,
										 unsigned int target_value,
										 counter_callback_t&& cb)
{
	if (target_value == 0)
		return new WFCounterTask(0, std::move(cb));

	auto *task = new __WFNamedCounterTask(target_value, std::move(cb));
	mutex_.lock();
	task->push_to(__get_object_list<CounterList>(name, &root_, true));
	mutex_.unlock();
	return task;
}

void __NamedCounterMap::count_n_locked(CounterList *counters, unsigned int n,
									   struct list_head *task_list)
{
	struct __counter_node *node;

	do
	{
		if (n == 0)
			return;

		node = list_entry(counters->head.next, struct __counter_node, list);
		if (n >= node->target_value)
		{
			n -= node->target_value;
			node->target_value = 0;
			list_move_tail(&node->list, task_list);
		}
		else
		{
			node->target_value -= n;
			n = 0;
		}
	} while (!counters->empty());

	rb_erase(&counters->rb, &root_);
	delete counters;
}

void __NamedCounterMap::count_n(const std::string& name, unsigned int n)
{
	LIST_HEAD(task_list);
	struct __counter_node *node;
	CounterList *counters;

	mutex_.lock();
	counters = __get_object_list<CounterList>(name, &root_, false);
	if (counters)
		count_n_locked(counters, n, &task_list);

	mutex_.unlock();
	while (!list_empty(&task_list))
	{
		node = list_entry(task_list.next, struct __counter_node, list);
		list_del(&node->list);
		node->task->WFCounterTask::count();
	}
}

void __NamedCounterMap::count(CounterList *counters,
							  struct __counter_node *node)
{
	__WFNamedCounterTask *task = NULL;

	mutex_.lock();
	if (--node->target_value == 0)
	{
		task = node->task;
		counters->del(node, &root_);
	}

	mutex_.unlock();
	if (task)
		task->WFCounterTask::count();
}

WFCounterTask *WFTaskFactory::create_counter_task(const std::string& counter_name,
												  unsigned int target_value,
												  counter_callback_t callback)
{
	return __counter_map.create(counter_name, target_value, std::move(callback));
}

void WFTaskFactory::count_by_name(const std::string& counter_name, unsigned int n)
{
	__counter_map.count_n(counter_name, n);
}

/****************** Named Conditional ******************/

class __WFNamedCondtional;

struct __conditional_node
{
	struct list_head list;
	__WFNamedCondtional *cond;
};

static class __NamedConditionalMap
{
public:
	using ConditionalList = struct __NamedObjectList<struct __conditional_node>;

public:
	WFConditional *create(const std::string& name, SubTask *task,
						  void **msgbuf);
	WFConditional *create(const std::string& name, SubTask *task);

	void signal(const std::string& name, void *msg, size_t max);
	void signal(ConditionalList *conds, struct __conditional_node *node,
				void *msg);

	void remove(ConditionalList *conds, struct __conditional_node *node)
	{
		mutex_.lock();
		conds->del(node, &root_);
		mutex_.unlock();
	}

private:
	void signal_max_locked(ConditionalList *conds, void *msg, size_t max,
						   struct list_head *cond_list);
	struct rb_root root_;
	std::mutex mutex_;

public:
	__NamedConditionalMap()
	{
		root_.rb_node = NULL;
	}
} __conditional_map;

class __WFNamedCondtional : public WFConditional
{
public:
	__WFNamedCondtional(SubTask *task, void **msgbuf) :
		WFConditional(task, msgbuf)
	{
		node_.cond = this;
	}

	__WFNamedCondtional(SubTask *task) :
		WFConditional(task)
	{
		node_.cond = this;
	}

	void push_to(__NamedConditionalMap::ConditionalList *conds)
	{
		conds->push_back(&node_);
		conds_ = conds;
	}

	virtual void signal(void *msg)
	{
		__conditional_map.signal(conds_, &node_, msg);
	}

	virtual ~__WFNamedCondtional()
	{
		if (!this->flag)
			__conditional_map.remove(conds_, &node_);
	}

private:
	struct __conditional_node node_;
	__NamedConditionalMap::ConditionalList *conds_;
};

WFConditional *__NamedConditionalMap::create(const std::string& name,
											 SubTask *task, void **msgbuf)
{
	auto *cond = new __WFNamedCondtional(task, msgbuf);
	mutex_.lock();
	cond->push_to(__get_object_list<ConditionalList>(name, &root_, true));
	mutex_.unlock();
	return cond;
}

WFConditional *__NamedConditionalMap::create(const std::string& name,
											 SubTask *task)
{
	auto *cond = new __WFNamedCondtional(task);
	mutex_.lock();
	cond->push_to(__get_object_list<ConditionalList>(name, &root_, true));
	mutex_.unlock();
	return cond;
}

void __NamedConditionalMap::signal_max_locked(ConditionalList *conds,
											  void *msg, size_t max,
											  struct list_head *cond_list)
{
	if (max == (size_t)-1)
		list_splice(&conds->head, cond_list);
	else
	{
		do
		{
			if (max == 0)
				return;

			list_move_tail(conds->head.next, cond_list);
			max--;
		} while (!conds->empty());
	}

	rb_erase(&conds->rb, &root_);
	delete conds;
}

void __NamedConditionalMap::signal(const std::string& name, void *msg, size_t max)
{
	LIST_HEAD(cond_list);
	struct __conditional_node *node;
	ConditionalList *conds;

	mutex_.lock();
	conds = __get_object_list<ConditionalList>(name, &root_, false);
	if (conds)
		signal_max_locked(conds, msg, max, &cond_list);

	mutex_.unlock();
	while (!list_empty(&cond_list))
	{
		node = list_entry(cond_list.next, struct __conditional_node, list);
		list_del(&node->list);
		node->cond->WFConditional::signal(msg);
	}
}

void __NamedConditionalMap::signal(ConditionalList *conds,
								   struct __conditional_node *node,
								   void *msg)
{
	mutex_.lock();
	conds->del(node, &root_);
	mutex_.unlock();
	node->cond->WFConditional::signal(msg);
}

WFConditional *WFTaskFactory::create_conditional(const std::string& cond_name,
												 SubTask *task, void **msgbuf)
{
	return __conditional_map.create(cond_name, task, msgbuf);
}

WFConditional *WFTaskFactory::create_conditional(const std::string& cond_name,
												 SubTask *task)
{
	return __conditional_map.create(cond_name, task);
}

void WFTaskFactory::signal_by_name(const std::string& cond_name, void *msg,
								   size_t max)
{
	__conditional_map.signal(cond_name, msg, max);
}

/**************** Timed Go Task *****************/

void __WFTimedGoTask::dispatch()
{
	WFTimerTask *timer;

	timer = WFTaskFactory::create_timer_task(this->seconds, this->nanoseconds,
											 __WFTimedGoTask::timer_callback);
	timer->user_data = this;

	this->__WFGoTask::dispatch();
	timer->start();
}

SubTask *__WFTimedGoTask::done()
{
	if (this->callback)
		this->callback(this);

	return series_of(this)->pop();
}

void __WFTimedGoTask::handle(int state, int error)
{
	if (--this->ref == 3)
	{
		this->state = state;
		this->error = error;
		this->subtask_done();
	}

	if (--this->ref == 0)
		delete this;
}

void __WFTimedGoTask::timer_callback(WFTimerTask *timer)
{
	__WFTimedGoTask *task = (__WFTimedGoTask *)timer->user_data;

	if (--task->ref == 3)
	{
		task->state = WFT_STATE_SYS_ERROR;
		task->error = ETIMEDOUT;
		task->subtask_done();
	}

	if (--task->ref == 0)
		delete task;
}

