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

#include <sys/types.h>
#include <time.h>
#include <string>
#include <mutex>
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
	__WFTimerTask(CommScheduler *scheduler, time_t seconds, long nanoseconds,
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
	return new __WFTimerTask(WFGlobal::get_scheduler(), seconds, nanoseconds,
							 std::move(callback));
}

/* Deprecated. */
WFTimerTask *WFTaskFactory::create_timer_task(unsigned int microseconds,
											  timer_callback_t callback)
{
	return new __WFTimerTask(WFGlobal::get_scheduler(),
							 (time_t)(microseconds / 1000000),
							 (long)(microseconds % 1000000 * 1000),
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

	void del(T *node)
	{
		list_del(&node->list);
	}

	struct rb_node rb;
	struct list_head head;
	std::string name;
};

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
	using CounterList = __NamedObjectList<struct __counter_node>;

public:
	WFCounterTask *create(const std::string& name, unsigned int target_value,
						  std::function<void (WFCounterTask *)>&& cb);

	void count_n(const std::string& name, unsigned int n);
	void count(CounterList *counters, struct __counter_node *node);
	void remove(CounterList *counters, struct __counter_node *node);

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
	__WFNamedCounterTask(unsigned int target_value,
					 __NamedCounterMap::CounterList *counters,
					 std::function<void (WFCounterTask *)>&& cb) :
		WFCounterTask(1, std::move(cb))
	{
		node_.target_value = target_value;
		node_.task = this;
		counters->push_back(&node_);
		counters_ = counters;
	}

	virtual ~__WFNamedCounterTask()
	{
		if (this->value != 0)
			__counter_map.remove(counters_, &node_);
	}

	virtual void count()
	{
		__counter_map.count(counters_, &node_);
	}

private:
	struct __counter_node node_;
	__NamedCounterMap::CounterList *counters_;
};

WFCounterTask *__NamedCounterMap::create(const std::string& name,
								unsigned int target_value,
								std::function<void (WFCounterTask *)>&& cb)
{
	if (target_value == 0)
		return new WFCounterTask(0, std::move(cb));

	struct rb_node **p = &root_.rb_node;
	struct rb_node *parent = NULL;
	CounterList *counters;
	std::lock_guard<std::mutex> lock(mutex_);

	while (*p)
	{
		parent = *p;
		counters = rb_entry(*p, CounterList, rb);
		if (name < counters->name)
			p = &(*p)->rb_left;
		else if (name > counters->name)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (*p == NULL)
	{
		counters = new CounterList(name);
		rb_link_node(&counters->rb, parent, p);
		rb_insert_color(&counters->rb, &root_);
	}

	return new __WFNamedCounterTask(target_value, counters, std::move(cb));
}

void __NamedCounterMap::count_n_locked(CounterList *counters, unsigned int n,
									   struct list_head *task_list)
{
	struct __counter_node *node;
	struct list_head *pos;
	struct list_head *tmp;

	list_for_each_safe(pos, tmp, &counters->head)
	{
		if (n == 0)
			return;

		node = list_entry(pos, struct __counter_node, list);
		if (n >= node->target_value)
		{
			n -= node->target_value;
			node->target_value = 0;
			list_move_tail(pos, task_list);
			if (counters->empty())
			{
				rb_erase(&counters->rb, &root_);
				delete counters;
				return;
			}
		}
		else
		{
			node->target_value -= n;
			n = 0;
		}
	}
}

void __NamedCounterMap::count_n(const std::string& name, unsigned int n)
{
	LIST_HEAD(task_list);
	CounterList *counters;
	struct __counter_node *node;
	struct rb_node *p;

	mutex_.lock();
	p = root_.rb_node;
	while (p)
	{
		counters = rb_entry(p, CounterList, rb);
		if (name < counters->name)
			p = p->rb_left;
		else if (name > counters->name)
			p = p->rb_right;
		else
		{
			count_n_locked(counters, n, &task_list);
			break;
		}
	}

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
		counters->del(node);
		if (counters->empty())
		{
			rb_erase(&counters->rb, &root_);
			delete counters;
		}
	}

	mutex_.unlock();
	if (task)
		task->WFCounterTask::count();
}

void __NamedCounterMap::remove(CounterList *counters,
							   struct __counter_node *node)
{
	mutex_.lock();
	counters->del(node);
	if (counters->empty())
	{
		rb_erase(&counters->rb, &root_);
		delete counters;
	}

	mutex_.unlock();
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
	using ConditionalList = __NamedObjectList<struct __conditional_node>;

public:
	WFConditional *create(const std::string& name, SubTask *task,
						  void **msgbuf);
	WFConditional *create(const std::string& name, SubTask *task);

	void signal(const std::string& name, void *msg, size_t max);
	void signal(ConditionalList *conds, struct __conditional_node *node,
				void *msg);
	void remove(ConditionalList *conds, struct __conditional_node *node);

private:
	ConditionalList *get_list(const std::string& name, bool insert);
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
	__WFNamedCondtional(SubTask *task, void **msgbuf,
						__NamedConditionalMap::ConditionalList *conds) :
		WFConditional(task, msgbuf)
	{
		node_.cond = this;
		conds->push_back(&node_);
		conds_ = conds;
	}

	__WFNamedCondtional(SubTask *task,
						__NamedConditionalMap::ConditionalList *conds) :
		WFConditional(task)
	{
		node_.cond = this;
		conds->push_back(&node_);
		conds_ = conds;
	}

	virtual ~__WFNamedCondtional()
	{
		if (!this->flag)
			__conditional_map.remove(conds_, &node_);
	}

	virtual void signal(void *msg)
	{
		__conditional_map.signal(conds_, &node_, msg);
	}

private:
	struct __conditional_node node_;
	__NamedConditionalMap::ConditionalList *conds_;
};

WFConditional *__NamedConditionalMap::create(const std::string& name,
											 SubTask *task, void **msgbuf)
{
	std::lock_guard<std::mutex> lock(mutex_);
	ConditionalList *conds = get_list(name, true);
	return new __WFNamedCondtional(task, msgbuf, conds);
}

WFConditional *__NamedConditionalMap::create(const std::string& name,
											 SubTask *task)
{
	std::lock_guard<std::mutex> lock(mutex_);
	ConditionalList *conds = get_list(name, true);
	return new __WFNamedCondtional(task, conds);
}

__NamedConditionalMap::ConditionalList *
__NamedConditionalMap::get_list(const std::string& name, bool insert)
{
	struct rb_node **p = &root_.rb_node;
	struct rb_node *parent = NULL;
	ConditionalList *conds;

	while (*p)
	{
		parent = *p;
		conds = rb_entry(*p, ConditionalList, rb);
		if (name < conds->name)
			p = &(*p)->rb_left;
		else if (name > conds->name)
			p = &(*p)->rb_right;
		else
			return conds;
	}

	if (insert)
	{
		conds = new ConditionalList(name);
		rb_link_node(&conds->rb, parent, p);
		rb_insert_color(&conds->rb, &root_);
		return conds;
	}

	return NULL;
}

void __NamedConditionalMap::signal(const std::string& name, void *msg, size_t max)
{
	LIST_HEAD(cond_list);
	struct __conditional_node *node;
	ConditionalList *conds;
	struct list_head *pos;
	struct list_head *tmp;

	mutex_.lock();
	conds = get_list(name, false);
	if (!conds)
	{
		mutex_.unlock();
		return;
	}

	if (max == (size_t)-1)
		list_splice(&conds->head, &cond_list);
	else
	{
		list_for_each_safe(pos, tmp, &conds->head)
		{
			if (max == 0)
			{
				conds = NULL;
				break;
			}

			list_move_tail(pos, &cond_list);
			max--;
		}
	}

	if (conds)
	{
		rb_erase(&conds->rb, &root_);
		delete conds;
	}

	mutex_.unlock();
	list_for_each_safe(pos, tmp, &cond_list)
	{
		node = list_entry(pos, struct __conditional_node, list);
		node->cond->WFConditional::signal(msg);
	}
}

void __NamedConditionalMap::signal(ConditionalList *conds,
								   struct __conditional_node *node,
								   void *msg)
{
	mutex_.lock();
	conds->del(node);
	if (conds->empty())
	{
		rb_erase(&conds->rb, &root_);
		delete conds;
	}

	mutex_.unlock();
	node->cond->WFConditional::signal(msg);
}

void __NamedConditionalMap::remove(ConditionalList *conds,
								   struct __conditional_node *node)
{
	mutex_.lock();
	conds->del(node);
	if (conds->empty())
	{
		rb_erase(&conds->rb, &root_);
		delete conds;
	}

	mutex_.unlock();
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
		task->state = WFT_STATE_ABORTED;
		task->error = 0;
		task->subtask_done();
	}

	if (--task->ref == 0)
		delete task;
}

