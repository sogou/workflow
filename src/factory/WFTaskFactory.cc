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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
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

WFTimerTask *WFTaskFactory::create_timer_task(unsigned int microseconds,
											  timer_callback_t callback)
{
	return new __WFTimerTask(WFGlobal::get_scheduler(),
							 (time_t)(microseconds / 1000000),
							 (long)(microseconds % 1000000 * 1000),
							 std::move(callback));
}

WFTimerTask *WFTaskFactory::create_timer_task(time_t seconds, long nanoseconds,
											  timer_callback_t callback)
{
	return new __WFTimerTask(WFGlobal::get_scheduler(), seconds, nanoseconds,
							 std::move(callback));
}

class __WFCounterTask;

struct __counter_node
{
	struct list_head list;
	unsigned int target_value;
	__WFCounterTask *task;
};

struct __CounterList
{
	__CounterList(const std::string& str):
		name(str)
	{
		INIT_LIST_HEAD(&this->head);
	}

	void push_back(struct __counter_node *node)
	{
		list_add_tail(&node->list, &this->head);
	}

	bool empty() const
	{
		return list_empty(&this->head);
	}

	void del(struct __counter_node *node)
	{
		list_del(&node->list);
	}

	struct rb_node rb;
	struct list_head head;
	std::string name;
};

static class __CounterMap
{
public:
	WFCounterTask *create(const std::string& name, unsigned int target_value,
						  std::function<void (WFCounterTask *)>&& cb);

	void count_n(const std::string& name, unsigned int n);
	void count(struct __CounterList *counters, struct __counter_node *node);
	void remove(struct __CounterList *counters, struct __counter_node *node);

private:
	void count_n_locked(struct __CounterList *counters, unsigned int n,
						struct list_head *task_list);
	struct rb_root counters_map_;
	std::mutex mutex_;

public:
	__CounterMap()
	{
		counters_map_.rb_node = NULL;
	}
} __counter_map;

class __WFCounterTask : public WFCounterTask
{
public:
	__WFCounterTask(unsigned int target_value, struct __CounterList *counters,
					std::function<void (WFCounterTask *)>&& cb) :
		WFCounterTask(1, std::move(cb)),
		counters_(counters)
	{
		node_.target_value = target_value;
		node_.task = this;
		counters_->push_back(&node_);
	}

	virtual ~__WFCounterTask()
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
	struct __CounterList *counters_;
	friend class __CounterMap;
};

WFCounterTask *__CounterMap::create(const std::string& name,
									unsigned int target_value,
									std::function<void (WFCounterTask *)>&& cb)
{
	if (target_value == 0)
		return new WFCounterTask(0, std::move(cb));

	struct rb_node **p = &counters_map_.rb_node;
	struct rb_node *parent = NULL;
	struct __CounterList *counters;
	std::lock_guard<std::mutex> lock(mutex_);

	while (*p)
	{
		parent = *p;
		counters = rb_entry(*p, struct __CounterList, rb);

		if (name < counters->name)
			p = &(*p)->rb_left;
		else if (name > counters->name)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (*p == NULL)
	{
		counters = new struct __CounterList(name);
		rb_link_node(&counters->rb, parent, p);
		rb_insert_color(&counters->rb, &counters_map_);
	}

	return new __WFCounterTask(target_value, counters, std::move(cb));
}

void __CounterMap::count_n_locked(struct __CounterList *counters,
								  unsigned int n, struct list_head *task_list)
{
	struct list_head *pos;
	struct list_head *tmp;
	struct __counter_node *node;

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
				rb_erase(&counters->rb, &counters_map_);
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

void __CounterMap::count_n(const std::string& name, unsigned int n)
{
	LIST_HEAD(task_list);
	struct __CounterList *counters;
	struct __counter_node *node;
	struct rb_node *p;

	mutex_.lock();
	p = counters_map_.rb_node;
	while (p)
	{
		counters = rb_entry(p, struct __CounterList, rb);
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

void __CounterMap::count(struct __CounterList *counters,
						 struct __counter_node *node)
{
	__WFCounterTask *task = NULL;

	mutex_.lock();
	if (--node->target_value == 0)
	{
		task = node->task;
		counters->del(node);
		if (counters->empty())
		{
			rb_erase(&counters->rb, &counters_map_);
			delete counters;
		}
	}

	mutex_.unlock();
	if (task)
		task->WFCounterTask::count();
}

void __CounterMap::remove(struct __CounterList *counters,
						  struct __counter_node *node)
{
	mutex_.lock();
	counters->del(node);
	if (counters->empty())
	{
		rb_erase(&counters->rb, &counters_map_);
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

class __WFConditional;

struct __conditional_node
{
	struct list_head list;
	__WFConditional *cond;
};

struct __ConditionalList
{
	__ConditionalList(const std::string& str):
		name(str)
	{
		INIT_LIST_HEAD(&this->head);
	}

	void push_back(struct __conditional_node *node)
	{
		list_add_tail(&node->list, &this->head);
	}

	bool empty() const
	{
		return list_empty(&this->head);
	}

	void del(struct __conditional_node *node)
	{
		list_del(&node->list);
	}

	struct rb_node rb;
	struct list_head head;
	std::string name;
	friend class __ConditionalMap;
};

static class __ConditionalMap
{
public:
	WFConditional *create(const std::string& name,
						  SubTask *task, void **msgbuf);

	WFConditional *create(const std::string& name, SubTask *task);

	void signal(const std::string& name, void *msg);
	void signal(struct __ConditionalList *conds,
				struct __conditional_node *node,
				void *msg);
	void remove(struct __ConditionalList *conds,
				struct __conditional_node *node);

private:
	struct __ConditionalList *get_list(const std::string& name);
	struct rb_root conds_map_;
	std::mutex mutex_;

public:
	__ConditionalMap()
	{
		conds_map_.rb_node = NULL;
	}
} __conditional_map;

class __WFConditional : public WFConditional
{
public:
	__WFConditional(SubTask *task, void **msgbuf,
					struct __ConditionalList *conds) :
		WFConditional(task, msgbuf),
		conds_(conds)
	{
		node_.cond = this;
		conds_->push_back(&node_);
	}

	__WFConditional(SubTask *task, struct __ConditionalList *conds) :
		WFConditional(task),
		conds_(conds)
	{
		node_.cond = this;
		conds_->push_back(&node_);
	}

	virtual ~__WFConditional()
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
	struct __ConditionalList *conds_;
	friend class __ConditionalMap;
};

WFConditional *__ConditionalMap::create(const std::string& name,
										SubTask *task, void **msgbuf)
{
	std::lock_guard<std::mutex> lock(mutex_);
	struct __ConditionalList *conds = get_list(name);
	return new __WFConditional(task, msgbuf, conds);
}

WFConditional *__ConditionalMap::create(const std::string& name,
										SubTask *task)
{
	std::lock_guard<std::mutex> lock(mutex_);
	struct __ConditionalList *conds = get_list(name);
	return new __WFConditional(task, conds);
}

struct __ConditionalList *__ConditionalMap::get_list(const std::string& name)
{
	struct rb_node **p = &conds_map_.rb_node;
	struct rb_node *parent = NULL;
	struct __ConditionalList *conds;

	while (*p)
	{
		parent = *p;
		conds = rb_entry(*p, struct __ConditionalList, rb);
		if (name < conds->name)
			p = &(*p)->rb_left;
		else if (name > conds->name)
			p = &(*p)->rb_right;
		else
			break;
	}

	if (*p == NULL)
	{
		conds = new struct __ConditionalList(name);
		rb_link_node(&conds->rb, parent, p);
		rb_insert_color(&conds->rb, &conds_map_);
	}

	return conds;
}

void __ConditionalMap::signal(const std::string& name, void *msg)
{
	struct __ConditionalList *conds;
	struct rb_node *p;

	mutex_.lock();
	p = conds_map_.rb_node;
	while (p)
	{
		conds = rb_entry(p, struct __ConditionalList, rb);
		if (name < conds->name)
			p = p->rb_left;
		else if (name > conds->name)
			p = p->rb_right;
		else
		{
			rb_erase(&conds->rb, &conds_map_);
			break;
		}
	}

	mutex_.unlock();
	if (!p)
		return;

	struct list_head *pos;
	struct list_head *tmp;
	struct __conditional_node *node;

	list_for_each_safe(pos, tmp, &conds->head)
	{
		node = list_entry(pos, struct __conditional_node, list);
		node->cond->WFConditional::signal(msg);
	}

	delete conds;
}

void __ConditionalMap::signal(struct __ConditionalList *conds,
							  struct __conditional_node *node,
							  void *msg)
{
	mutex_.lock();
	conds->del(node);
	if (conds->empty())
	{
		rb_erase(&conds->rb, &conds_map_);
		delete conds;
	}

	mutex_.unlock();
	node->cond->WFConditional::signal(msg);
}

void __ConditionalMap::remove(struct __ConditionalList *conds,
							  struct __conditional_node *node)
{
	mutex_.lock();
	conds->del(node);
	if (conds->empty())
	{
		rb_erase(&conds->rb, &conds_map_);
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

void WFTaskFactory::signal_by_name(const std::string& cond_name, void *msg)
{
	__conditional_map.signal(cond_name, msg);
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

