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

	bool del(T *node, rb_root *root)
	{
		list_del(&node->list);
		if (this->empty())
		{
			rb_erase(&this->rb, root);
			return true;
		}
		else
			return false;
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
	int n;

	while (*p)
	{
		parent = *p;
		objs = rb_entry(*p, T, rb);
		n = name.compare(objs->name);
		if (n < 0)
			p = &(*p)->rb_left;
		else if (n > 0)
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
	using TimerList = __NamedObjectList<struct __timer_node>;

public:
	WFTimerTask *create(const std::string& name,
						time_t seconds, long nanoseconds,
						CommScheduler *scheduler,
						timer_callback_t&& cb);

public:
	int cancel(const std::string& name, size_t max);

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
			bool erased = false;

			__timer_map.mutex_.lock();
			if (node_.task)
				erased = timers_->del(&node_, &__timer_map.root_);

			__timer_map.mutex_.unlock();
			if (erased)
				delete timers_;
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
		bool erased = false;

		__timer_map.mutex_.lock();
		if (node_.task)
		{
			erased = timers_->del(&node_, &__timer_map.root_);
			node_.task = NULL;
		}

		__timer_map.mutex_.unlock();
		if (erased)
			delete timers_;
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

int __NamedTimerMap::cancel(const std::string& name, size_t max)
{
	struct __timer_node *node;
	TimerList *timers;
	int ret = 0;

	mutex_.lock();
	timers = __get_object_list<TimerList>(name, &root_, false);
	if (timers)
	{
		while (1)
		{
			if (max == 0)
			{
				timers = NULL;
				break;
			}

			node = list_entry(timers->head.next, struct __timer_node, list);
			list_del(&node->list);
			if (node->task->flag_.exchange(true))
				node->task->cancel();

			node->task = NULL;
			max--;
			ret++;
			if (timers->empty())
			{
				rb_erase(&timers->rb, &root_);
				break;
			}
		}
	}

	mutex_.unlock();
	delete timers;
	return ret;
}

WFTimerTask *WFTaskFactory::create_timer_task(const std::string& name,
											  time_t seconds, long nanoseconds,
											  timer_callback_t callback)
{
	return __timer_map.create(name, seconds, nanoseconds,
							  WFGlobal::get_scheduler(),
							  std::move(callback));
}

int WFTaskFactory::cancel_by_name(const std::string& name, size_t max)
{
	return __timer_map.cancel(name, max);
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
	using CounterList = __NamedObjectList<struct __counter_node>;

public:
	WFCounterTask *create(const std::string& name, unsigned int target_value,
						  counter_callback_t&& cb);

	int count_n(const std::string& name, unsigned int n);
	void count(CounterList *counters, struct __counter_node *node);

	void remove(CounterList *counters, struct __counter_node *node)
	{
		bool erased;

		mutex_.lock();
		erased = counters->del(node, &root_);
		mutex_.unlock();
		if (erased)
			delete counters;
	}

private:
	bool count_n_locked(CounterList *counters, unsigned int n,
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

bool __NamedCounterMap::count_n_locked(CounterList *counters, unsigned int n,
									   struct list_head *task_list)
{
	struct __counter_node *node;

	while (n > 0)
	{
		node = list_entry(counters->head.next, struct __counter_node, list);
		if (n >= node->target_value)
		{
			n -= node->target_value;
			node->target_value = 0;
			list_move_tail(&node->list, task_list);
			if (counters->empty())
			{
				rb_erase(&counters->rb, &root_);
				return true;
			}
		}
		else
		{
			node->target_value -= n;
			break;
		}
	}

	return false;
}

int __NamedCounterMap::count_n(const std::string& name, unsigned int n)
{
	LIST_HEAD(task_list);
	struct __counter_node *node;
	CounterList *counters;
	bool erased = false;
	int ret = 0;

	mutex_.lock();
	counters = __get_object_list<CounterList>(name, &root_, false);
	if (counters)
		erased = count_n_locked(counters, n, &task_list);

	mutex_.unlock();
	if (erased)
		delete counters;

	while (!list_empty(&task_list))
	{
		node = list_entry(task_list.next, struct __counter_node, list);
		list_del(&node->list);
		node->task->WFCounterTask::count();
		ret++;
	}

	return ret;
}

void __NamedCounterMap::count(CounterList *counters,
							  struct __counter_node *node)
{
	__WFNamedCounterTask *task = NULL;
	bool erased = false;

	mutex_.lock();
	if (--node->target_value == 0)
	{
		task = node->task;
		erased = counters->del(node, &root_);
	}

	mutex_.unlock();
	if (erased)
		delete counters;

	if (task)
		task->WFCounterTask::count();
}

WFCounterTask *WFTaskFactory::create_counter_task(const std::string& name,
												  unsigned int target_value,
												  counter_callback_t callback)
{
	return __counter_map.create(name, target_value, std::move(callback));
}

int WFTaskFactory::count_by_name(const std::string& name, unsigned int n)
{
	return __counter_map.count_n(name, n);
}

/****************** Named Mailbox ******************/

class __WFNamedMailboxTask;

struct __mailbox_node
{
	struct list_head list;
	__WFNamedMailboxTask *task;
};

static class __NamedMailboxMap
{
public:
	using MailboxList = __NamedObjectList<struct __mailbox_node>;

public:
	WFMailboxTask *create(const std::string& name, void **mailbox,
						  mailbox_callback_t&& cb);
	WFMailboxTask *create(const std::string& name, mailbox_callback_t&& cb);

	int send(const std::string& name, void *msg, size_t max);
	void send(MailboxList *mailboxes, struct __mailbox_node *node, void *msg);

	void remove(MailboxList *mailboxes, struct __mailbox_node *node)
	{
		bool erased;

		mutex_.lock();
		erased = mailboxes->del(node, &root_);
		mutex_.unlock();
		if (erased)
			delete mailboxes;
	}

private:
	bool send_max_locked(MailboxList *mailboxes, void *msg, size_t max,
						 struct list_head *task_list);
	struct rb_root root_;
	std::mutex mutex_;

public:
	__NamedMailboxMap()
	{
		root_.rb_node = NULL;
	}
} __mailbox_map;

class __WFNamedMailboxTask : public WFMailboxTask
{
public:
	__WFNamedMailboxTask(void **mailbox, mailbox_callback_t&& cb) :
		WFMailboxTask(mailbox, std::move(cb))
	{
		node_.task = this;
	}

	__WFNamedMailboxTask(mailbox_callback_t&& cb) :
		WFMailboxTask(std::move(cb))
	{
		node_.task = this;
	}

	void push_to(__NamedMailboxMap::MailboxList *mailboxes)
	{
		mailboxes->push_back(&node_);
		mailboxes_ = mailboxes;
	}

	virtual void send(void *msg)
	{
		__mailbox_map.send(mailboxes_, &node_, msg);
	}

	virtual ~__WFNamedMailboxTask()
	{
		if (!this->flag)
			__mailbox_map.remove(mailboxes_, &node_);
	}

private:
	struct __mailbox_node node_;
	__NamedMailboxMap::MailboxList *mailboxes_;
};

WFMailboxTask *__NamedMailboxMap::create(const std::string& name,
										 void **mailbox,
										 mailbox_callback_t&& cb)
{
	auto *task = new __WFNamedMailboxTask(mailbox, std::move(cb));
	mutex_.lock();
	task->push_to(__get_object_list<MailboxList>(name, &root_, true));
	mutex_.unlock();
	return task;
}

WFMailboxTask *__NamedMailboxMap::create(const std::string& name,
										 mailbox_callback_t&& cb)
{
	auto *task = new __WFNamedMailboxTask(std::move(cb));
	mutex_.lock();
	task->push_to(__get_object_list<MailboxList>(name, &root_, true));
	mutex_.unlock();
	return task;
}

bool __NamedMailboxMap::send_max_locked(MailboxList *mailboxes,
										void *msg, size_t max,
										struct list_head *task_list)
{
	if (max == (size_t)-1)
		list_splice(&mailboxes->head, task_list);
	else
	{
		do
		{
			if (max == 0)
				return false;

			list_move_tail(mailboxes->head.next, task_list);
			max--;
		} while (!mailboxes->empty());
	}

	rb_erase(&mailboxes->rb, &root_);
	return true;
}

int __NamedMailboxMap::send(const std::string& name, void *msg, size_t max)
{
	LIST_HEAD(task_list);
	struct __mailbox_node *node;
	MailboxList *mailboxes;
	bool erased = false;
	int ret = 0;

	mutex_.lock();
	mailboxes = __get_object_list<MailboxList>(name, &root_, false);
	if (mailboxes)
		erased = send_max_locked(mailboxes, msg, max, &task_list);

	mutex_.unlock();
	if (erased)
		delete mailboxes;

	while (!list_empty(&task_list))
	{
		node = list_entry(task_list.next, struct __mailbox_node, list);
		list_del(&node->list);
		node->task->WFMailboxTask::send(msg);
		ret++;
	}

	return ret;
}

void __NamedMailboxMap::send(MailboxList *mailboxes,
							 struct __mailbox_node *node,
							 void *msg)
{
	bool erased;

	mutex_.lock();
	erased = mailboxes->del(node, &root_);
	mutex_.unlock();
	if (erased)
		delete mailboxes;

	node->task->WFMailboxTask::send(msg);
}

WFMailboxTask *WFTaskFactory::create_mailbox_task(const std::string& name,
												  void **mailbox,
												  mailbox_callback_t callback)
{
	return __mailbox_map.create(name, mailbox, std::move(callback));
}

WFMailboxTask *WFTaskFactory::create_mailbox_task(const std::string& name,
												  mailbox_callback_t callback)
{
	return __mailbox_map.create(name, std::move(callback));
}

int WFTaskFactory::send_by_name(const std::string& name, void *msg, size_t max)
{
	return __mailbox_map.send(name, msg, max);
}

/****************** Named Conditional ******************/

class __WFNamedConditional;

struct __conditional_node
{
	struct list_head list;
	__WFNamedConditional *cond;
};

static class __NamedConditionalMap
{
public:
	using ConditionalList = __NamedObjectList<struct __conditional_node>;

public:
	WFConditional *create(const std::string& name, SubTask *task,
						  void **msgbuf);
	WFConditional *create(const std::string& name, SubTask *task);

	int signal(const std::string& name, void *msg, size_t max);
	void signal(ConditionalList *conds, struct __conditional_node *node,
				void *msg);

	void remove(ConditionalList *conds, struct __conditional_node *node)
	{
		bool erased;

		mutex_.lock();
		erased = conds->del(node, &root_);
		mutex_.unlock();
		if (erased)
			delete conds;
	}

private:
	bool signal_max_locked(ConditionalList *conds, void *msg, size_t max,
						   struct list_head *cond_list);
	struct rb_root root_;
	std::mutex mutex_;

public:
	__NamedConditionalMap()
	{
		root_.rb_node = NULL;
	}
} __conditional_map;

class __WFNamedConditional : public WFConditional
{
public:
	__WFNamedConditional(SubTask *task, void **msgbuf) :
		WFConditional(task, msgbuf)
	{
		node_.cond = this;
	}

	__WFNamedConditional(SubTask *task) :
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

	virtual ~__WFNamedConditional()
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
	auto *cond = new __WFNamedConditional(task, msgbuf);
	mutex_.lock();
	cond->push_to(__get_object_list<ConditionalList>(name, &root_, true));
	mutex_.unlock();
	return cond;
}

WFConditional *__NamedConditionalMap::create(const std::string& name,
											 SubTask *task)
{
	auto *cond = new __WFNamedConditional(task);
	mutex_.lock();
	cond->push_to(__get_object_list<ConditionalList>(name, &root_, true));
	mutex_.unlock();
	return cond;
}

bool __NamedConditionalMap::signal_max_locked(ConditionalList *conds,
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
				return false;

			list_move_tail(conds->head.next, cond_list);
			max--;
		} while (!conds->empty());
	}

	rb_erase(&conds->rb, &root_);
	return true;
}

int __NamedConditionalMap::signal(const std::string& name, void *msg, size_t max)
{
	LIST_HEAD(cond_list);
	struct __conditional_node *node;
	ConditionalList *conds;
	bool erased = false;
	int ret = 0;

	mutex_.lock();
	conds = __get_object_list<ConditionalList>(name, &root_, false);
	if (conds)
		erased = signal_max_locked(conds, msg, max, &cond_list);

	mutex_.unlock();
	if (erased)
		delete conds;

	while (!list_empty(&cond_list))
	{
		node = list_entry(cond_list.next, struct __conditional_node, list);
		list_del(&node->list);
		node->cond->WFConditional::signal(msg);
		ret++;
	}

	return ret;
}

void __NamedConditionalMap::signal(ConditionalList *conds,
								   struct __conditional_node *node,
								   void *msg)
{
	bool erased;

	mutex_.lock();
	erased = conds->del(node, &root_);
	mutex_.unlock();
	if (erased)
		delete conds;

	node->cond->WFConditional::signal(msg);
}

WFConditional *WFTaskFactory::create_conditional(const std::string& name,
												 SubTask *task, void **msgbuf)
{
	return __conditional_map.create(name, task, msgbuf);
}

WFConditional *WFTaskFactory::create_conditional(const std::string& name,
												 SubTask *task)
{
	return __conditional_map.create(name, task);
}

int WFTaskFactory::signal_by_name(const std::string& name, void *msg,
								   size_t max)
{
	return __conditional_map.signal(name, msg, max);
}

/****************** Named Guard ******************/

class __WFNamedGuard;

struct __guard_node
{
	struct list_head list;
	__WFNamedGuard *guard;
};

static class __NamedGuardMap
{
public:
	struct GuardList : public __NamedObjectList<struct __guard_node>
	{
		GuardList(const std::string& name) : __NamedObjectList(name)
		{
			acquired = false;
			refcnt = 0;
		}

		bool acquired;
		size_t refcnt;
		std::mutex mutex;
	};

public:
	WFConditional *create(const std::string& name, SubTask *task);
	WFConditional *create(const std::string& name, SubTask *task,
						  void **msgbuf);

	struct __guard_node *release(const std::string& name);

	void unref(GuardList *guards)
	{
		mutex_.lock();
		if (--guards->refcnt == 0)
			rb_erase(&guards->rb, &root_);
		else
			guards = NULL;

		mutex_.unlock();
		delete guards;
	}

private:
	struct rb_root root_;
	std::mutex mutex_;

public:
	__NamedGuardMap()
	{
		root_.rb_node = NULL;
	}
} __guard_map;

class __WFNamedGuard : public WFConditional
{
public:
	__WFNamedGuard(SubTask *task) : WFConditional(task)
	{
		node_.guard = this;
	}

	__WFNamedGuard(SubTask *task, void **msgbuf) : WFConditional(task, msgbuf)
	{
		node_.guard = this;
	}

	virtual ~__WFNamedGuard()
	{
		if (!this->flag)
			__guard_map.unref(guards_);
	}

	SubTask *get_task() const { return this->task; }

	void set_task(SubTask *task) { this->task = task; }

protected:
	virtual void dispatch();
	virtual void signal(void *msg) { }

private:
	struct __guard_node node_;
	__NamedGuardMap::GuardList *guards_;
	friend __NamedGuardMap;
};

void __WFNamedGuard::dispatch()
{
	guards_->mutex.lock();
	if (guards_->acquired)
		guards_->push_back(&node_);
	else
	{
		guards_->acquired = true;
		this->WFConditional::signal(NULL);
	}

	guards_->mutex.unlock();
	this->WFConditional::dispatch();
}

WFConditional *__NamedGuardMap::create(const std::string& name,
									   SubTask *task)
{
	auto *guard = new __WFNamedGuard(task);
	mutex_.lock();
	guard->guards_ = __get_object_list<GuardList>(name, &root_, true);
	guard->guards_->refcnt++;
	mutex_.unlock();
	return guard;
}

WFConditional *__NamedGuardMap::create(const std::string& name,
									   SubTask *task, void **msgbuf)
{
	auto *guard = new __WFNamedGuard(task, msgbuf);
	mutex_.lock();
	guard->guards_ = __get_object_list<GuardList>(name, &root_, true);
	guard->guards_->refcnt++;
	mutex_.unlock();
	return guard;
}

struct __guard_node *__NamedGuardMap::release(const std::string& name)
{
	struct __guard_node *node = NULL;
	GuardList *guards;

	mutex_.lock();
	guards = __get_object_list<GuardList>(name, &root_, false);
	if (guards)
	{
		if (--guards->refcnt == 0)
			rb_erase(&guards->rb, &root_);
		else
		{
			guards->mutex.lock();
			if (!guards->empty())
			{
				node = list_entry(guards->head.next, struct __guard_node, list);
				list_del(&node->list);
			}
			else
				guards->acquired = false;

			guards->mutex.unlock();
			guards = NULL;
		}
	}

	mutex_.unlock();
	delete guards;
	return node;
}

WFConditional *WFTaskFactory::create_guard(const std::string& name,
										   SubTask *task)
{
	return __guard_map.create(name, task);
}

WFConditional *WFTaskFactory::create_guard(const std::string& name,
										   SubTask *task, void **msgbuf)
{
	return __guard_map.create(name, task, msgbuf);
}

int WFTaskFactory::release_guard(const std::string& name, void *msg)
{
	struct __guard_node *node = __guard_map.release(name);

	if (!node)
		return 0;

	node->guard->WFConditional::signal(msg);
	return 1;
}

int WFTaskFactory::release_guard_safe(const std::string& name, void *msg)
{
	struct __guard_node *node = __guard_map.release(name);
	WFTimerTask *timer;

	if (!node)
		return 0;

	timer = WFTaskFactory::create_timer_task(0, 0, [](WFTimerTask *timer) {
		series_of(timer)->push_front((SubTask *)timer->user_data);
	});
	timer->user_data = node->guard->get_task();
	node->guard->set_task(timer);
	node->guard->WFConditional::signal(msg);
	return 1;
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
		if (timer->get_state() == WFT_STATE_SUCCESS)
		{
			task->state = WFT_STATE_SYS_ERROR;
			task->error = ETIMEDOUT;
		}
		else
		{
			task->state = timer->get_state();
			task->error = timer->get_error();
		}

		task->subtask_done();
	}

	if (--task->ref == 0)
		delete task;
}

