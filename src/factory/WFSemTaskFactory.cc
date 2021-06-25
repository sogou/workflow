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
#include "WFTaskFactory.h"
#include "WFGlobal.h"
#include "WFSemTaskFactory.h"

class __WFCondition : public WFCondition
{
public:
	__WFCondition(const std::string& str) :
		name(str)
	{
		this->node.ptr = this;
	}

public:
	struct entry
	{
		struct rb_node rb;
		__WFCondition *ptr;
	} node;

	std::string name;
};

class __ConditionMap
{
public:
	void signal(const std::string& name, void *msg);
	void broadcast(const std::string& name, void *msg);

	WFWaitTask *create(const std::string& name,
						  wait_callback_t&& cb);
	WFWaitTask *create(const std::string& name,
						  const struct timespec *abstime,
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

	return WFSemTaskFactory::create_wait_task(cond, std::move(cb));
}

WFWaitTask *__ConditionMap::create(const std::string& name,
									  const struct timespec *abstime,
									  wait_callback_t&& cb)
{
	__WFCondition *cond = this->find_condition(name);

	return WFSemTaskFactory::create_timedwait_task(cond, abstime,
												   std::move(cb));
}

__ConditionMap::~__ConditionMap()
{
	__WFCondition *cond;
	WFCondWaitTask *task;
	struct list_head *pos;
	struct list_head *tmp;
	struct WFSemaphoreTask::entry *node;
	struct __WFCondition::entry *cond_node;

	while (this->condition_map.rb_node)
	{
		cond_node = rb_entry(this->condition_map.rb_node,
							 struct __WFCondition::entry, rb);
		cond = cond_node->ptr;

		list_for_each_safe(pos, tmp, &cond->waiter_list)
		{
			node = list_entry(pos, struct WFSemaphoreTask::entry, list);
			task = (WFCondWaitTask *)node->ptr;
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
	struct __WFCondition::entry *cond_node;
	struct rb_node **p = &this->condition_map.rb_node;
	struct rb_node *parent = NULL;

	this->mutex.lock();
	while (*p)
	{
		parent = *p;
		cond_node = rb_entry(*p, struct __WFCondition::entry, rb);
		cond = cond_node->ptr;

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
		rb_link_node(&cond->node.rb, parent, p);
		rb_insert_color(&cond->node.rb, &this->condition_map);
	}

	this->mutex.unlock();

	return cond;
}

/////////////// factory api ///////////////

void WFSemTaskFactory::signal_by_name(const std::string& name, void *msg)
{
	return __ConditionMap::get_instance()->signal(name, msg);
}

void WFSemTaskFactory::broadcast_by_name(const std::string& name, void *msg)
{
	return __ConditionMap::get_instance()->broadcast(name, msg);
}

WFWaitTask *WFSemTaskFactory::create_wait_task(const std::string& name,
												  wait_callback_t callback)
{
	return __ConditionMap::get_instance()->create(name, std::move(callback));
}

WFWaitTask *WFSemTaskFactory::create_timedwait_task(const std::string& name,
													   const struct timespec *abstime,
													   wait_callback_t callback)
{
	return __ConditionMap::get_instance()->create(name, abstime,
												  std::move(callback));
}

WFWaitTask *WFSemTaskFactory::create_wait_task(WFCondition *cond,
												  wait_callback_t callback)
{
	WFCondWaitTask *task = new WFCondWaitTask(std::move(callback));

	cond->mutex.lock();
	list_add_tail(&task->node.list, &cond->waiter_list);
	cond->mutex.unlock();

	return task;
}

WFWaitTask *WFSemTaskFactory::create_timedwait_task(WFCondition *cond,
													   const struct timespec *abstime,
													   wait_callback_t callback)
{
	WFCondWaitTask *waiter = new WFCondWaitTask(std::move(callback));
	WFTimedWaitTask *task = new WFTimedWaitTask(waiter, &cond->mutex, abstime,
												WFGlobal::get_scheduler(),
												nullptr);
	waiter->set_timer(task);

	cond->mutex.lock();
	list_add_tail(&waiter->node.list, &cond->waiter_list);
	cond->mutex.unlock();

	return waiter;
}

