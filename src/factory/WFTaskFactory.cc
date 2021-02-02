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
#include <string>
#include <mutex>
#include "list.h"
#include "rbtree.h"
#include "WFGlobal.h"
#include "WFTaskFactory.h"

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

class __CounterMap
{
public:
	static __CounterMap *get_instance()
	{
		static __CounterMap kInstance;
		return &kInstance;
	}

	WFCounterTask *create(const std::string& name, unsigned int target_value,
						  std::function<void (WFCounterTask *)>&& cb);

	void count_n(const std::string& name, unsigned int n);
	void count(struct __CounterList *counters, struct __counter_node *node);
	void remove(struct __CounterList *counters, struct __counter_node *node);

	virtual ~__CounterMap();

private:
	void count_n_locked(struct __CounterList *counters, unsigned int n,
						struct list_head *task_list);
	__CounterMap()
	{
		counters_map_.rb_node = NULL;
	}

	struct rb_root counters_map_;
	std::mutex mutex_;
};

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
			__CounterMap::get_instance()->remove(counters_, &node_);
	}

	virtual void count()
	{
		__CounterMap::get_instance()->count(counters_, &node_);
	}

private:
	struct __counter_node node_;
	struct __CounterList *counters_;
	friend class __CounterMap;
};

__CounterMap::~__CounterMap()
{
	struct __CounterList *counters;
	struct __counter_node *node;
	struct list_head *pos;
	struct list_head *tmp;

	while (counters_map_.rb_node)
	{
		counters = rb_entry(counters_map_.rb_node, struct __CounterList, rb);
		list_for_each_safe(pos, tmp, &counters->head)
		{
			node = list_entry(pos, struct __counter_node, list);
			counters->del(node);
			delete node->task;
		}

		rb_erase(counters_map_.rb_node, &counters_map_);
		delete counters;
	}
}

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
	struct rb_node **p = &counters_map_.rb_node;
	struct __CounterList *counters;
	struct __counter_node *node;
	LIST_HEAD(task_list);

	mutex_.lock();
	while (*p)
	{
		counters = rb_entry(*p, struct __CounterList, rb);

		if (name < counters->name)
			p = &(*p)->rb_left;
		else if (name > counters->name)
			p = &(*p)->rb_right;
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
	return __CounterMap::get_instance()->create(counter_name, target_value,
												std::move(callback));
}

void WFTaskFactory::count_by_name(const std::string& counter_name, unsigned int n)
{
	__CounterMap::get_instance()->count_n(counter_name, n);
}

WFDNSTask *WFTaskFactory::create_dns_task(const std::string& host,
										  unsigned short port,
										  dns_callback_t callback)
{
	auto *task = WFThreadTaskFactory<DNSInput, DNSOutput>::
						create_thread_task(WFGlobal::get_dns_queue(),
										   WFGlobal::get_dns_executor(),
										   DNSRoutine::run,
										   std::move(callback));

	task->get_input()->reset(host, port);
	return task;
}

/********FileIOTask*************/

class WFFilepreadTask : public WFFileIOTask
{
public:
	WFFilepreadTask(int fd, void *buf, size_t count, off_t offset,
					IOService *service, fio_callback_t&& cb) :
		WFFileIOTask(service, std::move(cb))
	{
		this->args.fd = fd;
		this->args.buf = buf;
		this->args.count = count;
		this->args.offset = offset;
	}

	virtual int prepare()
	{
		this->prep_pread(this->args.fd, this->args.buf, this->args.count,
						 this->args.offset);
		return 0;
	}
};

class WFFilepwriteTask : public WFFileIOTask
{
public:
	WFFilepwriteTask(int fd, const void *buf, size_t count, off_t offset,
					 IOService *service, fio_callback_t&& cb) :
		WFFileIOTask(service, std::move(cb))
	{
		this->args.fd = fd;
		this->args.buf = (void *)buf;
		this->args.count = count;
		this->args.offset = offset;
	}

	virtual int prepare()
	{
		this->prep_pwrite(this->args.fd, this->args.buf, this->args.count,
						  this->args.offset);
		return 0;
	}
};

class WFFilepreadvTask : public WFFileVIOTask
{
public:
	WFFilepreadvTask(int fd, const struct iovec *iov, int iovcnt, off_t offset,
					 IOService *service, fvio_callback_t&& cb) :
		WFFileVIOTask(service, std::move(cb))
	{
		this->args.fd = fd;
		this->args.iov = iov;
		this->args.iovcnt = iovcnt;
		this->args.offset = offset;
	}

	virtual int prepare()
	{
		this->prep_preadv(this->args.fd, this->args.iov, this->args.iovcnt,
						  this->args.offset);
		return 0;
	}
};

class WFFilepwritevTask : public WFFileVIOTask
{
public:
	WFFilepwritevTask(int fd, const struct iovec *iov, int iovcnt, off_t offset,
					  IOService *service, fvio_callback_t&& cb) :
		WFFileVIOTask(service, std::move(cb))
	{
		this->args.fd = fd;
		this->args.iov = iov;
		this->args.iovcnt = iovcnt;
		this->args.offset = offset;
	}

	virtual int prepare()
	{
		this->prep_pwritev(this->args.fd, this->args.iov, this->args.iovcnt,
						   this->args.offset);
		return 0;
	}
};

class WFFilefsyncTask : public WFFileSyncTask
{
public:
	WFFilefsyncTask(int fd, IOService *service, fsync_callback_t&& cb) :
		WFFileSyncTask(service, std::move(cb))
	{
		this->args.fd = fd;
	}

	virtual int prepare()
	{
		this->prep_fsync(this->args.fd);
		return 0;
	}
};

class WFFilefdsyncTask : public WFFileSyncTask
{
public:
	WFFilefdsyncTask(int fd, IOService *service, fsync_callback_t&& cb) :
		WFFileSyncTask(service, std::move(cb))
	{
		this->args.fd = fd;
	}

	virtual int prepare()
	{
		this->prep_fdsync(this->args.fd);
		return 0;
	}
};

WFFileIOTask *WFTaskFactory::create_pread_task(int fd,
											   void *buf,
											   size_t count,
											   off_t offset,
											   fio_callback_t callback)
{
	return new WFFilepreadTask(fd, buf, count, offset,
							   WFGlobal::get_io_service(),
							   std::move(callback));
}

WFFileIOTask *WFTaskFactory::create_pwrite_task(int fd,
												const void *buf,
												size_t count,
												off_t offset,
												fio_callback_t callback)
{
	return new WFFilepwriteTask(fd, buf, count, offset,
								WFGlobal::get_io_service(),
								std::move(callback));
}

WFFileVIOTask *WFTaskFactory::create_preadv_task(int fd,
												 const struct iovec *iovec,
												 int iovcnt,
												 off_t offset,
												 fvio_callback_t callback)
{
	return new WFFilepreadvTask(fd, iovec, iovcnt, offset,
								WFGlobal::get_io_service(),
								std::move(callback));
}

WFFileVIOTask *WFTaskFactory::create_pwritev_task(int fd,
												  const struct iovec *iovec,
												  int iovcnt,
												  off_t offset,
												  fvio_callback_t callback)
{
	return new WFFilepwritevTask(fd, iovec, iovcnt, offset,
								 WFGlobal::get_io_service(),
								 std::move(callback));
}

WFFileSyncTask *WFTaskFactory::create_fsync_task(int fd,
												 fsync_callback_t callback)
{
	return new WFFilefsyncTask(fd,
							   WFGlobal::get_io_service(),
							   std::move(callback));
}

WFFileSyncTask *WFTaskFactory::create_fdsync_task(int fd,
												  fsync_callback_t callback)
{
	return new WFFilefdsyncTask(fd,
								WFGlobal::get_io_service(),
								std::move(callback));
}

