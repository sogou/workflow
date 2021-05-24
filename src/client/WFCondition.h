#ifndef _WFCONDITION_H_
#define _WFCONDITION_H_

#include "list.h"
#include "WFTask.h"
#include "WFGlobal.h"

class WFTimedWaitTask;
class WFCondition;

class WFWaitTask : class WFCounterTask
{
public:
	WFWaitTask(std::function<void (WFCounterTask *)>&& cb) :
		WFCounterTask(1, std::move(cb))
	{
		this->timer = NULL;
		this->list.next = NULL;
	}

protected:
	virtual SubTask *done()
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

public:
	void set_timer(WFTimedWaitTask *timer) { this->timer = timer; }
	void clear_timer_waiter()
	{
		if (this->timer)
			timer->clear_waiter_task();
	}

public:
	struct list_head list;

private:
	WFTimedWaitTask *timer;
};

class WFTimedWaitTask : class __WFTimerTask
{
public:
	WFTimedWaitTask(WFWaitTask *wait_task, WFCondition *condition,
					const struct timespec *value,
					CommScheduler *scheduler,
					std::function<void (WFTimerTask *)> cb) :
		__WFTimerTask(value, scheduler, std::move(cb))
	{
		this->mutex = mutex;
		this->wait_task = wait_task;
	}

protected:
	virtual SubTask *done()
	{
		pthread_mutex_lock(&this->condition.mutex);
		if (this->condition->remove_waiter(this->wait_task))
			wati_task->count();
		pthread_mutex_unlock(&this->condition.mutex);
	}

pulbic:
	void clear_wait_task()
	{
		this->wait_task = NULL;
	}

private:
	WFCondition *condition;
	WFCounterTask *wait_task;
};

class WFCondition
{
public:
	WFCondition() :
		mutex(PTHREAD_MUTEX_INITIALIZER)
	{
		INIT_LIST_HEAD(this->waiter_list);
	}

	WFCounterTask *create_wait_task(std::function<void (WFCounterTask *)> cb)
	{
		WFWaitTask *task = new WFWaitTask(std::move(cb));
		pthread_mutex_lock(&this->mutex);
		this->waiter_list->push_back(task);
		pthread_mutex_unlock(&this->mutex);
		return task;
	}

	WFCounterTask *create_timedwait_task(unsigned int microseconds,
										 std::function<void (WFCounterTask *)> cb)
	{
		WFWaitTask *waiter = new WFWaitTask(std::move(cb));
		struct timespec value = {
			.tv_sec     =   (time_t)(microseconds / 1000000),
			.tv_nsec    =   (long)(microseconds % 1000000 * 1000)
		};

		WFTimedWaitTask *task = new WFTimedWaitTask(waiter, this,
													&value,
													WFGlobal::get_scheduler(),
													nullptr); //
		waiter->set_timer(task);

		pthread_mutex_lock(&this->mutex);
		this->waiter_list->push_back(waiter);
		pthread_mutex_unlock(&this->mutex);

		task->dispatch();

		return waiter;
	}

	void signal()
	{
		pthread_mutex_lock(&this->mutex);
		WFWaiterTask *task = waiter_list->pop_front();

		if (task)
		{
			task->clear_timer_waiter();
			task->count();
		}

		pthread_mutex_unlock(&this->mutex);
	}

	void broadcast()
	{
		pthread_mutex_lock(&this->mutex);
		WFWaitTask *task = waiter_list->pop_front();

		while (task)
		{
			task->count();
			task = waiter_list->pop_front();
		}

		pthread_mutex_unlock(&this->mutex);
	}

	bool remove_waiter(WFCounterTask *task)
	{
		if (task->list.next)
		{
			list_del(&task->list);
			task->list.next = NULL;
		}
		// remove from list without mutex
	}

public:
	pthread_mutex_t mutex;

private:
	struct list_head waiter_list;
};

#endif

