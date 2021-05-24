#ifndef _WFCONDITION_H_
#define _WFCONDITION_H_

#include "WFTask.h"
#include "WFGlobal.h"

class WFWaitTask : class WFCounterTask
{
public:
	WFWaitTask(std::function<void (WFCounterTask *)>&& cb) :
		WFCounterTask(1, std::move(cb))
	{}

protected:
	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		WFTimerTask *switch_task = WFTaskFactory::create_timer_task(0,
			[this](WFTimerTask *task){
				if (this->callback)
					this->callback(this);
		});
		series->push_front(switch_task);

		delete this;
		return series->pop();
	}
};

class WFTimedWaitTask : class __WFTimerTask
{
public:
	WFTimedWaitTask(WFWaitTask *wait_task, const struct timespec *value,
					CommScheduler *scheduler,
					std::function<void (WFTimerTask *)> cb) :
		__WFTimerTask(value, scheduler, std::move(cb))
	{
		this->wait_task = wait_task;
	}

protected:
	virtual SubTask *done()
	{
		if (wait_task)
			wati_task->count();
	}

private:
	WFWaitTask *wait_task;
};

class WFCondition
{
public:
	WFCounterTask *create_wait_task(std::function<void (WFCounterTask *)> cb)
	{
		WFWaitTask *task = new WFWaitTask(std::move(cb));
		pthread_mutex_lock(&this->mutex);
		this->waiter_list->push_back(task);
		pthread_mutex_unlock(&this->mutex);
		return task;
	}

	WFCounterTask *create_timed_wait_task(unsigned int microseconds,
										  std::function<void (WFCounterTask *)> cb)
	{
		WFWaitTask *waiter = new WFWaitTask(std::move(cb));
		struct timespec value = {
			.tv_sec     =   (time_t)(microseconds / 1000000),
			.tv_nsec    =   (long)(microseconds % 1000000 * 1000)
		};

		WFTimedWaitTask *task = new WFTimedWaitTask(waiter, &value,
													WFGlobal::get_scheduler(),
													nullptr); // maybe some stradegy

		task->dispatch();
		pthread_mutex_lock(&this->mutex);
		this->waiter_list->push_back(waiter);
		pthread_mutex_unlock(&this->mutex);

		return waiter;
	}

	void signal()
	{
		pthread_mutex_lock(&this->mutex);
		WFWaitTask *task = waiter_list->pop_front();

		if (task)
			task->count();

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

private:
	pthread_mutex_t mutex;
	std::list<WFCounterTask *> waiter_list;
};

#endif

