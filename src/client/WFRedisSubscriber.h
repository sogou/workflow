#include <string>
#include <vector>
#include <utility>
#include <functional>
#include <atomic>
#include <mutex>
#include "WFTask.h"
#include "WFTaskFactory.h"

class WFRedisSubscribeTask : public WFGenericTask
{
pubilc:
	int subscribe(const std::vector<std::string>& channels);
	int unsubscribe(const std::vector<std::string>& channels);
	int unsubscribe_all();

	int psubscribe(const std::vector<std::string>& patterns);
	int punsubscribe(const std::vector<std::string>& patterns);
	int punsubscribe_all();

public:
	/* User needs to call 'release()' exactly once. */
	void release()
	{
		if (this->flag.exchange(true))
			delete this;
	}

protected:
	virtual void dispatch()
	{
		series_of(this)->push_front(this->task);
		this->subtask_done();
	}

	virtual SubTask *done()
	{
		return series_of(this)->pop();
	}

protected:
	WFRedisTask *task;
	std::mutex mutex;
	std::atomic<bool> flag;
	std::function<void (WFRedisSubscribeTask *)> callback;

protected:
	static void task_callback(WFRedisTask *task)
	{
		auto *t = (WFRedisSubscribeTask *)task->user_data;

		t->mutex.lock();
		t->task = NULL;
		t->mutex.unlock();

		t->state = task->get_state();
		t->error = task->get_error();
		t->callback(t);
		t->release();
	}

public:
	WFRedisSubscribeTask(WFRedisTask *task,
						 std::function<void (WFRedisSubscribeTask *)>&& cb) :
		flag(false),
		callback(std::move(cb))
	{
		task->user_data = this;
		task->set_callback(WFRedisSubscribeTask::redis_task_callback);
		this->task = task;
	}

protected:
	virtual ~WFRedisSubscribeTask()
	{
		if (this->task)
			this->task->dismiss();
	}
};

