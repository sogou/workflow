#ifndef _WFCHANNEL_H_
#define _WFCHANNEL_H_

#include "CommScheduler.h"
#include "TransRequest.h"
#include "Workflow.h"

template<class MESSAGE>
class ChanTask : public TransRequest
{
public:
/*
	void start()
	{
		assert(!series_of(this));
		Workflow::start_series_work(this, nullptr);
	}
*/
	void dismiss()
	{
		assert(!series_of(this));
		delete this;
	}

	MESSAGE *get_message()
	{
		return &this->message;
	}

	int get_state() const { return this->state; }
	int get_error() const { return this->error; }
	void *user_data;

public:
	ChanTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (ChanTask<MESSAGE> *)>&& cb) :
		TransRequest(channel, scheduler)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (this->callback)
			this->callback(this);

		delete this;
		return series->pop();
	}
/*
	virtual MESSAGE *message_out()
	{
		return &this->message;
	}
*/
private:
	MESSAGE message;

protected:
	std::function<void (ChanTask<MESSAGE> *)> callback;
};

template<class MESSAGE>
class ChanPassiveTask : public ChanTask
{
public:
	ChanPassiveTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (ChanTask<MESSAGE> *)>&& cb,
				std::function<void (ChanTask<MESSAGE> *)>& proc) :
		ChanTask(channel, scheduler, std::move(cb)),
		process(proc)
	{
	}

	virtual void dispatch()
	{
		this->process(this);
		this->subtask_done();
	}

	void set_callback(std::function<void (ChanTask<MESSAGE> *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	std::function<void (ChanTask<MESSAGE> *)>& process;
};

template<class IN>
class WFChannel : public ChanRequest
{
public:
	WFChannel(CommSchedObject *object, CommScheduler *scheduler,
			  std::function<void (ChanTask<IN> *)>&& process) :
		ChanRequest(object, scheduler),
		process(std::move(process))
	{
		this->session = NULL;
	}
/*
	virtual ChanTask<OUT> *create_task(std::function<void (ChanTask<OUT> *)>&& cb)
	{
		return new ChanTask<OUT>(this, this->scheduler, std::move(cb));
	}
*/
	virtual CommMessageIn *message_in()
	{
		this->session = this->new_session();
		return task->get_message();
	}

//	virtual ~WFChannel() {}

protected:
	virtual ChanTask<IN> *new_session()
	{
		return new ChanPassiveTask<IN>(this, this->scheduler, nullptr, this->process);
//		Workflow::create_series_work(task, nullptr);
	}

	virtual void handle_in(CommMessageIn *in)
	{
		if (this->session)
			this->session->dispatch();
		this->session = NULL;
	}

protected:
	TransRequest *session;
	std::function<void (ChanTask<IN> *)> process;
};

#endif

