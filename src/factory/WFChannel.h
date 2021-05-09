#ifndef _WFCHANNEL_H_
#define _WFCHANNEL_H_

#include "Communicator.h"
#include "CommScheduler.h"
#include "ChannelRequest.h"
#include "Workflow.h"

#define CHANNEL_STATE_UNDEFINED		-1
#define CHANNEL_STATE_ESTABLISHED	0
#define CHANNEL_STATE_ERROR			CS_STATE_ERROR
#define CHANNEL_STATE_STOPPED		CS_STATE_STOPPED
#define CHANNEL_STATE_SHUTDOWN		CS_STATE_SHUTDOWN
/*
class WFEstablishTask : public EstablishSession
{
public:
	WFEstablishTask(CommChannel *channel,
					CommScheduler *scheduler,
					CommSchedObject *object,
					int wait_timeout,
					CommTarget **target,
					std::function<void (WFEstablishTask *)> cb) :
		EstablishSession(channel, scheduler, object, wait_timeout, target)
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

private:
	std::function<void (WFEstablishTask *)> callback;
};
*/

template<class MESSAGE>
class TransTask : public TransRequest
{
public:
	void start() //
	{
		assert(!series_of(this));
		Workflow::start_series_work(this, nullptr);
	}

	void dismiss() //
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
	// OUT TASK
	TransTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (TransTask<MESSAGE> *)>&& cb) :
		TransRequest(channel, scheduler)
	{
		this->process = NULL;
		this->callback = std::move(cb);
	}

	// IN TASK
	TransTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (TransTask<MESSAGE> *)> *process,
				std::function<void (TransTask<MESSAGE> *)>&& cb) :
		ChannelRequest(channel, scheduler)
	{
		this->process = process;
		this->callback = std::move(cb);
	}

	void set_callback(std::function<void (TransTask<MESSAGE> *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual void dispatch()
	{
		if (this->process) // passive
		{
			(*process)(this);
			this->subtask_done();
		}
		else
			TransRequest::dispatch();
	}

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (this->callback)
			this->callback(this);

		delete this;
		return series->pop();
	}

	virtual MESSAGE *message_out()
	{
		return &this->message;
	}

private:
	MESSAGE message;

protected:
	std::function<void (TransTask<MESSAGE> *)> callback;
	std::function<void (TransTask<MESSAGE> *)> *process;
};

template<class IN, class OUT>
class WFChannel : public ChanRequest//CommChannel
{
public:
	WFChannel(CommSchedObject *object, CommScheduler *scheduler,
			  std::function<void (TransTask<IN> *)>&& process) :
		ChanRequest(object, scheduler),
		process(std::move(process))
	{
//		this->state = CHANNEL_STATE_UNDEFINED;
		this->session = NULL;
//		this->establish_session = NULL;
	}

	virtual TransTask<OUT> *create_task(std::function<void (TransTask<OUT> *)>&& cb)
	{
		return new TransTask<OUT>(this, this->scheduler, std::move(cb));
	}
/*
	virtual bool close(std::function<void ()> close_callback)
	{
		this->close_callback = std::move(close_callback);

		if (this->state != CHANNEL_STATE_ESTABLISHED)
			return false;

		this->scheduler->shutdown(this);
		return true;
	}
*/

	int get_state() { return this->state; }

public:
	virtual CommMessageIn *message_in()
	{
		fprintf(stderr, "WFChannel::message_in()\n");
		TransTask<IN> *task = new TransTask<IN>(this, this->scheduler,
												&this->process, nullptr);
		Workflow::create_series_work(task, nullptr); //
		this->session = task; //TODO: new_session
		return task->get_message();
	}

	virtual ~WFChannel()
	{
		if (this->state == CHANNEL_STATE_ESTABLISHED)
			this->scheduler->shutdown(this);
	}

protected:
	/*
	virtual void handle_established() //
	{
		this->state = CHANNEL_STATE_ESTABLISHED;
		ChanRequest::handle_established();
	}

	virtual void handle_shutdown() //
	{
		this->state = CHANNEL_STATE_SHUTDOWN;
		ChanRequest::handle();
	}
	*/
	virtual void handle_in(CommMessageIn *in)
	{
		if (this->session)
			this->session->dispatch();
	}
	
/*
	virtual void handle(int state, int error)
	{
		if (!error)
			this->state = state;
		else
			this->state = CHANNEL_STATE_ERROR;
	}
*/
public:
	std::function<void (TransTask<IN> *)> process;

//private:
//	int state;

protected:
	TransRequest *session;
};

#endif

