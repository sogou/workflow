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

template<class MESSAGE>
class ChannelTask : public ChannelRequest
{
public:
	void start()
	{
		assert(!series_of(this));
		Workflow::start_series_work(this, nullptr);
	}

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
	// OUT TASK
	ChannelTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (ChannelTask<MESSAGE> *)>&& cb) :
		ChannelRequest(channel, scheduler)
	{
		this->process = NULL;
		this->callback = std::move(cb);
	}

	// IN TASK
	ChannelTask(CommSchedChannel *channel, CommScheduler *scheduler,
				std::function<void (ChannelTask<MESSAGE> *)> *process,
				std::function<void (ChannelTask<MESSAGE> *)>&& cb) :
		ChannelRequest(channel, scheduler)
	{
		this->passive = true;
		this->process = process;
		this->callback = std::move(cb);
	}

	void set_callback(std::function<void (ChannelTask<MESSAGE> *)> cb)
	{
		this->callback = std::move(cb);
	}

/*
	ChannelTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (ChannelTask<MESSAGE> *)>&& cb,
				bool passive) :
		ChannelRequest(channel, scheduler)
	{
		this->passive = true;
		this->callback = std::move(cb);
	}
*/

protected:
	virtual void process_message()
	{
		if (this->process != NULL)
			(*process)(this);

		this->callback();
	}

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (!this->passive && this->callback)
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
	std::function<void (ChannelTask<MESSAGE> *)> callback;
	std::function<void (ChannelTask<MESSAGE> *)> *process;
};

template<class IN, class OUT>
class WFChannel : public CommChannel
{
public:
	WFChannel(CommScheduler *scheduler, CommSchedObject *object, int wait_timeout,
			  std::function<void (ChannelTask<IN> *)>&& process) :
		process(std::move(process))
	{
		this->scheduler = scheduler;
		this->object = object;
		this->wait_timeout = wait_timeout;
		this->state = CHANNEL_STATE_UNDEFINED;
		this->session = NULL;
		this->establish_session = NULL;
	}

	virtual ChannelTask<OUT> *create_task(std::function<void (ChannelTask<OUT> *)>&& cb)
	{
		return new ChannelTask<OUT>(this, this->scheduler, std::move(cb));
	}

	virtual bool close(std::function<void ()> close_callback)
	{
		this->close_callback = std::move(close_callback);

		if (this->state != CHANNEL_STATE_ESTABLISHED)
			return false;

		this->scheduler->shutdown(this);
		return true;
	}

	CommSchedObject *get_request_object() const { return this->object; }
	void set_request_object(CommSchedObject *object) { this->object = object; }
	int get_wait_timeout() const { return this->wait_timeout; }
	void set_wait_timeout(int timeout) { this->wait_timeout = timeout; }
	int get_state() { return this->state; }

public:
	virtual CommMessageIn *message_in()
	{
		fprintf(stderr, "WFChannel::message_in()\n");
		ChannelTask<IN> *task = new ChannelTask<IN>(this, this->scheduler,
													&this->process, nullptr);
		Workflow::create_series_work(task, nullptr);
		this->session = task; //TODO: new_session
		return task->get_message();
	}

	virtual ~WFChannel()
	{
		if (this->state == CHANNEL_STATE_ESTABLISHED)
			this->scheduler->shutdown(this);
	}

protected:
	virtual void handle_established()
	{
		this->state = CHANNEL_STATE_ESTABLISHED;
		this->establish_session->handle(this->state, 0);
	}

	virtual void handle_shutdown()
	{
		this->state = CHANNEL_STATE_SHUTDOWN;

		if (this->close_callback)
			this->close_callback();
	}

	virtual void handle_in(CommMessageIn *in)
	{
		if (this->session)
			this->session->dispatch();
	}

	virtual void handle(int state, int error)
	{
		if (!error)
			this->state = state;
		else
			this->state = CHANNEL_STATE_ERROR;
	}

public:
	std::function<void (ChannelTask<IN> *)> process;

private:
	CommShecdObject *object;
	CommScheduler *scheduler;
	int wait_timeout;
	int state;

protected:
	CommTarget *target;
//	int timeout_reason;
	ChannelRequest *session;
	EstablishSession *establish_session;
};

#endif

