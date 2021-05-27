#ifndef _WFCHANNEL_H_
#define _WFCHANNEL_H_

#include "CommScheduler.h"
#include "TransRequest.h"
#include "Workflow.h"
#include "RouteManager.h"
#include "EndpointParams.h"
#include "WFNameService.h"

template<class MESSAGE>
class ChannelTask : public TransRequest
{
public:
	ChannelTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (ChannelTask<MESSAGE> *)>&& cb) :
		TransRequest(channel, scheduler)
	{
		this->callback = std::move(cb);
	}

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

protected:
	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (this->callback)
			this->callback(this);

		delete this;
		return series->pop();
	}

protected:
	MESSAGE message;
	std::function<void (ChannelTask<MESSAGE> *)> callback;
};

template<class MESSAGE>
class ChannelOutTask : public ChannelTask<MESSAGE>
{
public:
	ChannelOutTask(CommChannel *channel, CommScheduler *scheduler,
				   std::function<void (ChannelTask<MESSAGE> *)>&& cb) :
		ChannelTask<MESSAGE>(channel, scheduler, std::move(cb))
	{
	}

	virtual MESSAGE *message_out()
	{
		return &this->message;
	}
};

template<class MESSAGE>
class ChannelInTask : public ChannelTask<MESSAGE>
{
public:
	ChannelInTask(CommChannel *channel, CommScheduler *scheduler,
				std::function<void (ChannelTask<MESSAGE> *)>&& cb,
				std::function<void (ChannelTask<MESSAGE> *)>& proc) :
		ChannelTask<MESSAGE>(channel, scheduler, std::move(cb)),
		process(proc)
	{
	}

	virtual void dispatch()
	{
		this->state = WFT_STATE_SUCCESS;
		this->error = 0;
		this->process(this);
		this->subtask_done();
	}

	void set_callback(std::function<void (ChannelTask<MESSAGE> *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	std::function<void (ChannelTask<MESSAGE> *)>& process;
};

template<class MESSAGE>
class WFChannel : public ChanRequest
{
public:
	WFChannel(CommSchedObject *object, CommScheduler *scheduler,
			  std::function<void (ChannelTask<MESSAGE> *)>&& process) :
		ChanRequest(object, scheduler),
		process(std::move(process))
	{
		this->session = NULL;
	}

	virtual CommMessageIn *message_in()
	{
		this->session = this->new_session();
		return this->session->get_message();
	}

	int get_state() const { return this->state; }
	int get_error() const { return this->error; }
	bool is_established() const { return this->established == 1; }
	void set_callback(std::function<void (WFChannel<MESSAGE> *)>&& cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual ChannelTask<MESSAGE> *new_session()
	{
		auto *task = new ChannelInTask<MESSAGE>(this, this->scheduler,
												nullptr, this->process);
		Workflow::create_series_work(task, nullptr);
		return task;
	}

	virtual void handle_in(CommMessageIn *in)
	{
		if (this->session)
			this->session->dispatch();
		this->session = NULL;
	}

	virtual SubTask *done()
	{
		if (this->callback)
			this->callback(this);

		return series_of(this)->pop();
	}

protected:
	std::function<void (ChannelTask<MESSAGE> *)> process;
	std::function<void (WFChannel<MESSAGE> *)> callback;

private:
	ChannelTask<MESSAGE> *session;
};

#endif

