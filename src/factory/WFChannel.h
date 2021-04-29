#ifndef _WFCHANNEL_H_
#define _WFCHANNEL_H_

#include "Communicator.h"
#include "ChannelRequest.h"
#include "Workflow.h"

template<class MESSAGE>
class ChannelTask : public ChannelRequest
{
public:
	ChannelTask(CommBaseChannel *channel, std::function<void (ChannelTask<MESSAGE> *)>&& cb) :
		ChannelRequest(channel)
	{
		this->send_callback = std::move(cb);
		this->process_message = NULL;
	}

	ChannelTask(CommBaseChannel *channel, std::function<void (ChannelTask<MESSAGE> *)> *process) :
		ChannelRequest(channel)
	{
		this->passive = true;
		this->process_message = process;
		this->send_callback = nullptr;
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

	int get_state() const { return this->state; }
	int get_error() const { return this->error; }
//	void *user_data;

protected:
	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (!this->passive && this->send_callback)
			this->send_callback(this);

		delete this;
		return series->pop();
	}

public:
	virtual void on_message()
	{
		if (this->process_message != NULL)
			(*process_message)(this);
	}

	MESSAGE *get_message()//TODO
	{
		return &this->message;
	}

private:
	MESSAGE message;

protected:
	virtual MESSAGE *message_out()
	{
		return &this->message;
	}

protected:
	std::function<void (ChannelTask<MESSAGE> *)> send_callback;
	std::function<void (ChannelTask<MESSAGE> *)> *process_message;
};

template<class IN, class OUT>
class WFChannel : public CommBaseChannel
{
public:
	WFChannel(Communicator *comm, CommTarget *target,
			  std::function<void (ChannelTask<IN> *)>&& process_message) :
		CommBaseChannel(comm, target),
		process_message(std::move(process_message))
	{
	}

	ChannelTask<OUT> *create_out_task(std::function<void (ChannelTask<OUT> *)>&& cb)
	{
		return new ChannelTask<OUT>(this, std::move(cb));
	}

	int connect(std::function<void ()> on_connect)
	{
		this->on_connect = std::move(on_connect);
		return this->establish();
	}

	int close(std::function<void ()> on_close)
	{
		this->on_close = std::move(on_close);
		return this->shutdown();
	}

public:
	virtual CommMessageIn *message_in()
	{
		ChannelTask<IN> *task = new ChannelTask<IN>(this, &this->process_message);
		Workflow::create_series_work(task, nullptr);
		this->in_session = task;
		return task->get_message();
	}	

	virtual ~WFChannel() //don`t need this after ChannelFactory reuse target
	{
		this->communicator->shutdown(this);
		delete this->target;
	}

protected:	
	virtual void handle_established()
	{
		CommBaseChannel::handle_established();

		if (this->on_connect)
			this->on_connect();
	}

	virtual void handle_shutdown()
	{
		CommBaseChannel::handle_terminated();

		if (this->on_close)
			this->on_close();
	}

public:
	std::function<void (ChannelTask<IN> *)> process_message;
	std::function<void ()> on_connect;
	std::function<void ()> on_close;	
};

#endif

