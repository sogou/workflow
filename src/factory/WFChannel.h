#ifndef _WFCHANNEL_H_
#define _WFCHANNEL_H_

#include "Communicator.h"
#include "ChannelRequest.h"
#include "Workflow.h"

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
	ChannelTask(CommSchedChannel *channel, Communicator *comm,
				std::function<void (ChannelTask<MESSAGE> *)>&& cb) :
		ChannelRequest(channel, comm)
	{
		this->send_callback = std::move(cb);
		this->process_message = NULL;
	}

	// IN TASK
	ChannelTask(CommSchedChannel *channel, Communicator *comm,
				std::function<void (ChannelTask<MESSAGE> *)> *process) :
		ChannelRequest(channel, comm)
	{
		this->passive = true;
		this->process_message = process;
		this->send_callback = nullptr;
	}

	ChannelTask(CommSchedChannel *channel, Communicator *comm,
				std::function<void (ChannelTask<MESSAGE> *)> func,
				bool passive) :
		ChannelRequest(channel, comm)
	{
		this->passive = passive;
		if (passive)
			this->process_message = &func;
		else
			this->send_callback = std::move(func);
	}

protected:
	virtual void on_message()
	{
		if (this->process_message != NULL)
			(*process_message)(this);
	}

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (!this->passive && this->send_callback)
			this->send_callback(this);

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
	std::function<void (ChannelTask<MESSAGE> *)> send_callback;
	std::function<void (ChannelTask<MESSAGE> *)> *process_message;
};

template<class IN, class OUT>
class WFChannel : public CommChannel//CommSchedChannel
{
public:
	WFChannel(Communicator *comm, CommTarget *target,
			  std::function<void (ChannelTask<IN> *)>&& process_message) :
		CommSchedChannel(comm, target),
		process_message(std::move(process_message))
	{
	}

	virtual ChannelTask<OUT> *create_task(std::function<void (ChannelTask<OUT> *)>&& cb)
	{
		return new ChannelTask<OUT>(this, this->communicator, std::move(cb));
	}

	virtual bool connect(std::function<void ()> on_connect)
	{
		this->on_connect = std::move(on_connect);
		return this->establish();
	}

	virtual bool close(std::function<void ()> on_close)
	{
		this->on_close = std::move(on_close);
		return this->shutdown();
	}

public:
	virtual CommMessageIn *message_in()
	{
		fprintf(stderr, "WFChannel::message_in()\n");
		ChannelTask<IN> *task = new ChannelTask<IN>(this, this->communicator,
													&this->process_message);
//		Workflow::create_series_work(task, nullptr); // TODO: dispatch() ?
		this->in_session = task; // new_session
		return task->get_message();
	}

	//don`t need this after ChannelFactory reuse target
	virtual ~WFChannel()
	{
		if (this->state == CHANNEL_STATE_ESTABLISHED)
			this->communicator->shutdown(this);
		delete this->target;
	}

protected:	
	virtual void handle_established()
	{
		CommSchedChannel::handle_established();

		if (this->on_connect)
			this->on_connect();
	}

	virtual void handle_shutdown()
	{
		CommSchedChannel::handle_terminated();

		if (this->on_close)
			this->on_close();
	}

public:
	std::function<void (ChannelTask<IN> *)> process_message;
	std::function<void ()> on_connect;
	std::function<void ()> on_close;
};

#endif

