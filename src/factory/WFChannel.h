#ifndef _WF_CHANNEL_H_
#define _WF_CHANNEL_H_

#include "Communicator.h"
#include "ChannelRequest.h"
#include "Workflow.h"

template<class OUT>
class ChannelOutTask : public ChannelOutRequest
{
public:
	ChannelOutTask(CommBaseChannel *channel, std::function<void (ChannelOutTask<OUT> *)>&& cb) :
		ChannelOutRequest(channel),
		send_callback(std::move(cb))
	{}

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
		// set state/error

		if (this->send_callback)
			this->send_callback(this);

		delete this;
		return series->pop();
	}

public:
	OUT *message_out()
	{
		return &this->out;
	}

private:
	OUT out;

protected:
	std::function<void (ChannelOutTask<OUT> *)> send_callback;
};

template<class IN>
class ChannelInTask : public ChannelInRequest
{
public:
	ChannelInTask(std::function<void (ChannelInTask<IN> *)> *process) :
		process_message(process)
	{}

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

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);
		delete this;

		return series->pop();
	}

	void set_in_message(CommMessageIn *in)
	{
		this->in = (IN *)in;
	}

	IN *get_in_message()
	{
		return this->in;
	}

	virtual void on_message()
	{
		if (this->process_message != NULL)
			(*process_message)(this);
	}

	int get_state() const { return this->state; }
	int get_error() const { return this->error; }
//	void *user_data;

private:
	IN *in;

protected:
	std::function<void (ChannelInTask<IN> *)> *process_message;
};

template<class IN, class OUT>
class WFChannel : public CommBaseChannel
{
public:
	WFChannel(Communicator *comm, CommTarget *target,
			  std::function<void (ChannelInTask<IN> *)>&& process_message) :
		CommBaseChannel(comm, target),
		process_message(std::move(process_message))
	{
	}

	ChannelOutTask<OUT> *create_out_task(std::function<void (ChannelOutTask<OUT> *)>&& cb)
	{
		return new ChannelOutTask<OUT>(this, std::move(cb));
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
	virtual ChannelInTask<IN> *new_request(CommMessageIn *in)
	{
		ChannelInTask<IN> *task = new ChannelInTask<IN>(&this->process_message);
		Workflow::create_series_work(task, nullptr);
		task->set_in_message(in);
		return task;
	}

	virtual CommMessageIn *message_in()
	{
		return new IN;
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
	std::function<void (ChannelInTask<IN> *)> process_message;
	std::function<void ()> on_connect;
	std::function<void ()> on_close;
};

class WFChannelFactory
{
public:
    int init(size_t threads)
    {   
        return this->comm.init(threads, 1/*handler_threads*/);
    }   

    void deinit()
    {   
        this->comm.deinit();
    }

	template<class IN, class OUT>
	WFChannel<IN, OUT> *create_channel(const struct sockaddr *addr, socklen_t addrlen,
									int connect_timeout, std::function<void (ChannelInTask<IN> *)> process)
	{
		// TODO: reuse target
		CommTarget *target = new CommTarget();
		if (target)
		{
			if (target->init(addr, addrlen, connect_timeout, 0 /*response_timeout*/) >= 0)
			{
				auto *channel = new WFChannel<IN, OUT>(&this->comm, target, std::move(process));
				if (channel)
					return channel;
			}
			else
				delete target;
		}
		return NULL;
	}

private:
	Communicator comm;
//	std::map<int, CommTarget *> target_map;
};

#endif

