#ifndef _COMPLEXCHANNEL_H_
#define _COMPLEXCHANNEL_H_

#include "WFChannel.h"

#define CHANNEL_STATE_UNDEFINED		-1
#define CHANNEL_STATE_ESTABLISHED	0
#define CHANNEL_STATE_ERROR			CS_STATE_ERROR
#define CHANNEL_STATE_STOPPED		CS_STATE_STOPPED
#define CHANNEL_STATE_SHUTDOWN		CS_STATE_SHUTDOWN

template<class MESSAGE>
class ComplexChanTask : public ChanTask
{
public:
	ComplexChanTask(CommChannel *channel, CommScheduler *scheduler,
					std::function<void (ChanTask<MESSAGE> *)>&& cb) :
		ChanRequest(channel, scheduler, std::move(cb))
	{
		//
	}

protected:
	virtual void dispatch()
	{
		switch (this->channel->get_state())
		{
		case WFT_STATE_SUCCESS:
			return this->ChanTask<MESSAGE>::dispatch();

		case WFT_STATE_UNDEFINED:
		case WFT_STATE_ABORTED:
			series_of(this)->push_front(this);
			sereis_of(this)->push_front(this->channel);
		default:
			break;
		}

		this->subtask_done();
	}

	virtual SubTask *done()
	{
		//TODO
	}
};

template<class IN, class OUT>
class ComplexChannel : public WFChannel
{
public:
	ComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
				   std::function<void (ChanTask<IN> *)>&& process) :
		WFChannel(object, scheduler, std::move(process))
	{
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
	}

	int get_state() const { return this->state; }
	int get_error() const { return this->error; }

protected:
	virtual void dispatch()
	{
		if (this->object)
			return this->WFChannel::dispatch();

		WFRouterTask *task = this->route();
		series_of(this)->push_front(task);
	}

	virtual WFRouterTask *route()
	{
		auto&& cb = std::bind(&ComplexChannel::router_callback,
							  this, std::placeholders::_1);
		struct WFNSParams params = {
			.type			=	type_,
			.uri			=	uri_,
			.info			=	info_.c_str(),
			.fixed_addr		=	fixed_addr_,
			.retry_times	=	retry_times_,
			.tracing		=	&tracing_,
		};

		WFNameService *ns = WFGlobal::get_name_service();
		WFNSPolicy *policy = ns->get_policy(this->uri.host ? this->uri.host : "");
		return policy->create_router_task(&params, cb);
	}

	virtual void router_callback(WFRouterTask *task)
	{	
		if (task->get_state() == WFT_STATE_SUCCESS)
			this->set_request_object(task->get_result()->request_object);
		else
		{
			this->state = task->get_state();
			this->error = task->get_error();
			this->subtask_done();
		}
	}

private:
	int state;
	int error;
};

#endif

