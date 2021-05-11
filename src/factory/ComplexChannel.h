#ifndef _COMPLEXCHANNEL_H_
#define _COMPLEXCHANNEL_H_

#include "WFChannel.h"
#include "WFGlobal.h"

template<class MESSAGE>
class ComplexChannelOutTask : public ChannelOutTask<MESSAGE>
{
public:
	ComplexChannelOutTask(CommChannel *channel, CommScheduler *scheduler,
					std::function<void (ChannelTask<MESSAGE> *)>&& cb) :
		ChannelOutTask<MESSAGE>(channel, scheduler, std::move(cb))
	{
	}

protected:
	virtual void dispatch()
	{
		auto *channel = static_cast<WFChannel<MESSAGE> *>(this->get_request_channel());
		switch (channel->get_state())
		{
		case WFT_STATE_SUCCESS:
			return this->ChannelOutTask<MESSAGE>::dispatch();

		case WFT_STATE_UNDEFINED:
		case WFT_STATE_ABORTED:
			series_of(this)->push_front(this);
			series_of(this)->push_front(channel);
		default:
			break;
		}

		this->subtask_done();
	}
};

template<class MESSAGE>
class ComplexChannel : public WFChannel<MESSAGE>
{
public:
	ComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
				   std::function<void (ChannelTask<MESSAGE> *)>&& process) :
		WFChannel<MESSAGE>(object, scheduler, std::move(process))
	{
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
	}

	int get_state() const { return this->state; }
	int get_error() const { return this->error; }
	void set_uri(const ParsedURI& uri) { this->uri = uri; }

protected:
	virtual void dispatch()
	{
		if (this->object)
			return this->WFChannel<MESSAGE>::dispatch();

		this->router_task = this->route();
		series_of(this)->push_front(this->router_task);
	}

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);

		if (this->router_task)
		{
			this->router_task = NULL;
			return series->pop();
		}

		if (this->established == 1)
		{
			if (this->state == WFT_STATE_SYS_ERROR)
				this->ns_policy->failed(&this->route_result, NULL, this->target);
			else
				this->ns_policy->success(&this->route_result, NULL, this->target);
		}

		return series->pop();
	}

	virtual WFRouterTask *route()
	{
		auto&& cb = std::bind(&ComplexChannel::router_callback,
							  this, std::placeholders::_1);
		struct WFNSParams params = {
			.type			=	TT_TCP,
			.uri			=	this->uri,
			.info			=	"",
			.fixed_addr		=	false/*fixed_addr*/,
			.retry_times	=	0,
			.tracing		=	NULL,
		};

		WFNameService *ns = WFGlobal::get_name_service();
		this->ns_policy = ns->get_policy(this->uri.host ? this->uri.host : "");
		return this->ns_policy->create_router_task(&params, cb);
	}

	virtual void router_callback(WFRouterTask *task)
	{	
		if (task->get_state() == WFT_STATE_SUCCESS)
		{
			this->route_result = std::move(*task->get_result());
			this->set_request_object(this->route_result.request_object);
		}
		else
		{
			this->state = task->get_state();
			this->error = task->get_error();
		}
	}

protected:
	ParsedURI uri;
	WFNSPolicy *ns_policy;
	WFRouterTask *router_task;
	RouteManager::RouteResult route_result;
};

#endif

