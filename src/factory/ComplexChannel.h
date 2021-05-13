#ifndef _COMPLEXCHANNEL_H_
#define _COMPLEXCHANNEL_H_

#include "TransRequest.h"
#include "WFChannel.h"
#include "WFGlobal.h"

template<class MESSAGE>
class WFComplexChannel : public WFChannel<MESSAGE>
{
public:
	WFComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
					 std::function<void (ChannelTask<MESSAGE> *)>&& process) :
		WFChannel<MESSAGE>(object, scheduler, std::move(process)),
		mutex(PTHREAD_MUTEX_INITIALIZER)
	{
		this->state = WFT_STATE_UNDEFINED;
		this->error = 0;
		this->counter = NULL;
	}

	int get_state() const { return this->state; }
	int get_error() const { return this->error; }

	void set_state(int state) { this->state = state; }
	void set_counter(WFCounterTask *counter) { this->counter = counter; }

	void set_callback(std::function<void (ChanRequest *)>&& cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual void dispatch()
	{
		if (this->object)
			return this->WFChannel<MESSAGE>::dispatch();

		this->router_task = this->route();		
		series_of(this)->push_front(this);
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

		if (this->callback)
			this->callback(this);

		return series->pop();
	}

	virtual WFRouterTask *route() = 0;

public:
	pthread_mutex_t mutex;

protected:
	WFCounterTask *counter;
	WFRouterTask *router_task;
	std::function<void (ChanRequest *)> callback;
};

template<class MESSAGE>
class ComplexChannel : public WFComplexChannel<MESSAGE>
{
public:
	ComplexChannel(CommSchedObject *object, CommScheduler *scheduler,
				   std::function<void (ChannelTask<MESSAGE> *)>&& process) :
		WFComplexChannel<MESSAGE>(object, scheduler, std::move(process))
	{}

	void set_uri(const ParsedURI& uri) { this->uri = uri; }

protected:
	virtual SubTask *done()
	{
		if (this->established == 1)
		{
			if (this->state == WFT_STATE_SYS_ERROR)
				this->ns_policy->failed(&this->route_result, NULL, this->target);
			else
				this->ns_policy->success(&this->route_result, NULL, this->target);
		}

		return WFComplexChannel<MESSAGE>::done();
	}

	virtual WFRouterTask *route()
	{
		auto&& cb = std::bind(&ComplexChannel<MESSAGE>::router_callback,
							  this, std::placeholders::_1);
		struct WFNSParams params = {
			.type			=	TT_TCP,
			.uri			=	this->uri,
			.info			=	"",
			.fixed_addr		=	true,
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
	RouteManager::RouteResult route_result;
};

template<class MESSAGE>
class ComplexChannelOutTask : public ChannelOutTask<MESSAGE>
{
public:
	ComplexChannelOutTask(CommChannel *channel, CommScheduler *scheduler,
						  std::function<void (ChannelTask<MESSAGE> *)>&& cb) :
		ChannelOutTask<MESSAGE>(channel, scheduler, std::move(cb))
	{
		this->upgrading = false;
	}

protected:
	virtual void dispatch()
	{
		int ret = false;
		auto *channel = static_cast<ComplexChannel<MESSAGE> *>(this->get_request_channel());

		pthread_mutex_lock(&channel->mutex);

		switch (channel->get_state())
		{
		case WFT_STATE_UNDEFINED:
			if (channel->is_established())
			{
				series_of(this)->push_front(this);
				series_of(this)->push_front(channel);
			}
			else if (!this->upgrading)
			{
				SubTask *upgrade_task = this->upgrade();
				series_of(this)->push_front(this);
				series_of(this)->push_front(upgrade_task);
			}
			else
			{
				auto&& cb = std::bind(&ComplexChannelOutTask<MESSAGE>::counter_callback,
									  this, std::placeholders::_1);
				WFCounterTask *counter = new WFCounterTask(1, cb); //
				series_of(this)->push_front(this);
				series_of(this)->push_front(counter);
				channel->set_counter(counter);
			}
			break;
		case WFT_STATE_SUCCESS:
			ret = true;
		default:
			break;
		}

		pthread_mutex_unlock(&channel->mutex);

		if (ret == true)
			return this->ChannelOutTask<MESSAGE>::dispatch();

		return this->subtask_done();
	}

	virtual SubTask *upgrade()
	{
		this->upgrading = true;
		auto&& cb = std::bind(&ComplexChannelOutTask<MESSAGE>::upgrade_callback,
							  this, std::placeholders::_1);
		return new WFCounterTask(0, cb);
	}

	virtual SubTask *done()
	{
		SeriesWork *series = series_of(this);
		
		if (this->upgrading)
			return series->pop();

		return ComplexChannelOutTask<MESSAGE>::done();
	}

	void upgrade_callback(WFCounterTask *task)
	{
		auto *channel = static_cast<ComplexChannel<MESSAGE> *>(this->get_request_channel());
		channel->set_state(WFT_STATE_SUCCESS);
		this->upgrading = false;
	}

	void counter_callback(WFCounterTask *task)
	{
		this->upgrading = false;
	}

private:
	bool upgrading;
};

#endif

