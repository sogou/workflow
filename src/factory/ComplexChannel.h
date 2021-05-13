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
	virtual void dispatch();
	virtual SubTask *done();
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
	const ParsedURI *get_uri() const { return &this->uri; }

protected:
	virtual SubTask *done();
	virtual WFRouterTask *route();
	virtual void router_callback(WFRouterTask *task);

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
	virtual void dispatch();
	virtual SubTask *upgrade();
	virtual SubTask *done();
	void upgrade_callback(WFCounterTask *task);

	void counter_callback(WFCounterTask *task)
	{
		this->upgrading = false;
	}

private:
	bool upgrading;
};

#endif

