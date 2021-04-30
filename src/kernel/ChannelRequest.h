#ifndef _CHANNEL_REQUEST_H_
#define _CHANNEL_REQUEST_H_

#include "Communicator.h"
#include "SubTask.h"

#define CHANNEL_STATE_UNDEFINED		-1
#define CHANNEL_STATE_ESTABLISHED	0
#define CHANNEL_STATE_ERROR			CS_STATE_ERROR
#define CHANNEL_STATE_STOPPED		CS_STATE_STOPPED
#define CHANNEL_STATE_SHUTDOWN		CS_STATE_SHUTDOWN

#define CHANNEL_SUCCESS				0
#define CHANNEL_ERROR_UNOPEN		CHANNEL_STATE_UNDEFINED
#define CHANNEL_ERROR_STOPPED		CHANNEL_STATE_STOPPED
#define CHANNEL_ERROR_SENDING		3
#define CHANNEL_ERROR_SEND			4

class ChannelRequest;

class CommBaseChannel : public CommChannel
{
public:
	CommBaseChannel(Communicator *comm, CommTarget *target) :
		send_mutex(PTHREAD_MUTEX_INITIALIZER)
	{
		this->communicator = comm;
		this->target = target;
		this->state = CHANNEL_STATE_UNDEFINED;
	}

	int establish()
	{
		if (this->state != CHANNEL_STATE_UNDEFINED &&
			this->state != CHANNEL_STATE_SHUTDOWN &&
			this->state != CHANNEL_STATE_STOPPED)
		{
			//errno = EINVALID;
			return -1;
		}
		
		return this->communicator->establish(this, target);
	}

	virtual void handle_established()
	{
		this->state = CHANNEL_STATE_ESTABLISHED;
	}

	int shutdown()
	{
		if (this->state != CHANNEL_STATE_ESTABLISHED)
			return -1;

		this->communicator->shutdown(this);
		return 0;
	}

	virtual void handle_terminated()
	{
		this->state = CHANNEL_STATE_SHUTDOWN;
	}

	int get_state() { return this->state; }

	int send(ChannelRequest *req/*, int wait_timeout*/);
	virtual void handle(int state, int error);// TODO: wait for handle finish and we can reuse this channel
	virtual void handle_in(CommMessageIn *in);

protected:
	Communicator *communicator;
	CommTarget *target;
	pthread_mutex_t send_mutex;
	ChannelRequest *in_session;
	int state;
};

class ChannelRequest : public SubTask, public TransSession
{
public:
	ChannelRequest(CommBaseChannel *channel)
	{
		this->channel = channel;
		this->passive = false;
	}

	virtual void dispatch()
	{
		if (this->passive) // ChannelInRequest
		{
			this->on_message();
			this->subtask_done();
		}	
		else
		{
			if (!this->channel || ((CommBaseChannel *)this->channel)->send(this) < 0)
				this->subtask_done();
		}
	}

	// ChannelOutRequest
	void handle(int state, int error)
	{
		this->state = state;
		this->error = error;
		this->on_send();
	}

	virtual void on_send()
	{
		this->subtask_done();
	}

	// ChannelInRequest
	virtual void on_message() {}

protected:
    int state;
    int error;
	bool passive;
	friend CommBaseChannel;
};

/*
class ChannelOutRequest : public SubTask, public TransSession
{
public:
	ChannelOutRequest(CommBaseChannel *channel)
	{
		this->channel = channel;
	}

	virtual void dispatch()
	{
		if (!this->channel || ((CommBaseChannel *)this->channel)->send(this) < 0)
			this->subtask_done();
	}

	virtual void on_send()
	{
		this->subtask_done();
	}

	void handle(int state, int error)
	{
		this->state = state;
		this->error = error;
		this->on_send();
	}

protected:
    int state;
    int error;
	friend CommBaseChannel;
};

class ChannelInRequest : public SubTask
{
public:
	ChannelInRequest()
	{
	}

	virtual void dispatch()
	{
		this->on_message();
		this->subtask_done();
	}

	virtual void on_message() = 0;

protected:
    int state;
    int error;
	friend CommBaseChannel;
};
*/
#endif

