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

class CommSchedChannel : public CommChannel
{
public:
	CommSchedChannel(Communicator *comm, CommTarget *target) :
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

	// TODO: wait for handle finish and we can reuse this channel
	virtual void handle(int state, int error);
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
	ChannelRequest(CommSchedChannel *channel, Communicator *comm)
	{
		this->sched_channel = channel;
		this->communicator = comm;
		this->passive = false;
	}

	virtual void dispatch()
	{
		fprintf(stderr, "ChannelRequest::dispatch()\n");
		if (!this->passive) // OUT
		{
			int ret = this->communicator->send(this, this->sched_channel);

			if (ret < 0)
				this->handle(CHANNEL_STATE_ERROR, CHANNEL_ERROR_SEND);
			else if (ret == 1)
				this->handle(CS_STATE_SUCCESS, CHANNEL_SUCCESS);
			// else 0: async send
		}
		else // IN
		{
			this->on_message();
			this->subtask_done();
		}
	}

	// OUT
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

	// IN
	virtual void on_message() {}

	const CommSchedChannel *get_sched_channel()
	{
		return this->sched_channel;
	}

protected:
    int state;
    int error;
	bool passive;
	Communicator *communicator;
	CommSchedChannel *sched_channel;
	friend CommSchedChannel;
};

/*
class ChannelOutRequest : public SubTask, public TransSession
{
public:
	ChannelOutRequest(CommSchedChannel *channel)
	{
		this->channel = channel;
	}

	virtual void dispatch()
	{
		if (!this->channel || ((CommSchedChannel *)this->channel)->send(this) < 0)
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
	friend CommSchedChannel;
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
	friend CommSchedChannel;
};
*/
#endif

