#ifndef _CHANNEL_REQUEST_H_
#define _CHANNEL_REQUEST_H_

#include "Communicator.h"
#include "SubTask.h"

#define CHANNEL_STATE_UNDEFINED		-1
#define CHANNEL_STATE_ESTABLISHED	0
#define CHANNEL_STATE_ERROR			CS_STATE_ERROR
#define CHANNEL_STATE_STOPPED		CS_STATE_STOPPED
#define CHANNEL_STATE_SHUTDOWN		CS_STATE_SHUTDOWN

#define CHANNEL_ERROR_UNOPEN		CHANNEL_STATE_UNDEFINED
#define CHANNEL_ERROR_STOPPED		CHANNEL_STATE_STOPPED
#define CHANNEL_ERROR_SENDING		3
#define CHANNEL_ERROR_SEND			4

class ChannelOutRequest;
class ChannelInRequest;

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
		if (this->state != CHANNEL_STATE_UNDEFINED)
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

	int send(ChannelOutRequest *req/*, int wait_timeout*/);
	virtual void handle(int state, int error);
	virtual void handle_in(CommMessageIn *in);
	virtual ChannelInRequest *new_request(CommMessageIn *in) = 0;

protected:
	Communicator *communicator;
	CommTarget *target;
	pthread_mutex_t send_mutex;
	int state;
};

class ChannelOutRequest : public SubTask, public CommSessionOut
{
public:
	ChannelOutRequest(CommBaseChannel *channel)
	{
		this->channel = channel;
		this->out_message = NULL;
	}

	virtual void dispatch()
	{
		fprintf(stderr, "ChannelOutRequest dispatch()\n");
		if (this->channel->send(this/*, this->wait_timeout*/) < 0)
			this->subtask_done();
	}

	virtual void on_send()
	{
		this->subtask_done();
	}

	void handle(int state, int error)
	{
		fprintf(stderr, "ChannelOutRequest handle()\n");
		this->state = state;
		this->error = error;
		this->on_send();
	}

	virtual CommMessageOut *get_out_message() = 0;

    int state;
    int error;
	CommMessageOut *out_message;

protected:
	CommBaseChannel *channel;
};

class ChannelInRequest : public SubTask
{
public:
	ChannelInRequest(CommBaseChannel *channel)
	{
		this->channel = channel;
	}

	virtual void dispatch()
	{
		fprintf(stderr, "ChannelInRequest dispatch()\n");
		this->on_message();
		this->subtask_done();
	}

	virtual void on_message() = 0;

    int state;
    int error;

protected:
	CommBaseChannel *channel;
};

#endif

