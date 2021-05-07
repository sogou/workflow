#include "ChannelRequest.h"

void CommSchedChannel::handle_in(CommMessageIn *in)
{
	if (this->in_session)
		this->in_session->dispatch();
}

void CommSchedChannel::handle(int state, int error)
{
	if (!error)
		this->state = state;
	else
		this->state = CHANNEL_STATE_ERROR;
}
	
void ChannelRequest::dispatch()
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
//		this->on_message();
		this->subtask_done();
	}
}

void ChannelRequest::handle(int state, int error)
{
	this->state = state;
	this->error = error;
	this->subtask_done();
}

