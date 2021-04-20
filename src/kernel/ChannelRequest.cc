#include "ChannelRequest.h"

void CommBaseChannel::handle_in(CommMessageIn *in)
{
	ChannelInRequest *req = this->new_request(in);
	req->dispatch();
}

int CommBaseChannel::send(ChannelOutRequest *req)
{
	if (this->state != CHANNEL_STATE_ESTABLISHED)
	{
		req->state = CHANNEL_STATE_ERROR;
		req->error = this->state;
		req->on_send();
		return -1;
	}

	CommMessageOut *out = req->get_out_message();

	if (out)
	{
		pthread_mutex_lock(&this->send_mutex);
		req->out_message = out;
		int ret = this->communicator->send(out, req, this);
		fprintf(stderr, "communicator->send() ret=%d\n", ret);
		if (ret < 0)
			req->handle(CHANNEL_STATE_ERROR, CHANNEL_ERROR_SEND);

		if (ret == 1)
			req->handle(0, 0);
		pthread_mutex_unlock(&this->send_mutex);
	}

	return !!out;
}
/*
int CommBaseChannel::send(ChannelOutRequest *req)
{
	if (this->state != CHANNEL_STATE_ESTABLISHED)
	{
		req->state = CHANNEL_STATE_ERROR;
		req->error = this->state;
		req->on_send();
		return -1;
	}

	CommMessageOut *out = req->new_out_message();//message_out();

	if (out)
	{
		pthread_mutex_lock(&this->send_mutex);
		if (this->out_session == NULL)
		{
			this->out_session = req;
			this->out_message = out;
			this->communicator->send(out, this, this);
		}
		else
		{
			req->state = CHANNEL_STATE_ERROR;
			req->error = CHANNEL_ERROR_SENDING;
			req->on_send();
			delete out;
		}
		pthread_mutex_unlock(&this->send_mutex);
	}

	return req->error == 0 ? 0 : -1;
}
*/
void CommBaseChannel::handle(int state, int error)
{
/*
	pthread_mutex_lock(&this->send_mutex);
	this->out_session->state = state;
	this->out_session->error = error;
	this->out_session->on_send();
	delete this->out_message;
	this->out_message = NULL;		
	this->out_session = NULL;
	pthread_mutex_unlock(&this->send_mutex);
*/
}
