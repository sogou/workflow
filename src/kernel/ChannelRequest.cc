#include "ChannelRequest.h"

void CommBaseChannel::handle_in(CommMessageIn *in)
{
	ChannelRequest *req = this->new_request(in);
	req->dispatch();
}

int CommBaseChannel::send(ChannelRequest *req)
{
	if (this->state != CHANNEL_STATE_ESTABLISHED)
	{
		req->state = CHANNEL_STATE_ERROR;
		req->error = this->state;
		req->on_send();
		return -1;
	}

	pthread_mutex_lock(&this->send_mutex);
	int ret = this->communicator->send(req, this);

	if (ret < 0)
		req->handle(CHANNEL_STATE_ERROR, CHANNEL_ERROR_SEND);

	if (ret == 1)
		req->handle(CS_STATE_SUCCESS, CHANNEL_SUCCESS);

	pthread_mutex_unlock(&this->send_mutex);

	return 0;
}

void CommBaseChannel::handle(int state, int error)
{
//	fprintf(stderr, "CommBaseChannel handle(). state=%d error=%d\n", state, error);
	if (!error)
		this->state = state;
	else
		this->state = CHANNEL_STATE_ERROR;
}
