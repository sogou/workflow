#include "ChannelRequest.h"

void CommSchedChannel::handle_in(CommMessageIn *in)
{
	if (this->in_session)
		this->in_session->dispatch();
}

void CommSchedChannel::handle(int state, int error)
{
//	fprintf(stderr, "CommSchedChannel handle(). state=%d error=%d\n", state, error);
	if (!error)
		this->state = state;
	else
		this->state = CHANNEL_STATE_ERROR;
}

/*
int CommSchedChannel::send(ChannelRequest *req)
{
//	if (this->state != CHANNEL_STATE_ESTABLISHED)
//	{
//		req->state = CHANNEL_STATE_ERROR;
//		req->error = this->state;
//		req->on_send();
//		return -1;
//	}
	pthread_mutex_lock(&this->send_mutex);
	int ret = this->communicator->send(req, this);

	if (ret < 0)
		req->handle(CHANNEL_STATE_ERROR, CHANNEL_ERROR_SEND);

	if (ret == 1)
		req->handle(CS_STATE_SUCCESS, CHANNEL_SUCCESS);

	pthread_mutex_unlock(&this->send_mutex);

	return 0;
}
*/

