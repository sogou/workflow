#include "WFChannel.h"
#include "WFChannelFactory.h"
#include "WebSocketMessage.h"

using namespace protocol;

class WebSocketChannel : public WFWebSocketChannel
{
public:
	WebSocketChannel(Communicator *comm, CommTarget *target,
					 std::function<void (ChannelTask<IN> *)>&& process_message)
	{}

	void handle_established()
	{
		ChannelTask<HttpRequest> *task = new ChannelTask<HttpRequest>(this, nullptr);
		HttpRequest *req = task->get_message();
		req->set_method(HttpMethodGet);
		req->set_http_version("HTTP/1.1");
		req->set_request_uri("/");
		req->set_header_pair("Host", "websocket.workflow.org");
		req->set_header_pair("Upgrade", "websocket");
		req->set_header_pair("Connection", "Upgrade");
		req->set_header_pair("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
		req->set_header_pair("Sec-WebSocket-Protocol", "chat");
		req->set_header_pair("Sec-WebSocket-Version", "13");
		task->start();
	}

public:
	virtual CommMessageIn *message_in()
	{
		long long seqid = this->get_seq();
//		fprintf(stderr, "message_in(), seqid=%d\n", seqid);

		if (seqid == 0)
			return new HttpResponse;

		return WFWebSocketChannel::message_in();
	}

	void handle_in(CommMessageIn *in)
	{
		long long seqid = this->get_seq();
//		fprintf(stderr, "handle_in(), seqid=%d\n", seqid);

		if (seqid == 0)
		{
			HttpResponse *resp = static_cast<HttpResponse *>(in);

			//TODO: check 
			if (resp->resp->get_status_code() == 101)
				this->state = CHANNEL_STATE_ESTABLISHED;
			else
			{
				this->state = CHANNEL_STATE_ERROR;
				this->error = resp->resp->get_status_code(); //TODO
			}

			delete resp;

			if (this->on_connect)
				this->on_connect();
		}
		else
			return WFWebSocketChannel::handle_in(in);
	}

	//TODO: close send a close frame	
};

/**********Channel Factory**********/

WFWebSocketChannel *WFChannelFactory::create_websocket_channel(const struct sockaddr *addr,
															   socklen_t addrlen,
															   int connect_timeout,
															   websocket_process_t process)
{
	// TODO: reuse target
	CommTarget *target = new CommTarget();
	if (target)
	{
		if (target->init(addr, addrlen, connect_timeout, 0 /*response_timeout*/) >= 0)
		{
			WebSocketChannel *channel = new WebSocketChannel(&this->comm,
															 target,
															 std::move(process));
			if (channel)
				return channel;
		}
		else
			delete target;
	}
	return NULL;
}


