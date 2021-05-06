#include "WFChannel.h"
#include "WFChannelFactory.h"
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "WebSocketMessage.h"

using namespace protocol;

/*
class WebSocketTask : public WFWebSocketTask
{
};
*/

class WebSocketChannel : public WFWebSocketChannel
{
public:
	WebSocketChannel(Communicator *comm, CommTarget *target,
					 websocket_process_t&& process_message) :
		WFChannel(comm, target, std::move(process_message))
	{
		this->is_server = false;
	}

	void handle_established()
	{
		fprintf(stderr, "WebSocketChannel::handle_established()\n");
		std::function<void (ChannelTask<HttpRequest> *)> tmp;
		ChannelTask<HttpRequest> *task = new ChannelTask<HttpRequest>(this,
																	  this->communicator,
																	  std::move(tmp));
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
		fprintf(stderr, "WebSocketChannel::message_in() state=%d\n", this->state);

		if (this->state == CHANNEL_STATE_UNDEFINED)
			return new HttpResponse;

		return WFWebSocketChannel::message_in();
	}

	void handle_in(CommMessageIn *in)
	{
		fprintf(stderr, "WebSocketChannel::handle_in() state=%d\n", this->state);

		if (this->state == CHANNEL_STATE_UNDEFINED)
		{
			HttpResponse *resp = static_cast<HttpResponse *>(in);

			if (strcmp(resp->get_status_code(), "101") == 0)
				this->state = CHANNEL_STATE_ESTABLISHED;
			else
			{
				this->state = CHANNEL_STATE_ERROR;
//				this->error = resp->get_status_code();
			}

			delete resp;

			if (this->on_connect)
				this->on_connect();
		}
		else
			return WFWebSocketChannel::handle_in(in);
	}

	virtual int close(std::function<void ()> on_close)
	{
		if (this->state != CHANNEL_STATE_ESTABLISHED)
			return -1;

		this->on_close = std::move(on_close);

		auto&& cb = std::bind(&WebSocketChannel::close_callback,
							  this,
							  std::placeholders::_1);
		auto *task = this->create_out_task(cb);
		auto *msg = task->get_message();
		msg->set_opcode(WebSocketFrameConnectionClose);
		msg->set_masking_key(0);
		task->start();

		return 0;
	}

	void close_callback(WFWebSocketTask *)
	{
		this->shutdown();
	}

private:
	bool is_server;
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


