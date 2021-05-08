#include "WFChannel.h"
#include "WFChannelFactory.h"
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "WebSocketMessage.h"

using namespace protocol;

class WebSocketChannel : public WFWebSocketChannel
{
public:
	WebSocketChannel(Communicator *comm, CommTarget *target, bool is_server,
					 websocket_process_t&& process_message) :
		WFChannel(comm, target, std::move(process_message))
	{
		this->is_server = is_server;
	}

	void handle_established()
	{
		fprintf(stderr, "WebSocketChannel::handle_established()\n");
		ChannelTask<HttpRequest> *task = new ChannelTask<HttpRequest>(this,
																	  this->communicator,
																	  nullptr,
																	  false/* passive */);
		HttpRequest *req = task->get_message();
		req->set_method(HttpMethodGet);
		req->set_http_version("HTTP/1.1");
		req->set_request_uri("/");
		req->set_header_pair("Host", "workflow.org");
		req->set_header_pair("Upgrade", "websocket");
		req->set_header_pair("Connection", "Upgrade");
		req->set_header_pair(WS_HTTP_SEC_KEY_K, WS_HTTP_SEC_KEY_V);
		req->set_header_pair(WS_HTTP_SEC_PROTOCOL_K, WS_HTTP_SEC_PROTOCOL_V);
		req->set_header_pair(WS_HTTP_SEC_VERSION_K, WS_HTTP_SEC_VERSION_V);
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
		{
			WFWebSocketChannel::handle_in(in);
/*
			if (this->parser->opcode == WebSocketFrameConnectionClose)
			{
				this->state = 
			}
*/
		}
		
	}

	virtual bool close(std::function<void ()> on_close)
	{
		if (this->state != CHANNEL_STATE_ESTABLISHED)
			return false;

		this->on_close = std::move(on_close);
		WFWebSocketTask *task = this->create_task(nullptr);
		protocol::WebSocketFrame *msg = task->get_message();
		msg->set_opcode(WebSocketFrameConnectionClose);
		task->start();

		return true;
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
		if (target->init(addr, addrlen, connect_timeout, 0 /* response_timeout */) >= 0)
		{
			WebSocketChannel *channel = new WebSocketChannel(&this->communicator,
															 target,
															 false, /* is_server */
															 std::move(process));
			if (channel)
				return channel;
		}
		else
			delete target;
	}
	return NULL;
}


