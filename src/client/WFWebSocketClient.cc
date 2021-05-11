#include "WFWebSocketClient.h"

#define WS_HTTP_SEC_KEY_K		"Sec-WebSocket-Key"
#define WS_HTTP_SEC_KEY_V		"dGhlIHNhbXBsZSBub25jZQ=="
#define WS_HTTP_SEC_PROTOCOL_K	"Sec-WebSocket-Protocol"
#define WS_HTTP_SEC_PROTOCOL_V	"chat"
#define WS_HTTP_SEC_VERSION_K	"Sec-WebSocket-Version"
#define WS_HTTP_SEC_VERSION_V	"13"

SubTask *WebSocketChannel::done()
{
	if (!this->router_task && this->state == WFT_STATE_SUCCESS &&
		this->established == 1)
	{
		ChannelOutTask<HttpRequest> *http_task;
		auto&& cb = std::bind(&WebSocketChannel::http_callback,
							  this, std::placeholders::_1);

		http_task = new ChannelOutTask<HttpRequest>(this, this->scheduler,
												 	nullptr, cb);
		HttpRequest *req = task->get_message();
		req->set_method(HttpMethodGet);
		req->set_http_version("HTTP/1.1");
		req->set_request_uri("/");
		req->set_header_pair("Host", "workflow.org");
		req->set_header_pair("Upgrade", "websocket");
		req->set_header_pair("Connection", "Upgrade");
		req->set_header_pair(WS_HTTP_SEC_KEY_K, WS_HTTP_SEC_KEY_V);
		auto *user_task = series->pop();
		sereis_of(this)->push_front(user_task);
		series_of(this)->push_front(http_task);

		this->state = WFT_STATE_UNDEFINED;
	}

	return WFWebSocketChannel::done();
}

void WebSocketChannel::http_callback(ChannelTask<HttpRequest> *task)
{
	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		this->counter = new WFCounterTask(1, nullptr);
		auto *user_task = series->pop();
		sereis_of(this)->push_front(user_task);
		series_of(task)->push_front(this->counter);
	}
	else
	{
		this->state = task->get_state();
		this->error = task->get_error();
	}
}
	
CommMessageIn *WebSocketChannel::message_in()
{
	if (this->state == WFT_STATE_UNDEFINED)
		return new HttpResponse;

	return WFWebSocketChannel::message_in();
}

void WebSocketChannel::handle_in(CommMessageIn *in)
{
	if (this->state == WFT_STATE_UNDEFINED)
	{
		HttpResponse *resp = static_cast<HttpResponse *>(in);

		if (strcmp(resp->get_status_code(), "101") == 0)
			this->state = WFT_STATE_ESTABLISHED;
		else
			this->state = WFT_STATE_ERROR;

		if (this->counter)
		{
			this->counter->count();
			this->counter = NULL;
		}

		delete resp;
	}
	else
	{
		WFWebSocketChannel::handle_in(in);
		//if (this->parser->opcode == WebSocketFrameConnectionClose)
	}
}

/*
	~WebSocketClient::WebSocketClient()
	{
		if (this->established == 1)
		{
			WFWebSocketTask *task = this->create_task(nullptr);
			WebSocketFrame *msg = task->get_message();
			msg->set_opcode(WebSocketFrameConnectionClose);
			task->start();
		}
	}
*/
