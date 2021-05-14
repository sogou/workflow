#include "WFTask.h"
#include "WFGlobal.h"
#include "WebSocketTask.h"

#define WS_HTTP_SEC_KEY_K		"Sec-WebSocket-Key"
#define WS_HTTP_SEC_KEY_V		"dGhlIHNhbXBsZSBub25jZQ=="
#define WS_HTTP_SEC_PROTOCOL_K	"Sec-WebSocket-Protocol"
#define WS_HTTP_SEC_PROTOCOL_V	"chat"
#define WS_HTTP_SEC_VERSION_K	"Sec-WebSocket-Version"
#define WS_HTTP_SEC_VERSION_V	"13"

#define WS_HANDSHAKE_TIMEOUT	10 * 1000

using namespace protocol;

SubTask *WebSocketTask::upgrade()
{
	ChannelOutTask<HttpRequest> *http_task;
//	auto&& cb = std::bind(&WebSocketTask::http_callback,
//						  this, std::placeholders::_1);

	WebSocketChannel *channel = static_cast<WebSocketChannel *>(this->get_request_channel());

	http_task = new ChannelOutTask<HttpRequest>(this->channel,
												WFGlobal::get_scheduler(),
												nullptr);
	HttpRequest *req = http_task->get_message();
	req->set_method(HttpMethodGet);
	req->set_http_version("HTTP/1.1");
	req->set_request_uri("/");
	req->add_header_pair("Host", channel->get_uri()->host);
	req->add_header_pair("Upgrade", "websocket");
	req->add_header_pair("Connection", "Upgrade");
	req->add_header_pair(WS_HTTP_SEC_KEY_K, WS_HTTP_SEC_KEY_V);
	req->add_header_pair(WS_HTTP_SEC_PROTOCOL_K, WS_HTTP_SEC_PROTOCOL_V);
	req->add_header_pair(WS_HTTP_SEC_VERSION_K, WS_HTTP_SEC_VERSION_V);

	return http_task;
}

CommMessageIn *WebSocketChannel::message_in()
{
	if (this->state == WFT_STATE_UNDEFINED)
		return new HttpResponse;

	return WFWebSocketChannel::message_in();
}

void WebSocketChannel::handle_in(CommMessageIn *in)
{
	int parse_websocket = false;
	WFCounterTask *counter = NULL;

	pthread_mutex_lock(&this->mutex);

	if (this->state == WFT_STATE_UNDEFINED)
	{
		HttpResponse *resp = static_cast<HttpResponse *>(in);

		if (strcmp(resp->get_status_code(), "101") == 0)
			this->state = WFT_STATE_SUCCESS;
		else
			this->state = WFT_STATE_TASK_ERROR;

		if (this->counter)
		{
			counter = this->counter;
			this->counter = NULL;
		}
		delete resp;
	}
	else if (this->state == WFT_STATE_SUCCESS)
		parse_websocket = true;

	pthread_mutex_unlock(&this->mutex);

	if (counter)
		counter->count();

	if (!parse_websocket)
		return;

	WFWebSocketChannel::handle_in(in);
	//if (this->parser->opcode == WebSocketFrameConnectionClose)
}

int WebSocketChannel::first_timeout()
{
	return WS_HANDSHAKE_TIMEOUT;
}

/*
	void disconnect()
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
