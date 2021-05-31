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

class WebSocketInTask : public ChannelInTask<WebSocketFrame>
{
public:
	WebSocketInTask(CommChannel *channel, CommScheduler *scheduler,
					std::function<void (ChannelTask<WebSocketFrame> *)>&& cb,
					std::function<void (ChannelTask<WebSocketFrame> *)>& proc) :
	ChannelInTask<WebSocketFrame>(channel, scheduler, std::move(cb), proc)
	{}

protected:
	virtual void dispatch();
	virtual SubTask *done();
};

void WebSocketInTask::dispatch()
{
	const websocket_parser_t *parser = this->get_message()->get_parser();
	
	if (parser->opcode != WebSocketFrameConnectionClose &&
		parser->status_code != WSStatusCodeUndefined)
	{
		this->state = WFT_STATE_SYS_ERROR;
		this->error = parser->status_code;
	}
	else
	{
		this->state = WFT_STATE_SUCCESS;
		this->error = 0;
	}

	this->process(this);
	this->subtask_done();
}

SubTask *WebSocketInTask::done()
{
	SeriesWork *series = series_of(this);
	const websocket_parser_t *parser = this->get_message()->get_parser();
	WebSocketChannel *channel = static_cast<WebSocketChannel *>(this->get_request_channel());

	if ((parser->opcode == WebSocketFrameConnectionClose && !channel->is_established()) ||
		parser->status_code != WSStatusCodeUndefined)
	{
		WebSocketTask *close_task = new WebSocketTask(channel,
													  WFGlobal::get_scheduler(),
													  nullptr);
		WebSocketFrame *msg = close_task->get_message();
		msg->set_opcode(WebSocketFrameConnectionClose);
		msg->set_data(parser);
		series->push_front(close_task);
	}
	else if (parser->opcode == WebSocketFramePing)
	{
		WebSocketTask *pong_task = new WebSocketTask(channel,
													 WFGlobal::get_scheduler(),
													 nullptr);
		WebSocketFrame *msg = pong_task->get_message();
		msg->set_opcode(WebSocketFramePong);
		msg->set_data(parser);
		series->push_front(pong_task);
	}

	if (this->callback)
		this->callback(this);

	delete this;
	return series->pop();
}

SubTask *WebSocketTask::upgrade()
{
	ChannelOutTask<HttpRequest> *http_task;
	auto&& cb = std::bind(&WebSocketTask::http_callback,
						  this, std::placeholders::_1);

	WebSocketChannel *channel = static_cast<WebSocketChannel *>(this->get_request_channel());

	http_task = new ChannelOutTask<HttpRequest>(this->channel,
												WFGlobal::get_scheduler(),
												cb);
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

void WebSocketTask::http_callback(ChannelTask<HttpRequest> *task)
{
	this->ready = true;
}

CommMessageIn *WebSocketChannel::message_in()
{
	if (this->state == WFT_STATE_UNDEFINED)
		return new HttpResponse;

	return WFWebSocketChannel::message_in();
}

void WebSocketChannel::handle_in(CommMessageIn *in)
{
	bool parse_websocket = false;

	pthread_mutex_lock(&this->mutex);

	if (this->state == WFT_STATE_UNDEFINED)
	{
		HttpResponse *resp = static_cast<HttpResponse *>(in);

		if (strcmp(resp->get_status_code(), "101") == 0)
			this->state = WFT_STATE_SUCCESS;
		else
			this->state = WFT_STATE_TASK_ERROR;

		delete resp;

		this->sending = false;
	}
	else if (this->state == WFT_STATE_SUCCESS)
		parse_websocket = true;

	pthread_mutex_unlock(&this->mutex);

	if (!parse_websocket) // so this is equal to should_count
	{
		WebSocketChannel *channel = static_cast<WebSocketChannel *>(this);
		pthread_mutex_lock(&channel->mutex);
		channel->condition.signal();
		pthread_mutex_unlock(&channel->mutex);
		return;
	}

	WFWebSocketChannel::handle_in(in);
	//if (this->parser->opcode == WebSocketFrameConnectionClose)
}

int WebSocketChannel::first_timeout()
{
	return WS_HANDSHAKE_TIMEOUT;
}

ChannelTask<protocol::WebSocketFrame> *WebSocketChannel::new_session()
{
	auto *task = new WebSocketInTask(this, this->scheduler,
									 nullptr, this->process);
	Workflow::create_series_work(task, nullptr);
	return task;
}

