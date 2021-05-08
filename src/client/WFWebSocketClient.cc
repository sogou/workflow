#include "WFWebSocketClient.h"

#define WS_HTTP_SEC_KEY_K		"Sec-WebSocket-Key"
#define WS_HTTP_SEC_KEY_V		"dGhlIHNhbXBsZSBub25jZQ=="
#define WS_HTTP_SEC_PROTOCOL_K	"Sec-WebSocket-Protocol"
#define WS_HTTP_SEC_PROTOCOL_V	"chat"
#define WS_HTTP_SEC_VERSION_K	"Sec-WebSocket-Version"
#define WS_HTTP_SEC_VERSION_V	"13"

template<>
void WFWebSocketTask::dispatch()
{
	if (this->channel->get_state() == CHANNEL_STATE_UNDEFINED) //get_seq
	{
		WebSocketClient *client = static_cast<WebSocketClient *>(this->get_sched_channel());
		WFRouterTask *task = client->route();
		series_of(this)->push_front(this);
		series_of(this)->push_front(task);
	}
	else
		ChannelRequest::dispatch();
}

WFRouterTask *WebSocketClient::route()
{
	auto&& cb = std::bind(&WebSocketClient::router_callback,
						  this, std::placeholders::_1);
	struct WFNSParams params = {
		.type			=	type_,
		.uri			=	uri_,
		.info			=	info_.c_str(),
		.fixed_addr		=	fixed_addr_,
		.retry_times	=	retry_times_,
		.tracing		=	&tracing_,
	};

	WFNameService *ns = WFGlobal::get_name_service();
	WFNSPolicy *policy = ns->get_policy(this->uri.host ? this->uri.host : "");
	return policy->create_router_task(&params, cb);
}

void WebSocketClient::router_callback(WFRouterTask *task)
{
	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		this->object = task->get_result()->request_object;

		auto&& cb = std::bind(&WebSocketClient::establish_callback,
							  this, std::placeholders::_1);

		this->establish_session = new WFEstablishTask(this, this->scheduler,
													  this->object, this->wait_timeout,
													  &this->target, cb);
		series_of(this)->push_front(this->establish_task);
	}
	else
	{
//		if (this->state == WFT_STATE_SYS_ERROR)
//			ns_policy_->failed(&route_result_, &tracing_, this->target);
		this->state = CHANNEL_STATE_ERROR;
		this->error = task->get_error();
	}
}

void WebSocketClient::establish_callback(WFEstablishTask *task)
{
	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		ChannelTask<HttpRequest> *http_task;
		auto&& cb = std::bind(&WebSocketClient::http_callback,
							  this, std::placeholders::_1);

		http_task = new ChannelTask<HttpRequest>(this, this->scheduler,
												 nullptr, cb);
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

		series_of(task)->push_front(http_task);
	}
	else
	{
		this->state = CHANNEL_STATE_ERROR;
		this->error = task->get_error();
	}
}

void WebSocketClient::http_callback(ChannelTask<HttpRequest> *task)
{
	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		this->counter = new WFCounterTask(1, nullptr);
		series_of(task)->push_front(this->counter);
	}
	else
	{
		this->state = CHANNEL_STATE_ERROR;
		this->error = task->get_error();
	}
}

CommMessageIn *WebSocketClient::message_in()
{
	fprintf(stderr, "WebSocketChannel::message_in() state=%d\n", this->state);

	if (this->state == CHANNEL_STATE_UNDEFINED)
		return new HttpResponse;

	return WFWebSocketChannel::message_in();
}

void WebSocketClient::handle_in(CommMessageIn *in)
{
	if (this->state == CHANNEL_STATE_UNDEFINED)
	{
		HttpResponse *resp = static_cast<HttpResponse *>(in);

		if (strcmp(resp->get_status_code(), "101") == 0)
			this->state = CHANNEL_STATE_ESTABLISHED;
		else
			this->state = CHANNEL_STATE_ERROR;

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
		//TODO
		//if (this->parser->opcode == WebSocketFrameConnectionClose)
	}
}

~WebSocketClient::WebSocketClient()
{
	if (this->state == CHANNEL_STATE_ESTABLISHED)
	{
		WFWebSocketTask *task = this->create_task(nullptr);
		protocol::WebSocketFrame *msg = task->get_message();
		msg->set_opcode(WebSocketFrameConnectionClose);
		task->start();
	}
}

/*
void WebSocketClient::close_callback(WFWebSocketTask *)
{
	this->shutdown();
}
*/
};

