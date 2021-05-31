#ifndef _WFWEBSOCKETCLIENT_H_
#define _WFWEBSOCKETCLIENT_H_

#include "WFGlobal.h"
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "ComplexChannel.h"
#include "WebSocketTask.h"
#include "WebSocketMessage.h"

struct WFWebSocketParams
{
	int idle_timeout;
	int ping_interval;
	bool random_masking_key;
};

static constexpr struct WFWebSocketParams WEBSOCKET_PARAMS_DEFAULT =
{
	.idle_timeout = WS_HANDSHAKE_TIMEOUT,
	.ping_interval = -1,
	.random_masking_key = false,
};

class WebSocketClient
{
public:
	WebSocketClient(const struct WFWebSocketParams *params,
					websocket_process_t process)
	{
		this->params = *params;
		this->channel = new WebSocketChannel(NULL, WFGlobal::get_scheduler(),
											 std::move(process));
		this->channel->set_idle_timeout(this->params.idle_timeout);
	}

	WebSocketClient(websocket_process_t process)
	{
		this->params = WEBSOCKET_PARAMS_DEFAULT;
		this->channel = new WebSocketChannel(NULL, WFGlobal::get_scheduler(),
											 std::move(process));
		this->channel->set_idle_timeout(this->params.idle_timeout);
	}

	int init(const std::string& url)
	{
		std::string tmp = url;
		if (tmp.find("ws://") != 0)
			tmp = "ws://" + tmp;

		ParsedURI uri;
		if (URIParser::parse(tmp, uri) != 0)
			return -1;

		this->channel->set_uri(uri);
		return 0;
	}

	WFWebSocketTask *create_websocket_task(websocket_callback_t cb)
	{
		return new WebSocketTask(this->channel, WFGlobal::get_scheduler(),
								 std::move(cb));
	}

	void deinit()
	{
		if (this->channel->is_established())
		{
			WFWebSocketTask *task = this->create_websocket_task(
				[](WFWebSocketTask *task){

					WebSocketChannel *channel = (WebSocketChannel *)task->user_data;
					if (task->get_state() == WFT_STATE_SUCCESS &&
						channel->is_established())
					{
						Workflow::start_series_work(channel, nullptr);
						channel->set_sending(true);
					}
				}
			);
			protocol::WebSocketFrame *msg = task->get_msg();
			msg->set_opcode(WebSocketFrameConnectionClose);
			task->user_data = this->channel;
			task->start();
		}
	}

private:
	WebSocketChannel *channel;
	struct WFWebSocketParams params;
};

#endif

