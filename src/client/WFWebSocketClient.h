#ifndef _WFWEBSOCKETCLIENT_H_
#define _WFWEBSOCKETCLIENT_H_

#include "WFGlobal.h"
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "ComplexChannel.h"
#include "WebSocketTask.h"
#include "WebSocketMessage.h"

class WebSocketClient
{
public:
	WebSocketClient(websocket_process_t&& process) :
		channel(NULL, WFGlobal::get_scheduler(), std::move(process))
	{
	}

	int init(const std::string& url)
	{
		std::string tmp = url;
		if (tmp.find("ws://") != 0)
			tmp = "ws://" + tmp;

		ParsedURI uri;
		if (URIParser::parse(tmp, uri) != 0)
			return -1;

		this->channel.set_uri(uri);
		return 0;
	}

	WFWebSocketTask *create_websocket_task(websocket_callback_t&& cb)
	{
		return new WebSocketTask(&this->channel, WFGlobal::get_scheduler(),
								 std::move(cb));
	}

private:
	WFWebSocketChannel channel;
};

#endif

