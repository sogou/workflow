#ifndef _WFWEBSOCKETTASK_H_
#define _WFWEBSOCKETTASK_H_

#include "ComplexChannel.h"
#include "WFGlobal.h"
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "WebSocketMessage.h"

using WFWebSocketTask = WFChannelTask<protocol::WebSocketFrame>;

using WFWebSocketComplexTask = ComplexChannelOutTask<protocol::WebSocketFrame>;
using WFWebSocketChannel = ComplexChannel<protocol::WebSocketFrame>;

using websocket_callback_t = std::function<void (WFWebSocketTask *)>;
using websocket_process_t = std::function<void (WFWebSocketTask *)>;

class WebSocketChannel : public WFWebSocketChannel
{
public:
	WebSocketChannel(CommSchedObject *object, CommScheduler *scheduler,
					 websocket_process_t&& process) :
		WFWebSocketChannel(object, scheduler, std::move(process))
	{
		this->idle_timeout = WS_HANDSHAKE_TIMEOUT;
	}

	void set_idle_timeout(int timeout) { this->idle_timeout = timeout; }

protected:
	CommMessageIn *message_in();
	void handle_in(CommMessageIn *in);
	int first_timeout();
	virtual WFWebSocketTask *new_session();

private:
	int idle_timeout;
};

class WebSocketTask : public WFWebSocketComplexTask
{
public:
	WebSocketTask(WebSocketChannel *channel, CommScheduler *scheduler,
				  websocket_callback_t&& cb) :
		WFWebSocketComplexTask(channel, scheduler, std::move(cb))
	{
	}

private:
	void http_callback(WFChannelTask<protocol::HttpRequest> *task);

protected:
	virtual SubTask *upgrade();
};

#endif

