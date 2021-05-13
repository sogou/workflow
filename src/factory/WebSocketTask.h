#ifndef _WFWEBSOCKETTASK_H_
#define _WFWEBSOCKETTASK_H_

#include "ComplexChannel.h"
#include "WFGlobal.h"
#include "HttpUtil.h"
#include "HttpMessage.h"
#include "WebSocketMessage.h"

using WFWebSocketTask = ComplexChannelOutTask<protocol::WebSocketFrame>;
using WFWebSocketChannel = ComplexChannel<protocol::WebSocketFrame>;

using websocket_callback_t = std::function<void (ChannelTask<protocol::WebSocketFrame> *)>;
using websocket_process_t = std::function<void (ChannelTask<protocol::WebSocketFrame> *)>;

class WebSocketChannel : public WFWebSocketChannel
{
public:
	WebSocketChannel(CommSchedObject *object, CommScheduler *scheduler,
					 websocket_process_t&& process) :
		WFWebSocketChannel(object, scheduler, std::move(process))
	{
	}

protected:
	CommMessageIn *message_in();
	void handle_in(CommMessageIn *in);
};

class WebSocketTask : public WFWebSocketTask
{
public:
	WebSocketTask(CommChannel *channel, CommScheduler *scheduler,
				  websocket_callback_t&& cb) :
		WFWebSocketTask(channel, scheduler, std::move(cb))
	{
	}

//	bool is_upgrading() const { return this->upgrading; }

protected:
	virtual SubTask *upgrade();
};

#endif

