#include "workflow/WFFacilities.h"
#include "workflow/WFWebSocketClient.h"

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include "unistd.h"

#define CONNECT_TIMEOUT 10000

using namespace protocol;

void process(ChannelTask<WebSocketFrame> *task)
{
	fprintf(stderr, "process. state=%d error=%d opcode=%d\n",
			task->get_state(), task->get_error(), task->get_message()->get_opcode());
}

void channel_callback(WFChannel<protocol::WebSocketFrame> *channel)
{
	fprintf(stderr, "channel callback. state=%d error=%d established=%d\n",
			channel->get_state(), channel->get_error(), channel->is_established());
}

int main()
{
	WebSocketClient client(process);
	client.init("ws://10.129.43.67:9001");
	client.set_callback(channel_callback);

	WFFacilities::WaitGroup wg(1);
	auto *ping_task = client.create_websocket_task([&wg, &client](ChannelTask<WebSocketFrame> *task){
		fprintf(stderr, "PING task on_send() state=%d error=%d\n",
				task->get_state(), task->get_error());

		auto *text_task = client.create_websocket_task([&wg] (ChannelTask<WebSocketFrame> *task)
		{
			fprintf(stderr, "TEXT task on_send() state=%d error=%d\n",
					task->get_state(), task->get_error());
			wg.done();
		});
		WebSocketFrame *msg = text_task->get_message();
		msg->set_masking_key(1412);
		msg->set_text_data("20210521", 8, true);
		text_task->start();
	});

	WebSocketFrame *msg = ping_task->get_message();
	msg->set_opcode(WebSocketFramePing);
	ping_task->start();

	wg.wait();
	sleep(3);
	client.deinit();
	sleep(2);

	return 0;
}
