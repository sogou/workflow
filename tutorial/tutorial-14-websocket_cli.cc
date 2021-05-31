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

void process(WFWebSocketTask *task)
{
	fprintf(stderr, "process. state=%d error=%d opcode=%d ",
			task->get_state(), task->get_error(),
			task->get_msg()->get_opcode());

	if (task->get_msg()->get_opcode() == WebSocketFrameText)
	{
		const char *data;
		size_t size;
		task->get_msg()->get_text_data(&data, &size);
		fprintf(stderr, "get message: len=%zu [%.*s]\n", size, (int)size, data);
	}
	else
	{
		fprintf(stderr, "\n");
	}
}

/*
void channel_callback(WFChannel<protocol::WebSocketFrame> *channel)
{
	fprintf(stderr, "channel callback. state=%d error=%d established=%d\n",
			channel->get_state(), channel->get_error(), channel->is_established());
}
*/

int main()
{
	WebSocketClient client(process);
	client.init("ws://10.129.43.67:9001");

	WFFacilities::WaitGroup wg(1);
	auto *ping_task = client.create_websocket_task([&wg, &client](WFWebSocketTask *task){
		fprintf(stderr, "PING task on_send() state=%d error=%d\n",
				task->get_state(), task->get_error());

		auto *text_task = client.create_websocket_task([&wg] (WFWebSocketTask *task)
		{
			fprintf(stderr, "TEXT task on_send() state=%d error=%d\n",
					task->get_state(), task->get_error());
			wg.done();
		});
		WebSocketFrame *msg = text_task->get_msg();
		msg->set_masking_key(1412);
		msg->set_text_data("20210531", 8, true);
		text_task->start();
	});

	WebSocketFrame *msg = ping_task->get_msg();
	msg->set_opcode(WebSocketFramePing);
	ping_task->start();

	wg.wait();
	sleep(3);
	fprintf(stderr, "client deinit()\n");
	client.deinit();

	return 0;
}
