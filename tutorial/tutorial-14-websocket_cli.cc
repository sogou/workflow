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
	fprintf(stderr, "process. opcode=%d\n",
			task->get_message()->get_opcode());
}

int main()
{
	WebSocketClient client(process);
	client.init("ws:://127.0.0.1:9001");

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
		msg->set_text_data("xiehan", 6, true);
		text_task->start();
	});

	WebSocketFrame *msg = ping_task->get_message();
	msg->set_opcode(WebSocketFramePing);
	msg->set_masking_key(0); //TODO
	ping_task->start();

	wg.wait();

	return 0;
}
