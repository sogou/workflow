/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Li Yingxin (liyingxin@sogou-inc.com)
*/

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

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "USAGE: %s <url>\n	url format:ws://host:ip\n", argv[0]);
		return 0;
	}

	WebSocketClient client(process);
	client.init(argv[1]);

	WFFacilities::WaitGroup wg(1);
	auto *ping_task = client.create_websocket_task([&wg, &client](WFWebSocketTask *task)
	{
		fprintf(stderr, "PING task send callback() state=%d error=%d\n",
				task->get_state(), task->get_error());

		if (task->get_state() != WFT_STATE_SUCCESS)
		{
			wg.done();
			return;
		}

		sleep(5);

		auto *text_task = client.create_websocket_task([&wg, &client] (WFWebSocketTask *task)
		{
			fprintf(stderr, "TEXT task send callback() state=%d error=%d\n",
					task->get_state(), task->get_error());

			if (task->get_state() != WFT_STATE_SUCCESS)
			{
				wg.done();
				return;
			}

			auto *close_task = client.create_close_task([&wg](WFWebSocketTask *task)
			{
				fprintf(stderr, "CLOSE task callback() state=%d error=%d\n",
						task->get_state(), task->get_error());
				wg.done();
			});

			series_of(task)->push_back(close_task);
		});

		WebSocketFrame *msg = text_task->get_msg();
		msg->set_masking_key(1412);
		msg->set_text_data("20210607", 8, true);
		series_of(task)->push_back(text_task);
	});

	WebSocketFrame *msg = ping_task->get_msg();
	msg->set_opcode(WebSocketFramePing);
	ping_task->start();

	wg.wait();
	sleep(3);

	fprintf(stderr, "client deinit()\n");
	client.deinit();
	sleep(3);

	return 0;
}
