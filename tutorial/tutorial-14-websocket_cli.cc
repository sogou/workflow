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
#include "workflow/WebSocketMessage.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "unistd.h"

using namespace protocol;

void process(WFWebSocketTask *task)
{
	const char *data;
	size_t size;

	if (task->get_msg()->get_opcode() == WebSocketFrameText)
	{
		task->get_msg()->get_data(&data, &size);
		fprintf(stderr, "get text message: [%.*s]\n", (int)size, data);
	}
	else
	{
		fprintf(stderr, "opcode=%d\n", task->get_msg()->get_opcode());
	}
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "USAGE: %s <url>\n	url format: ws://host:ip\n", argv[0]);
		return 0;
	}

	WebSocketClient client(process);
	client.init(argv[1]);

	WFFacilities::WaitGroup wg(1);
	auto *task = client.create_websocket_task([&wg, &client] (WFWebSocketTask *task)
	{
		fprintf(stderr, "send callback() state=%d error=%d\n",
				task->get_state(), task->get_error());

		if (task->get_state() != WFT_STATE_SUCCESS)
		{
			wg.done();
			return;
		}

		auto *close_task = client.create_close_task([&wg] (WFWebSocketTask *task) {
			wg.done();
		});

		series_of(task)->push_back(close_task);
	});

	WebSocketFrame *msg = task->get_msg();
	msg->set_text_data("This is Workflow websocket client.");
	task->start();

	wg.wait();

	return 0;
}
