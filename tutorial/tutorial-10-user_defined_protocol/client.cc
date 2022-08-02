/*
  Copyright (c) 2020 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com;63350856@qq.com)
*/

#include <string.h>
#include <stdio.h>
#include "workflow/Workflow.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"
#include "message.h"

using WFTutorialTask = WFNetworkTask<protocol::TutorialRequest,
									 protocol::TutorialResponse>;
using tutorial_callback_t = std::function<void (WFTutorialTask *)>;

using namespace protocol;

class MyFactory : public WFTaskFactory
{
public:
	static WFTutorialTask *create_tutorial_task(const std::string& host,
												unsigned short port,
												int retry_max,
												tutorial_callback_t callback)
	{
		using NTF = WFNetworkTaskFactory<TutorialRequest, TutorialResponse>;
		WFTutorialTask *task = NTF::create_client_task(TT_TCP, host, port,
													   retry_max,
													   std::move(callback));
		task->set_keep_alive(30 * 1000);
		return task;
	}
};

int main(int argc, char *argv[])
{
	unsigned short port;
	std::string host;

	if (argc != 3)
	{
		fprintf(stderr, "USAGE: %s <host> <port>\n", argv[0]);
		exit(1);
	}

	host = argv[1];
	port = atoi(argv[2]);

	auto&& create = [host, port](WFRepeaterTask *)->SubTask *{
		char buf[1024];
		printf("Input next request string (Ctrl-D to exit): ");
		*buf = '\0';
		scanf("%1023s", buf);
		size_t body_size = strlen(buf);
		if (body_size == 0)
		{
			printf("\n");
			return NULL;
		}

		WFTutorialTask *task = MyFactory::create_tutorial_task(host, port, 0,
											[](WFTutorialTask *task) {
			int state = task->get_state();
			int error = task->get_error();
			TutorialResponse *resp = task->get_resp();
			void *body;
			size_t body_size;

			if (state == WFT_STATE_SUCCESS)
			{
				resp->get_message_body_nocopy(&body, &body_size);
				printf("Server Response: %.*s\n", (int)body_size, (char *)body);
			}
			else
			{
				const char *str = WFGlobal::get_error_string(state, error);
				fprintf(stderr, "Error: %s\n", str);
			}
		});

		task->get_req()->set_message_body(buf, body_size);
		task->get_resp()->set_size_limit(4 * 1024);
		return task;
	};

	WFFacilities::WaitGroup wait_group(1);

	WFRepeaterTask *repeater;
	repeater = WFTaskFactory::create_repeater_task(std::move(create), nullptr);
	Workflow::start_series_work(repeater, [&wait_group](const SeriesWork *) {
		wait_group.done();
	});

	wait_group.wait();
	return 0;
}

