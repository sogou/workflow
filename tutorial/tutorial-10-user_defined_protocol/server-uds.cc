/*
  Copyright (c) 2022 Sogou, Inc.

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

#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include "workflow/Workflow.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFServer.h"
#include "workflow/WFFacilities.h"
#include "message.h"

using WFTutorialTask = WFNetworkTask<protocol::TutorialRequest,
									 protocol::TutorialResponse>;
using WFTutorialServer = WFServer<protocol::TutorialRequest,
								  protocol::TutorialResponse>;

using namespace protocol;

void process(WFTutorialTask *task)
{
	TutorialRequest *req = task->get_req();
	TutorialResponse *resp = task->get_resp();
	void *body;
	size_t size;
	size_t i;

	req->get_message_body_nocopy(&body, &size);
	for (i = 0; i < size; i++)
		((char *)body)[i] = toupper(((char *)body)[i]);

	resp->set_message_body(body, size);
}

static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}

int main(int argc, char *argv[])
{
	struct sockaddr_un sun = { };

	if (argc != 2)
	{
		fprintf(stderr, "USAGE %s <path>\n", argv[0]);
		exit(1);
	}

	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, argv[1], sizeof sun.sun_path - 1);

	signal(SIGINT, sig_handler);

	struct WFServerParams params = SERVER_PARAMS_DEFAULT;
	params.request_size_limit = 4 * 1024;

	WFTutorialServer server(&params, process);
	if (server.start((struct sockaddr *)&sun, sizeof sun) == 0)
	{
		wait_group.wait();
		server.stop();
	}
	else
	{
		perror("server.start");
		exit(1);
	}

	return 0;
}

