#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <utility>
#include <string>
#include <unordered_map>
#include "workflow/HttpMessage.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/Workflow.h"
#include "workflow/WFFacilities.h"

using namespace protocol;

static WFFacilities::WaitGroup wait_group(1);

void file_sync_callback(WFFileSyncTask *task)
{
	long ret = task->get_retval();

	if (task->get_state() != WFT_STATE_SUCCESS || ret < 0)
	{
		fprintf(stderr, "failed to write value into file, state: %d, ret: %ld, error: %d, error_str: %s\n", task->get_state(), ret, task->get_error(), strerror(task->get_error()));
	}
	else
	{
		fprintf(stderr, "success to write value into file, ret: %d\n", ret);
	}
	wait_group.done();
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "%s filename\n", argv[0]);
		exit(1);
	}

	std::string filename = argv[1];
	WFFileSyncTask *task = WFTaskFactory::create_fdsync_task(filename, file_sync_callback);
	task->start();

	wait_group.wait();
	return 0;
}
