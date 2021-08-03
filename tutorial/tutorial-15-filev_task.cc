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

static WFFacilities::WaitGroup *wait_group;

void file_pwrite_callback(WFFileVIOTask *task)
{
	long ret = task->get_retval();

	if (task->get_state() != WFT_STATE_SUCCESS || ret < 0)
	{
		fprintf(stderr, "failed to write value into file, state: %d, ret: %ld, error: %d, error_str: %s\n", task->get_state(), ret, task->get_error(), strerror(task->get_error()));
	}
	else
	{
		fprintf(stderr, "success to write value into file\n");
	}
	wait_group->done();
}

void file_pread_callback(WFFileVIOTask *task)
{
	long ret = task->get_retval();
	FileVIOArgs *args = task->get_args();

	if (task->get_state() != WFT_STATE_SUCCESS || ret < 0)
	{
		fprintf(stderr, "failed to read value from file, state: %d, ret: %ld, error: %d, erron_str: %s\n", task->get_state(), ret, task->get_error(), strerror(task->get_error()));
	}
	else
	{
		fprintf(stderr, "success to read file, value: %s, size: %ld\n", static_cast<char*>(args->iov->iov_base), ret);
	}
	wait_group->done();
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "%s filename value\n", argv[0]);
		exit(1);
	}

	wait_group = new WFFacilities::WaitGroup(1);
	std::string filename = argv[1];
	std::string value = argv[2];
	struct iovec iov =
	{
		.iov_base = const_cast<char*>(value.c_str()),
		.iov_len = value.size(),
	};
	WFFileVIOTask *file_task = WFTaskFactory::create_pwritev_task(filename, &iov, 1, 0, file_pwrite_callback);
	file_task->start();
	wait_group->wait();
	delete wait_group;
	wait_group = nullptr;

	wait_group = new WFFacilities::WaitGroup(1);
	void *buffer = malloc(10);
	struct iovec read_iov = 
	{
		.iov_base = buffer,
		.iov_len = 1024,
	};
	// struct iovec read_iov;
	WFFileVIOTask *read_task = WFTaskFactory::create_preadv_task(filename, &read_iov, 1, 0, file_pread_callback);
	read_task->start();
	wait_group->wait();
	free(buffer);
	return 0;
}
