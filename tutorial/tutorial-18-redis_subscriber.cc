#include <cerrno>
#include <cctype>
#include <cstring>
#include <iostream>
#include <string>

#include "workflow/WFRedisSubscriber.h"
#include "workflow/WFFacilities.h"
#include "workflow/StringUtil.h"

void extract(WFRedisSubscribeTask *task)
{
	auto *resp = task->get_resp();
	protocol::RedisValue value;

	resp->get_result(value);

	if (value.is_array())
	{
		for (size_t i = 0; i < value.arr_size(); i++)
		{
			if (value[i].is_string())
				std::cout << value[i].string_value();
			else if (value[i].is_int())
				std::cout << value[i].int_value();
			else if (value[i].is_nil())
				std::cout << "nil";
			else
				std::cout << "Unexpected value in array!";

			std::cout << "\n";
		}
	}
	else
		std::cout << "Unexpected value!\n";
}

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		std::cerr << argv[0] << " <URL> <Channel> [<Channel>]..." << std::endl;
		exit(1);
	}

	std::string url = argv[1];
	if (strncasecmp(argv[1], "redis://", 8) != 0 &&
		strncasecmp(argv[1], "rediss://", 9) != 0)
	{
		url = "redis://" + url;
	}

	WFRedisSubscriber suber;

	if (suber.init(url) != 0)
	{
		std::cerr << "Subscriber init failed " << strerror(errno) << std::endl;
		exit(1);
	}

	std::vector<std::string> channels;
	for (int i = 2; i < argc; i++)
		channels.push_back(argv[i]);

	WFFacilities::WaitGroup wg(1);
	bool finished = false;

	auto callback = [&](WFRedisSubscribeTask *task)
	{
		std::cout << "state = " << task->get_state()
			<< ", error = " << task->get_error() << std::endl;

		finished = true;
		wg.done();
	};

	WFRedisSubscribeTask *task;
	task = suber.create_subscribe_task(channels, extract, callback);

	task->set_watch_timeout(1000000);
	task->start();

	std::string line;

	while (!finished)
	{
		std::string cmd;
		std::vector<std::string> params;

		if (std::getline(std::cin, line))
		{
			if (line.empty())
				continue;

			params = StringUtil::split_filter_empty(line, ' ');
		}

		if (finished)
			break;

		if (params.empty())
		{
			task->unsubscribe();
			task->punsubscribe();
			break;
		}

		cmd = params[0];
		params.erase(params.begin());

		for (char &c : cmd)
			c = std::toupper(c);

		int ret;
		if (cmd == "SUBSCRIBE")
			ret = task->subscribe(params);
		else if (cmd == "UNSUBSCRIBE")
			ret = task->unsubscribe(params);
		else if (cmd == "PSUBSCRIBE")
			ret = task->psubscribe(params);
		else if (cmd == "PUNSUBSCRIBE")
			ret = task->punsubscribe(params);
		else if (cmd == "PING")
		{
			if (params.empty())
				ret = task->ping();
			else
				ret = task->ping(params[0]);
		}
		else if (cmd == "QUIT")
			ret = task->quit();
		else
		{
			std::cerr << "Invalid command " << cmd << std::endl;
			ret = 0;
		}

		if (ret < 0)
		{
			std::cerr << "Send command failed " << strerror(errno) << std::endl;
			break;
		}
	}

	task->release();
	wg.wait();
	suber.deinit();

	return 0;
}
