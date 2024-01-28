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

  Author: Wang Zhulei (wangzhulei@sogou-inc.com)
*/

#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include "workflow/WFKafkaClient.h"
#include "workflow/KafkaMessage.h"
#include "workflow/KafkaResult.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"
#include "workflow/WFGlobal.h"

using namespace protocol;

static WFFacilities::WaitGroup wait_group(1);

std::string url;
bool no_cgroup = false;
WFKafkaClient client;

void kafka_callback(WFKafkaTask *task)
{
	int state = task->get_state();
	int error = task->get_error();

	if (state != WFT_STATE_SUCCESS)
	{
		fprintf(stderr, "error msg: %s\n",
				WFGlobal::get_error_string(state, error));
		fprintf(stderr, "Failed. Press Ctrl-C to exit.\n");
		client.deinit();
		wait_group.done();
		return;
	}

	WFKafkaTask *next_task = NULL;
	std::vector<std::vector<KafkaRecord *>> records;
	std::vector<KafkaToppar *> toppars;
	int api_type = task->get_api_type();

	protocol::KafkaResult new_result;

	switch (api_type)
	{
	case Kafka_Produce:
		task->get_result()->fetch_records(records);

		for (const auto &v : records)
		{
			for (const auto &w: v)
			{
				const void *value;
				size_t value_len;
				w->get_value(&value, &value_len);
				printf("produce\ttopic: %s, partition: %d, status: %d, \
						offset: %lld, val_len: %zu\n",
					   w->get_topic(), w->get_partition(), w->get_status(),
					   w->get_offset(), value_len);
			}
		}

		break;

	case Kafka_Fetch:
		new_result = std::move(*task->get_result());
		new_result.fetch_records(records);

		if (!records.empty())
		{
			if (!no_cgroup)
				next_task = client.create_kafka_task("api=commit", 3, kafka_callback);

			std::string out;

			for (const auto &v : records)
			{
				if (v.empty())
					continue;

				char fn[1024];
				snprintf(fn, 1024, "/tmp/kafka.%s.%d.%llu",
						 v.back()->get_topic(), v.back()->get_partition(),
						 v.back()->get_offset());

				FILE *fp = fopen(fn, "w+");
				long long offset = 0;
				int partition = 0;
				std::string topic;

				for (const auto &w : v)
				{
					const void *value;
					size_t value_len;
					w->get_value(&value, &value_len);
					if (fp)
						fwrite(value, value_len, 1, fp);

					offset = w->get_offset();
					partition = w->get_partition();
					topic = w->get_topic();

					if (!no_cgroup)
						next_task->add_commit_record(*w);
				}

				if (!topic.empty())
				{
					out += "topic: "	  + topic;
					out += ",partition: " + std::to_string(partition);
					out += ",offset: "	  + std::to_string(offset) + ";";
				}

				if (fp)
					fclose(fp);
			}

			printf("fetch\t%s\n", out.c_str());

			if (!no_cgroup)
				series_of(task)->push_back(next_task);
		}

		break;

	case Kafka_OffsetCommit:
		task->get_result()->fetch_toppars(toppars);

		if (!toppars.empty())
		{
			for (const auto& v : toppars)
			{
				printf("commit\ttopic: %s, partition: %d, \
						offset: %llu, error: %d\n",
					   v->get_topic(), v->get_partition(),
					   v->get_offset(), v->get_error());
			}
		}

		next_task = client.create_leavegroup_task(3, kafka_callback);

		series_of(task)->push_back(next_task);

		break;

	case Kafka_LeaveGroup:
		printf("leavegroup callback\n");
		break;

	default:
		break;
	}

	if (!next_task)
	{
		client.deinit();
		wait_group.done();
	}
}

void sig_handler(int signo) { }

int main(int argc, char *argv[])
{
	if (argc < 3)
	{
		fprintf(stderr, "USAGE: %s url <p/c> [compress_type/d]\n", argv[0]);
		exit(1);
	}

	signal(SIGINT, sig_handler);

	url = argv[1];
	if (strncmp(argv[1], "kafka://", 8) != 0 &&
		strncmp(argv[1], "kafkas://", 9) != 0)
	{
		url = "kafka://" + url;
	}

	char buf[512 * 1024];
	WFKafkaTask *task;

	if (argv[2][0] == 'p')
	{
		int compress_type = Kafka_NoCompress;

		if (argc > 3)
			compress_type = atoi(argv[3]);

		if (compress_type > Kafka_Zstd)
			exit(1);

		if (client.init(url) < 0)
		{
			perror("client.init");
			exit(1);
		}

		task = client.create_kafka_task("api=produce", 3, kafka_callback);
		KafkaConfig config;
		KafkaRecord record;

		config.set_compress_type(compress_type);
		config.set_client_id("workflow");
		task->set_config(std::move(config));

		for (size_t i = 0; i < sizeof (buf); ++i)
			buf[i] = '1' + rand() % 128;

		record.set_key("key1", strlen("key1"));
		record.set_value(buf, sizeof (buf));
		record.add_header_pair("hk1", 3, "hv1", 3);
		task->add_produce_record("workflow_test1", -1, std::move(record));

		record.set_key("key2", strlen("key2"));
		record.set_value(buf, sizeof (buf));
		record.add_header_pair("hk2", 3, "hv2", 3);
		task->add_produce_record("workflow_test2", -1, std::move(record));
	}
	else if (argv[2][0] == 'c')
	{
		if (argc > 3 && argv[3][0] == 'd')
		{
			if (client.init(url) < 0)
			{
				perror("client.init");
				exit(1);
			}

			task = client.create_kafka_task("api=fetch", 3, kafka_callback);

			KafkaToppar toppar;
			toppar.set_topic_partition("workflow_test1", 0);
			toppar.set_offset(0);
			task->add_toppar(toppar);

			toppar.set_topic_partition("workflow_test2", 0);
			toppar.set_offset(1);
			task->add_toppar(toppar);

			no_cgroup = true;
		}
		else
		{
			if (client.init(url, "workflow_group") < 0)
			{
				perror("client.init");
				exit(1);
			}

			task = client.create_kafka_task("topic=workflow_test1&topic=workflow_test2&api=fetch",
											3, kafka_callback);
		}

		KafkaConfig config;
		config.set_client_id("workflow");
		task->set_config(std::move(config));
	}
	else
	{
		fprintf(stderr, "USAGE: %s url <p/c> [compress_type/d]\n", argv[0]);
		exit(1);
	}

	task->start();

	wait_group.wait();

	return 0;
}
