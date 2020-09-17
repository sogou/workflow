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

  Author: Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <gtest/gtest.h>

#include "workflow/WFKafkaClient.h"
#include "workflow/KafkaMessage.h"
#include "workflow/KafkaResult.h"
#include "workflow/WFTaskFactory.h"
#include "workflow/WFFacilities.h"
#include "workflow/WFGlobal.h"

using namespace protocol;
const char *URL = "10.160.32.25";
const char *KEY1 = "workflow_unittest_kafka_key_1";
const char *VALUE1 = "workflow_unittest_kafka_value_1";
const char *TOPIC1 = "workflow_unittest_kafka_topic_1";
const char *PAIR_KEY = "hk1";
const char *PAIR_VALUE = "hv1";

TEST(kafka_produce, kafka_client_unittest)
{
	WFKafkaClient kafka_client;
	KafkaConfig config;
	KafkaRecord record;
	WFFacilities::WaitGroup wg(1);

	// 1. client
	kafka_client.init(URL);

	// 2. config
	config.set_compress_type(Kafka_NoCompress); // Kafka_Zstd

	// 3. record
	record.set_key(KEY1, strlen(KEY1));
	record.set_value(VALUE1, strlen(VALUE1));
	record.add_header_pair(PAIR_KEY, strlen(PAIR_KEY), PAIR_VALUE, strlen(PAIR_VALUE));

	// 4. task
	WFKafkaTask *task = kafka_client.create_kafka_task("api=produce", 3, [&wg](WFKafkaTask *task) {
		int state = task->get_state();
		EXPECT_EQ(state, WFT_STATE_SUCCESS);

		// 5. records
		std::vector<std::vector<KafkaRecord *>> records;
		task->get_result()->fetch_records(records);
		EXPECT_EQ(records.size(), 1);

		for (const auto &v : records)
		{
			EXPECT_EQ(v.size(), 1);
			for (const auto &w: v)
			{
//				fprintf(stderr, "produce topic: %s, partition: %d, status: %d,",
//						" offset: %lld, val_len: %zu\n",
//						w->get_topic(), w->get_partition(), w->get_status(),
//						w->get_offset(), w->get_value_len());

				EXPECT_TRUE(strcmp(w->get_topic(), TOPIC1) == 0);
				EXPECT_EQ(w->get_partition(), 0);
				EXPECT_EQ(w->get_status(), 0);
				EXPECT_EQ(w->get_value_len(), strlen(VALUE1));
			}
		}

		wg.done();
	});
	task->set_config(std::move(config));
	task->add_produce_record(TOPIC1, -1, std::move(record));

	// 5. run
	task->start();
	wg.wait();
	kafka_client.deinit();
}

TEST(kafka_meta, kafka_client_unittest)
{
	WFKafkaClient kafka_client;
	KafkaConfig config;
	KafkaRecord record;
	WFFacilities::WaitGroup wg(1);

	kafka_client.init(URL);
	WFKafkaTask *task = kafka_client.create_kafka_task(3, [&wg, &kafka_client](WFKafkaTask *task) {
		int state = task->get_state();
		EXPECT_EQ(state, WFT_STATE_SUCCESS);

		KafkaMetaList *meta_list = kafka_client.get_meta_list();
		KafkaMeta *meta = meta_list->get_next();
		EXPECT_TRUE(meta);

		while (meta)
		{
			EXPECT_TRUE(strcmp(meta->get_topic(), TOPIC1) == 0);
			EXPECT_GT(meta->get_partition_elements(), 0);
//			fprintf(stderr, "check meta\ttopic: %s, partition_num: %d\n",
//					(char *)meta->get_topic(), meta->get_partition_elements());
			meta = meta_list->get_next();
		}

		wg.done();
	});

	task->set_api_type(Kafka_Metadata);
	task->add_topic(TOPIC1);

	task->start();
	wg.wait();
	kafka_client.deinit();
}

TEST(kafka_fetch, kafka_client_unittest)
{
	WFKafkaClient kafka_client;
	KafkaConfig config;
	KafkaRecord record;
	WFFacilities::WaitGroup wg(1);

	kafka_client.init(URL);

	KafkaToppar toppar;
	toppar.set_topic_partition(TOPIC1, 0);
	toppar.set_offset(0);

	WFKafkaTask *task = kafka_client.create_kafka_task("api=fetch", 3, [&wg, &kafka_client](WFKafkaTask *task) {
		int state = task->get_state();
		EXPECT_EQ(state, WFT_STATE_SUCCESS);

		std::vector<std::vector<KafkaRecord *>> records;

		task->get_result()->fetch_records(records);

		EXPECT_TRUE(!records.empty());

		if (!records.empty())
		{
			for (const auto &v : records)
			{
				EXPECT_TRUE(!v.empty());

//				fprintf(stderr, "[v] topic: %s partition: %d offset: %llu\n",
//						(char *)v.back()->get_topic(),
//						v.back()->get_partition(),
//						v.back()->get_offset());

				EXPECT_TRUE(strcmp(v.back()->get_topic(), TOPIC1) == 0);
				EXPECT_EQ(v.back()->get_partition(), 0);
//				EXPECT_GT(v.back()->get_offset(), 0);

				for (const auto &w : v)
				{
					char value[100];

					snprintf(value, 100, "%s%s%s", VALUE1, PAIR_KEY, PAIR_VALUE);
//					fprintf(stderr, "[w] value: %s len: %zu\n",
//							(char *)w->get_value(), w->get_value_len());

					EXPECT_TRUE(strcmp((char *)w->get_value(), value));
				}
			}
		}

		wg.done();
	});

	task->add_toppar(toppar);

	task->start();
	wg.wait();
	kafka_client.deinit();
}
