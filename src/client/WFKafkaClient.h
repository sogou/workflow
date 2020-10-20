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

  Authors: Wang Zhulei (wangzhulei@sogou-inc.com)
*/

#ifndef _WFKAFKACLIENT_H_
#define _WFKAFKACLIENT_H_


#include <string>
#include <vector>
#include <functional>
#include "KafkaMessage.h"
#include "KafkaResult.h"
#include "KafkaTaskImpl.inl"


class WFKafkaTask;
class WFKafkaClient;

using kafka_callback_t = std::function<void (WFKafkaTask *)>;
using kafka_partitioner_t = std::function<int (const char *topic_name,
											   const void *key,
											   size_t key_len,
											   int partition_num)>;

class WFKafkaTask : public WFGenericTask
{
public:
	virtual bool add_topic(const std::string& topic) = 0;

	virtual bool add_toppar(const protocol::KafkaToppar& toppar) = 0;

	virtual bool add_produce_record(const std::string& topic, int partition,
									protocol::KafkaRecord record) = 0;

	void add_commit_record(const protocol::KafkaRecord& record)
	{
		protocol::KafkaToppar toppar;
		toppar.set_topic_partition(record.get_topic(), record.get_partition());
		toppar.set_offset(record.get_offset());
		this->toppar_list.add_item(std::move(toppar));
	}

	void set_api_type(int api_type)
	{
		this->api_type = api_type;
	}

	int get_api_type() const
	{
		return this->api_type;
	}

	void set_config(protocol::KafkaConfig conf)
	{
		this->config = std::move(conf);
	}

	void set_partitioner(kafka_partitioner_t partitioner)
	{
		this->partitioner = std::move(partitioner);
	}

	protocol::KafkaResult *get_result()
	{
		return &this->result;
	}

	void set_callback(kafka_callback_t cb)
	{
		this->callback = std::move(cb);
	}

protected:
	WFKafkaTask(int retry_max, kafka_callback_t&& cb)
	{
		this->callback = std::move(cb);
		this->retry_max = retry_max;
		this->finish = false;
	}

	virtual ~WFKafkaTask() {}

	virtual SubTask *done();

protected:
	protocol::KafkaConfig config;
	protocol::KafkaTopparList toppar_list;
	protocol::KafkaMetaList meta_list;
	protocol::KafkaResult result;
	kafka_callback_t callback;
	kafka_partitioner_t partitioner;
	int api_type;
	int retry_max;
	bool finish;

private:
	friend class WFKafkaClient;
};

class WFKafkaClient
{
public:
	WFKafkaClient();

	// example: kafka://10.160.23.23:9000
	// example: kafka://kafka.sogou
	// example: kafka.sogou:9090
	// example: kafka://10.160.23.23:9000,10.123.23.23,kafka://kafka.sogou
	int init(const std::string& broker_url);

	int init(const std::string& broker_url, const std::string& group);

	void set_heartbeat_interval(size_t interval_ms);

	void deinit();

	// example: topic=xxx&topic=yyy&api=fetch
	// example: api=commit
	WFKafkaTask *create_kafka_task(const std::string& query,
								   int retry_max,
								   kafka_callback_t cb);

	WFKafkaTask *create_kafka_task(int retry_max, kafka_callback_t cb);

public:
	/* If you don't leavegroup manually, rebalance would be triggered */
	WFKafkaTask *create_leavegroup_task(int retry_max, 
										kafka_callback_t callback);

public:
	virtual ~WFKafkaClient();

	protocol::KafkaMetaList *get_meta_list();

	protocol::KafkaBrokerList *get_broker_list();

private:
	class KafkaMember *member;
	friend class ComplexKafkaTask;
};

#endif
