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

  Author: Wang Zhulei(wangzhulei@sogou-inc.com)
*/

#ifndef _KAFKAMESSAGE_H_
#define _KAFKAMESSAGE_H_

#include <string.h>
#include <utility>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include "ProtocolMessage.h"
#include "EncodeStream.h"
#include "kafka_parser.h"
#include "KafkaDataTypes.h"


namespace protocol
{

class KafkaMessage : public ProtocolMessage
{
public:
	KafkaMessage();

	virtual ~KafkaMessage();

private:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

	int encode_head();

public:
	KafkaMessage(KafkaMessage&& msg);
	KafkaMessage& operator= (KafkaMessage&& msg);

public:
	int encode_message(int api_type, struct iovec vectors[], int max);

	void set_api(int api_type) { this->api_type = api_type; }
	int get_api() const { return this->api_type; }

	void set_api_version(int ver) { this->api_version = ver; }
	int get_api_version() const { return this->api_version; }

	void set_config(const KafkaConfig& conf)
	{
		this->config = conf;
	}
	const KafkaConfig *get_config() const { return &this->config; }

	void set_cgroup(const KafkaCgroup& cgroup)
	{
		this->cgroup = cgroup;
	}
	KafkaCgroup *get_cgroup()
	{
		return &this->cgroup;
	}

	void set_broker(const KafkaBroker& broker)
	{
		this->broker = broker;
	}
	KafkaBroker *get_broker()
	{
		return &this->broker;
	}

	void set_meta_list(const KafkaMetaList& meta_list)
	{
		this->meta_list = meta_list;
	}
	KafkaMetaList *get_meta_list()
	{
		return &this->meta_list;
	}

	void set_toppar_list(const KafkaTopparList& toppar_list)
	{
		this->toppar_list = toppar_list;
	}
	KafkaTopparList *get_toppar_list()
	{
		return &this->toppar_list;
	}

	void set_broker_list(const KafkaBrokerList& broker_list)
	{
		this->broker_list = broker_list;
	}
	KafkaBrokerList *get_broker_list()
	{
		return &this->broker_list;
	}

	void duplicate(KafkaMessage& msg)
	{
		this->config = msg.config;
		this->cgroup = msg.cgroup;
		this->broker = msg.broker;
		this->meta_list = msg.meta_list;
		this->broker_list = msg.broker_list;
		this->toppar_list = msg.toppar_list;
	}

	void duplicate2(KafkaMessage& msg)
	{
		kafka_parser_deinit(this->parser);
		delete this->parser;
		this->config = msg.config;
		this->cgroup = msg.cgroup;
		this->broker = msg.broker;
		this->meta_list = msg.meta_list;
		this->broker_list = msg.broker_list;
		this->toppar_list = msg.toppar_list;
		this->uncompressed = msg.uncompressed;
		this->parser = msg.parser;
		msg.parser = new kafka_parser_t;
		kafka_parser_init(msg.parser);
	}

	void clear_buf()
	{
		this->msgbuf.clear();
		this->headbuf.clear();
		kafka_parser_deinit(this->parser);
		kafka_parser_init(this->parser);
	}

protected:
	static int parse_message_set(void **buf, size_t *size, int msg_vers,
								 struct list_head *record_list,
								 KafkaBuffer *uncompressed,
								 KafkaToppar *toppar);

	static int parse_records(void **buf, size_t *size,
							 struct list_head *record_list,
							 KafkaBuffer *uncompressed,
							 KafkaToppar *toppar);

	static std::string get_member_assignment(kafka_member_t *member);

	static KafkaToppar *find_toppar_by_name(const std::string& topic, int partition,
											struct list_head *toppar_list);

	static KafkaToppar *find_toppar_by_name(const std::string& topic, int partition,
											KafkaTopparList *toppar_list);

	static int kafka_parse_member_assignment(const char *bbuf, size_t n,
											 KafkaCgroup *cgroup);

protected:
	kafka_parser_t *parser;
	using encode_func = std::function<int (struct iovec vectors[], int max)>;
	std::map<int, encode_func> encode_func_map;

	using parse_func = std::function<int (void **buf, size_t *size)>;
	std::map<int, parse_func> parse_func_map;

	EncodeStream *stream;
	std::string msgbuf;
	std::string headbuf;

	KafkaConfig config;
	KafkaCgroup cgroup;
	KafkaBroker broker;
	KafkaMetaList meta_list;
	KafkaBrokerList broker_list;
	KafkaTopparList toppar_list;
	KafkaBuffer serialized;
	KafkaBuffer uncompressed;

	int api_type;
	int api_version;
	int message_version;

	std::map<int, int> api_mver_map;

	void *compress_env;
	size_t cur_size;
};

class KafkaRequest : public KafkaMessage
{
public:
	KafkaRequest()
	{
		using namespace std::placeholders;
		this->encode_func_map[Kafka_Metadata] = std::bind(&KafkaRequest::encode_metadata, this, _1, _2);
		this->encode_func_map[Kafka_Produce] = std::bind(&KafkaRequest::encode_produce, this, _1, _2);
		this->encode_func_map[Kafka_Fetch] = std::bind(&KafkaRequest::encode_fetch, this, _1, _2);
		this->encode_func_map[Kafka_FindCoordinator] = std::bind(&KafkaRequest::encode_findcoordinator, this, _1, _2);
		this->encode_func_map[Kafka_JoinGroup] = std::bind(&KafkaRequest::encode_joingroup, this, _1, _2);
		this->encode_func_map[Kafka_SyncGroup] = std::bind(&KafkaRequest::encode_syncgroup, this, _1, _2);
		this->encode_func_map[Kafka_Heartbeat] = std::bind(&KafkaRequest::encode_heartbeat, this, _1, _2);
		this->encode_func_map[Kafka_OffsetFetch] = std::bind(&KafkaRequest::encode_offsetfetch, this, _1, _2);
		this->encode_func_map[Kafka_OffsetCommit] = std::bind(&KafkaRequest::encode_offsetcommit, this, _1, _2);
		this->encode_func_map[Kafka_ListOffsets] = std::bind(&KafkaRequest::encode_listoffset, this, _1, _2);
		this->encode_func_map[Kafka_LeaveGroup] = std::bind(&KafkaRequest::encode_leavegroup, this, _1, _2);
		this->encode_func_map[Kafka_ApiVersions] = std::bind(&KafkaRequest::encode_apiversions, this, _1, _2);

		this->api_mver_map[Kafka_Metadata] = 4;
		this->api_mver_map[Kafka_Produce] = 7;
		this->api_mver_map[Kafka_Fetch] = 11;
		this->api_mver_map[Kafka_FindCoordinator] = 2;
		this->api_mver_map[Kafka_JoinGroup] = 5;
		this->api_mver_map[Kafka_SyncGroup] = 3;
		this->api_mver_map[Kafka_Heartbeat] = 3;
		this->api_mver_map[Kafka_OffsetFetch] = 1;
		this->api_mver_map[Kafka_OffsetCommit] = 7;
		this->api_mver_map[Kafka_ListOffsets] = 1;
		this->api_mver_map[Kafka_LeaveGroup] = 1;
		this->api_mver_map[Kafka_ApiVersions] = 0;
	}

private:
	int encode_produce(struct iovec vectors[], int max);
	int encode_fetch(struct iovec vectors[], int max);
	int encode_metadata(struct iovec vectors[], int max);
	int encode_findcoordinator(struct iovec vectors[], int max);
	int encode_listoffset(struct iovec vectors[], int max);
	int encode_joingroup(struct iovec vectors[], int max);
	int encode_syncgroup(struct iovec vectors[], int max);
	int encode_leavegroup(struct iovec vectors[], int max);
	int encode_heartbeat(struct iovec vectors[], int max);
	int encode_offsetcommit(struct iovec vectors[], int max);
	int encode_offsetfetch(struct iovec vectors[], int max);
	int encode_apiversions(struct iovec vectors[], int max);
};

class KafkaResponse : public KafkaMessage
{
public:
	KafkaResponse()
	{
		using namespace std::placeholders;
		this->parse_func_map[Kafka_Metadata] = std::bind(&KafkaResponse::parse_metadata, this, _1, _2);
		this->parse_func_map[Kafka_Produce] = std::bind(&KafkaResponse::parse_produce, this, _1, _2);
		this->parse_func_map[Kafka_Fetch] = std::bind(&KafkaResponse::parse_fetch, this, _1, _2);
		this->parse_func_map[Kafka_FindCoordinator] = std::bind(&KafkaResponse::parse_findcoordinator, this, _1, _2);
		this->parse_func_map[Kafka_JoinGroup] = std::bind(&KafkaResponse::parse_joingroup, this, _1, _2);
		this->parse_func_map[Kafka_SyncGroup] = std::bind(&KafkaResponse::parse_syncgroup, this, _1, _2);
		this->parse_func_map[Kafka_Heartbeat] = std::bind(&KafkaResponse::parse_heartbeat, this, _1, _2);
		this->parse_func_map[Kafka_OffsetFetch] = std::bind(&KafkaResponse::parse_offsetfetch, this, _1, _2);
		this->parse_func_map[Kafka_OffsetCommit] = std::bind(&KafkaResponse::parse_offsetcommit, this, _1, _2);
		this->parse_func_map[Kafka_ListOffsets] = std::bind(&KafkaResponse::parse_listoffset, this, _1, _2);
		this->parse_func_map[Kafka_LeaveGroup] = std::bind(&KafkaResponse::parse_leavegroup, this, _1, _2);
		this->parse_func_map[Kafka_ApiVersions] = std::bind(&KafkaResponse::parse_apiversions, this, _1, _2);
	}

	int parse_response();

private:
	int parse_produce(void **buf, size_t *size);
	int parse_fetch(void **buf, size_t *size);
	int parse_metadata(void **buf, size_t *size);
	int parse_findcoordinator(void **buf, size_t *size);
	int parse_joingroup(void **buf, size_t *size);
	int parse_syncgroup(void **buf, size_t *size);
	int parse_leavegroup(void **buf, size_t *size);
	int parse_listoffset(void **buf, size_t *size);
	int parse_offsetcommit(void **buf, size_t *size);
	int parse_offsetfetch(void **buf, size_t *size);
	int parse_heartbeat(void **buf, size_t *size);
	int parse_apiversions(void **buf, size_t *size);
};

}

#endif
