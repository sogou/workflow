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
#include "kafka_parser.h"
#include "ProtocolMessage.h"
#include "KafkaDataTypes.h"


namespace protocol
{

class KafkaMessage : public ProtocolMessage
{
public:
	KafkaMessage();

	virtual ~KafkaMessage();

protected:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

private:
	int encode_head();

public:
	KafkaMessage(KafkaMessage&& msg);
	KafkaMessage& operator= (KafkaMessage&& msg);

public:
	int encode_message(int api_type, struct iovec vectors[], int max);

	void set_api_type(int api_type) { this->api_type = api_type; }
	int get_api_type() const { return this->api_type; }

	void set_api_version(int ver) { this->api_version = ver; }
	int get_api_version() const { return this->api_version; }

	void set_correlation_id(int id) { this->correlation_id = id; }
	int get_correlation_id() const { return this->correlation_id; }

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

	void set_sasl(kafka_sasl_t *sasl)
	{
		this->sasl = sasl;
	}

	void set_api(kafka_api_t *api)
	{
		this->api = api;
	}

	void duplicate(const KafkaMessage& msg)
	{
		this->config = msg.config;
		this->cgroup = msg.cgroup;
		this->broker = msg.broker;
		this->meta_list = msg.meta_list;
		this->broker_list = msg.broker_list;
		this->toppar_list = msg.toppar_list;
		this->sasl = msg.sasl;
		this->api = msg.api;
	}

	void clear_buf()
	{
		this->msgbuf.clear();
		this->headbuf.clear();
		kafka_parser_deinit(this->parser);
		kafka_parser_init(this->parser);
		this->cur_size = 0;
		this->serialized = KafkaBuffer();
		this->uncompressed = KafkaBuffer();
	}

protected:
	static int parse_message_set(void **buf, size_t *size,
								 bool check_crcs, int msg_vers,
								 struct list_head *record_list,
								 KafkaBuffer *uncompressed,
								 KafkaToppar *toppar);

	static int parse_message_record(void **buf, size_t *size,
									kafka_record_t *kafka_record);

	static int parse_record_batch(void **buf, size_t *size,
								  bool check_crcs,
								  struct list_head *record_list,
								  KafkaBuffer *uncompressed,
								  KafkaToppar *toppar);

	static int parse_records(void **buf, size_t *size, bool check_crcs,
							 KafkaBuffer *uncompressed, KafkaToppar *toppar);

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

	class EncodeStream *stream;
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
	int correlation_id;
	int message_version;

	void *compress_env;
	size_t cur_size;

	kafka_sasl_t *sasl;
	kafka_api_t *api;
};

class KafkaRequest : public KafkaMessage
{
public:
	KafkaRequest();

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
	int encode_saslhandshake(struct iovec vectors[], int max);
	int encode_saslauthenticate(struct iovec vectors[], int max);
};

class KafkaResponse : public KafkaRequest
{
public:
	KafkaResponse();

	int parse_response();

protected:
    virtual int append(const void *buf, size_t *size);

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
	int parse_saslhandshake(void **buf, size_t *size);
	int parse_saslauthenticate(void **buf, size_t *size);

	int handle_sasl_continue();
};

}

#endif

