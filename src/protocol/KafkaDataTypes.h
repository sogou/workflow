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

#ifndef _KAFKA_DATATYPES_H_
#define _KAFKA_DATATYPES_H_

#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utility>
#include <string.h>
#include <vector>
#include <string>
#include <atomic>
#include <snappy.h>
#include <snappy-sinksource.h>
#include "list.h"
#include "rbtree.h"
#include "kafka_parser.h"

namespace protocol
{

template<class T>
class KafkaList
{
public:
	KafkaList()
	{
		this->t_list = new struct list_head;

		INIT_LIST_HEAD(this->t_list);
		this->ref = new std::atomic<int>(1);
		this->curpos = this->t_list;
	}

	~KafkaList()
	{
		if (--*this->ref == 0)
		{
			struct list_head *pos, *tmp;
			T *t;

			list_for_each_safe(pos, tmp, this->t_list)
			{
				t = list_entry(pos, T, list);
				list_del(pos);
				delete t;
			}

			delete this->t_list;
			delete this->ref;
		}
	}

	KafkaList(KafkaList&& move)
	{
		this->t_list = move.t_list;
		move.t_list = new struct list_head;
		INIT_LIST_HEAD(move.t_list);
		this->ref = move.ref;
		this->curpos = this->t_list;
		move.ref = new std::atomic<int>(1);
	}

	KafkaList& operator= (KafkaList&& move)
	{
		if (this != &move)
		{
			this->~KafkaList();
			this->t_list = move.t_list;
			move.t_list = new struct list_head;
			INIT_LIST_HEAD(move.t_list);
			this->ref = move.ref;
			this->curpos = this->t_list;
			move.ref = new std::atomic<int>(1);
		}

		return *this;
	}

	KafkaList(const KafkaList& copy)
	{
		this->ref = copy.ref;
		++*this->ref;
		this->t_list = copy.t_list;
		this->curpos = copy.curpos;
	}

	KafkaList& operator= (const KafkaList& copy)
	{
		if (this != &copy)
		{
			this->~KafkaList();
			this->ref = copy.ref;
			++*this->ref;
			this->t_list = copy.t_list;
			this->curpos = copy.curpos;
		}
		return *this;
	}

	T *add_item(T&& move)
	{
		T *t = new T;

		*t = std::move(move);
		list_add_tail(t->get_list(), this->t_list);
		return t;
	}

	void add_item(T& obj)
	{
		T *t = new T;

		*t = obj;
		list_add_tail(t->get_list(), this->t_list);
	}

	struct list_head *get_head() { return this->t_list; }

	struct list_head *get_tail() { return this->t_list->prev; }

	T *get_first_entry()
	{
		if (this->t_list == this->t_list->next)
			return NULL;

		return list_entry(this->t_list->next, T, list);
	}

	T *get_tail_entry()
	{
		if (this->t_list == this->get_tail())
			return NULL;

		return list_entry(this->get_tail(), T, list);
	}

	T *get_entry(struct list_head *pos)
	{
		return list_entry(pos, T, list);
	}

	void rewind()
	{
		this->curpos = this->t_list;
	}

	T *get_next()
	{
		if (this->curpos->next == this->t_list)
			return NULL;

		this->curpos = this->curpos->next;
		return list_entry(this->curpos, T, list);
	}

	void insert_pos(struct list_head *list, struct list_head *pos)
	{
		__list_add(list, pos, pos->next);
	}

	void del_cur()
	{
		assert(this->curpos != this->t_list);
		this->curpos = this->curpos->prev;
		list_del(this->curpos->next);
	}

private:
	struct list_head *t_list;
	std::atomic<int> *ref;
	struct list_head *curpos;
};

template<class T>
class KafkaMap
{
public:
	KafkaMap()
	{
		this->t_map = new struct rb_root;
		this->t_map->rb_node = NULL;

		this->ref = new std::atomic<int>(1);
	}

	~KafkaMap()
	{
		if (--*this->ref == 0)
		{
			T *t;
			while (this->t_map->rb_node)
			{
				t = rb_entry(this->t_map->rb_node, T, rb);
				rb_erase(this->t_map->rb_node, this->t_map);
				delete t;
			}

			delete this->t_map;
			delete this->ref;
		}
	}

	KafkaMap(const KafkaMap& copy)
	{
		this->ref = copy.ref;
		++*this->ref;
		this->t_map = copy.t_map;
	}

	KafkaMap& operator= (const KafkaMap& copy)
	{
		if (this != &copy)
		{
			this->~KafkaMap();
			this->ref = copy.ref;
			++*this->ref;
			this->t_map = copy.t_map;
		}
		return *this;
	}

	T *find_item(const T& v) const
	{
		rb_node **p = &this->t_map->rb_node;
		T *t;

		while (*p)
		{
			t = rb_entry(*p, T, rb);

			if (v < *t)
				p = &(*p)->rb_left;
			else if (v > *t)
				p = &(*p)->rb_right;
			else
				break;
		}

		return *p ? t : NULL;
	}

	void add_item(T& obj)
	{
		rb_node **p = &this->t_map->rb_node;
		rb_node *parent = NULL;
		T *t;

		while (*p)
		{
			parent = *p;
			t = rb_entry(*p, T, rb);

			if (obj < *t)
				p = &(*p)->rb_left;
			else if (obj > *t)
				p = &(*p)->rb_right;
			else
				break;
		}

		if (*p == NULL)
		{
			T *nt = new T;

			*nt = obj;
			rb_link_node(nt->get_rb(), parent, p);
			rb_insert_color(nt->get_rb(), this->t_map);
		}
	}

	T *find_item(int id) const
	{
		rb_node **p = &this->t_map->rb_node;
		T *t;

		while (*p)
		{
			t = rb_entry(*p, T, rb);

			if (id < t->get_id())
				p = &(*p)->rb_left;
			else if (id > t->get_id())
				p = &(*p)->rb_right;
			else
				break;
		}

		return *p ? t : NULL;
	}

	void add_item(T& obj, int id)
	{
		rb_node **p = &this->t_map->rb_node;
		rb_node *parent = NULL;
		T *t;

		while (*p)
		{
			parent = *p;
			t = rb_entry(*p, T, rb);

			if (id < t->get_id())
				p = &(*p)->rb_left;
			else if (id > t->get_id())
				p = &(*p)->rb_right;
			else
				break;
		}

		if (*p == NULL)
		{
			T *nt = new T;

			*nt = obj;
			rb_link_node(nt->get_rb(), parent, p);
			rb_insert_color(nt->get_rb(), this->t_map);
		}
	}

	T *get_first_entry()
	{
		struct rb_node *p = rb_first(this->t_map);
		return rb_entry(p, T, rb);
	}

	T *get_tail_entry()
	{
		struct rb_node *p = rb_last(this->t_map);
		return rb_entry(p, T, rb);
	}

private:
	struct rb_root *t_map;
	std::atomic<int> *ref;
};

class KafkaConfig
{
public:
	void set_produce_timeout(int ms) { this->ptr->produce_timeout = ms; }
	int get_produce_timeout() const { return this->ptr->produce_timeout; }

	void set_produce_msg_max_bytes(int bytes)
	{
		this->ptr->produce_msg_max_bytes = bytes;
	}
	int get_produce_msg_max_bytes() const
	{
		return this->ptr->produce_msg_max_bytes;
	}

	void set_produce_msgset_cnt(int cnt)
	{
		this->ptr->produce_msgset_cnt = cnt;
	}
	int get_produce_msgset_cnt() const
	{
		return this->ptr->produce_msgset_cnt;
	}

	void set_produce_msgset_max_bytes(int bytes)
	{
		this->ptr->produce_msgset_max_bytes = bytes;
	}
	int get_produce_msgset_max_bytes() const
	{
		return this->ptr->produce_msgset_max_bytes;
	}

	void set_fetch_timeout(int ms) { this->ptr->fetch_timeout = ms; }
	int get_fetch_timeout() const { return this->ptr->fetch_timeout; }

	void set_fetch_min_bytes(int bytes) { this->ptr->fetch_min_bytes = bytes; }
	int get_fetch_min_bytes() const { return this->ptr->fetch_min_bytes; }

	void set_fetch_max_bytes(int bytes) { this->ptr->fetch_max_bytes = bytes; }
	int get_fetch_max_bytes() const { return this->ptr->fetch_max_bytes; }

	void set_fetch_msg_max_bytes(int bytes) { this->ptr->fetch_msg_max_bytes = bytes; }
	int get_fetch_msg_max_bytes() const { return this->ptr->fetch_msg_max_bytes; }

	void set_offset_timestamp(long long tm)
	{
		this->ptr->offset_timestamp = tm;
	}
	long long get_offset_timestamp() const
	{
		return this->ptr->offset_timestamp;
	}

	void set_commit_timestamp(long long commit_timestamp)
	{
		this->ptr->commit_timestamp = commit_timestamp;
	}
	long long get_commit_timestamp() const { return this->ptr->commit_timestamp; }

	void set_session_timeout(int ms) { this->ptr->session_timeout = ms; }
	int get_session_timeout() const { return this->ptr->session_timeout; }

	void set_rebalance_timeout(int ms) { this->ptr->rebalance_timeout = ms; }
	int get_rebalance_timeout() const { return this->ptr->rebalance_timeout; }

	void set_retention_time_period(long long ms)
	{
		this->ptr->retention_time_period = ms;
	}
	long long get_retention_time_period() const
	{
		return this->ptr->retention_time_period;
	}

	void set_produce_acks(int acks) { this->ptr->produce_acks = acks; }
	int get_produce_acks() const { return this->ptr->produce_acks; }

	void set_allow_auto_topic_creation(bool allow_auto_topic_creation)
	{
		this->ptr->allow_auto_topic_creation = allow_auto_topic_creation;
	}
	bool get_allow_auto_topic_creation() const
	{
		return this->ptr->allow_auto_topic_creation;
	}

	void set_api_version_request(int api_ver)
	{
		this->ptr->api_version_request = api_ver;
	}
	int get_api_version_request() const
	{
		return this->ptr->api_version_request;
	}

	bool set_broker_version(const char *version)
	{
		char *p = strdup(version);

		if (!p)
			return false;

		free(this->ptr->broker_version);
		this->ptr->broker_version = p;
		return true;
	}
	const char *get_broker_version() const
	{
		return this->ptr->broker_version;
	}

	void set_compress_type(int type) { this->ptr->compress_type = type; }
	int get_compress_type() const { return this->ptr->compress_type; }

	const char *get_client_id() { return this->ptr->client_id; }
	bool set_client_id(const char *client_id)
	{
		char *p = strdup(client_id);

		if (!p)
			return false;

		free(this->ptr->client_id);
		this->ptr->client_id = p;
		return true;
	}

	bool get_check_crcs() const
	{
		return this->ptr->check_crcs != 0;
	}
	void set_check_crcs(bool check_crcs)
	{
		this->ptr->check_crcs = check_crcs;
	}

	int get_offset_store() const
	{
		return this->ptr->offset_store;
	}
	void set_offset_store(int offset_store)
	{
		this->ptr->offset_store = offset_store;
	}

	const char *get_rack_id() const
	{
		return this->ptr->rack_id;
	}
	bool set_rack_id(const char *rack_id)
	{
		char *p = strdup(rack_id);
		if (!p)
			return false;

		free(this->ptr->rack_id);
		this->ptr->rack_id = p;
		return true;
	}

	const char *get_sasl_mech() const
	{
		return this->ptr->mechanisms;
	}
	bool set_sasl_mech(const char *mechanisms)
	{
		char *p = strdup(mechanisms);

		if (!p)
			return false;

		free(this->ptr->mechanisms);
		this->ptr->mechanisms = p;
		if (kafka_sasl_set_mechanisms(this->ptr) != 0)
			return false;

		return true;
	}

	const char *get_sasl_username() const
	{
		return this->ptr->username;
	}
	bool set_sasl_username(const char *username)
	{
		return kafka_sasl_set_username(username, this->ptr) == 0;
	}

	const char *get_sasl_password() const
	{
		return this->ptr->password;
	}
	bool set_sasl_password(const char *password)
	{
		return kafka_sasl_set_password(password, this->ptr) == 0;
	}

	std::string get_sasl_info() const;

	bool new_client(kafka_sasl_t *sasl)
	{
		return this->ptr->client_new(this->ptr, sasl) == 0;
	}

public:
	KafkaConfig()
	{
		this->ptr = new kafka_config_t;
		kafka_config_init(this->ptr);
		this->ref = new std::atomic<int>(1);
	}

	virtual ~KafkaConfig()
	{
		if (--*this->ref == 0)
		{
			kafka_config_deinit(this->ptr);
			delete this->ptr;
			delete this->ref;
		}
	}

	KafkaConfig(KafkaConfig&& move)
	{
		this->ptr = move.ptr;
		this->ref = move.ref;
		move.ptr = new kafka_config_t;
		kafka_config_init(move.ptr);
		move.ref = new std::atomic<int>(1);
	}

	KafkaConfig& operator= (KafkaConfig&& move)
	{
		if (this != &move)
		{
			this->~KafkaConfig();
			this->ptr = move.ptr;
			this->ref = move.ref;
			move.ptr = new kafka_config_t;
			kafka_config_init(move.ptr);
			move.ref = new std::atomic<int>(1);
		}

		return *this;
	}

	KafkaConfig(const KafkaConfig& copy)
	{
		this->ptr = copy.ptr;
		this->ref = copy.ref;
		++*this->ref;
	}

	KafkaConfig& operator= (const KafkaConfig& copy)
	{
		if (this != &copy)
		{
			this->~KafkaConfig();
			this->ptr = copy.ptr;
			this->ref = copy.ref;
			++*this->ref;
		}

		return *this;
	}

	kafka_config_t *get_raw_ptr() { return this->ptr; }

private:
	kafka_config_t *ptr;
	std::atomic<int> *ref;
};

class KafkaRecord
{
public:
	bool set_key(const void *key, size_t key_len)
	{
		return kafka_record_set_key(key, key_len, this->ptr) == 0;
	}
	void get_key(const void **key, size_t *key_len) const
	{
		*key = this->ptr->key;
		*key_len = this->ptr->key_len;
	}
	size_t get_key_len() const { return this->ptr->key_len; }

	bool set_value(const void *value, size_t value_len)
	{
		return kafka_record_set_value(value, value_len, this->ptr) == 0;
	}
	void get_value(const void **value, size_t *value_len) const
	{
		*value = this->ptr->value;
		*value_len = this->ptr->value_len;
	}
	size_t get_value_len() const { return this->ptr->value_len; }

	bool add_header_pair(const void *key, size_t key_len,
						 const void *val, size_t val_len);

	bool add_header_pair(const std::string& key, const std::string& val);

	struct list_head *get_list() { return &this->list; }

	const char *get_topic() const { return this->ptr->toppar->topic_name; }

	void set_status(short err) { this->ptr->status = err; }
	short get_status() const { return this->ptr->status; }

	int get_partition() const { return this->ptr->toppar->partition; }

	long long get_offset() const { return this->ptr->offset; }
	void set_offset(long long offset) { this->ptr->offset = offset; }

	long long get_timestamp() const { return this->ptr->timestamp; }
	void set_timestamp(long long timestamp) { this->ptr->timestamp = timestamp; }

public:
	KafkaRecord()
	{
		this->ptr = new kafka_record_t;
		kafka_record_init(this->ptr);
		this->ref = new std::atomic<int>(1);
	}

	~KafkaRecord()
	{
		if (--*this->ref == 0)
		{
			kafka_record_deinit(this->ptr);
			delete this->ptr;
			delete this->ref;
		}
	}

	KafkaRecord(KafkaRecord&& move)
	{
		this->ptr = move.ptr;
		this->ref = move.ref;
		move.ptr = new kafka_record_t;
		kafka_record_init(move.ptr);
		move.ref = new std::atomic<int>(1);
	}

	KafkaRecord& operator= (KafkaRecord&& move)
	{
		if (this != &move)
		{
			this->~KafkaRecord();
			this->ptr = move.ptr;
			this->ref = move.ref;
			move.ptr = new kafka_record_t;
			kafka_record_init(move.ptr);
			move.ref = new std::atomic<int>(1);
		}

		return *this;
	}

	KafkaRecord(const KafkaRecord& copy)
	{
		this->ptr = copy.ptr;
		this->ref = copy.ref;
		++*this->ref;
	}

	KafkaRecord& operator= (const KafkaRecord& copy)
	{
		if (this != &copy)
		{
			this->~KafkaRecord();
			this->ptr = copy.ptr;
			this->ref = copy.ref;
			++*this->ref;
		}

		return *this;
	}

	kafka_record_t *get_raw_ptr() const { return this->ptr; }

	struct list_head *get_header_list() const { return &this->ptr->header_list; }

private:
	struct list_head list;
	kafka_record_t *ptr;
	std::atomic<int> *ref;

	friend class KafkaMessage;
	friend class KafkaResponse;
	friend class KafkaToppar;
};


class KafkaMeta;
class KafkaBroker;
class KafkaToppar;

using KafkaMetaList = KafkaList<KafkaMeta>;
using KafkaBrokerList = KafkaList<KafkaBroker>;
using KafkaBrokerMap = KafkaMap<KafkaBroker>;
using KafkaTopparList = KafkaList<KafkaToppar>;
using KafkaRecordList = KafkaList<KafkaRecord>;

extern KafkaToppar *get_toppar(const char *topic, int partition,
							   KafkaTopparList *toppar_list);

extern const KafkaMeta *get_meta(const char *topic, KafkaMetaList *meta_list);

class KafkaToppar
{
public:
	bool set_topic_partition(const std::string& topic, int partition)
	{
		return kafka_topic_partition_set_tp(topic.c_str(), partition,
											this->ptr) == 0;
	}

	int get_preferred_read_replica() const
	{
		return this->ptr->preferred_read_replica;
	}

	bool set_topic(const char *topic)
	{
		this->ptr->topic_name = strdup(topic);
		return this->ptr->topic_name != NULL;
	}

	const char *get_topic() const { return this->ptr->topic_name; }

	int get_partition() const { return this->ptr->partition; }

	long long get_offset() const { return this->ptr->offset; }
	void set_offset(long long offset) { this->ptr->offset = offset; }

	long long get_offset_timestamp() const { return this->ptr->offset_timestamp; }
	void set_offset_timestamp(long long tm) { this->ptr->offset_timestamp = tm; }

	long long get_high_watermark() const { return this->ptr->high_watermark; }
	void set_high_watermark(long long offset) const { this->ptr->high_watermark = offset; }

	long long get_low_watermark() const { return this->ptr->low_watermark; }
	void set_low_watermark(long long offset) { this->ptr->low_watermark = offset; }

	void clear_records()
	{
		INIT_LIST_HEAD(&this->ptr->record_list);
		this->curpos = &this->ptr->record_list;
		this->startpos = this->endpos = this->curpos;
	}

public:
	KafkaToppar()
	{
		this->ptr = new kafka_topic_partition_t;
		kafka_topic_partition_init(this->ptr);
		this->ref = new std::atomic<int>(1);
		this->curpos = &this->ptr->record_list;
		this->startpos = this->endpos = this->curpos;
	}

	~KafkaToppar();

	KafkaToppar(KafkaToppar&& move)
	{
		this->ptr = move.ptr;
		this->ref = move.ref;
		move.ptr = new kafka_topic_partition_t;
		kafka_topic_partition_init(move.ptr);
		move.ref = new std::atomic<int>(1);
		this->curpos = &this->ptr->record_list;
		this->startpos = this->endpos = this->curpos;
	}

	KafkaToppar& operator= (KafkaToppar&& move)
	{
		if (this != &move)
		{
			this->~KafkaToppar();
			this->ptr = move.ptr;
			this->ref = move.ref;
			move.ptr = new kafka_topic_partition_t;
			kafka_topic_partition_init(move.ptr);
			move.ref = new std::atomic<int>(1);
			this->curpos = &this->ptr->record_list;
			this->startpos = this->endpos = this->curpos;
		}

		return *this;
	}

	KafkaToppar(const KafkaToppar& copy)
	{
		this->ptr = copy.ptr;
		this->ref = copy.ref;
		++*this->ref;
		this->curpos = copy.curpos;
		this->startpos = copy.startpos;
		this->endpos = copy.endpos;
	}

	KafkaToppar& operator= (const KafkaToppar& copy)
	{
		if (this != &copy)
		{
			this->~KafkaToppar();
			this->ptr = copy.ptr;
			this->ref = copy.ref;
			++*this->ref;
			this->curpos = copy.curpos;
			this->startpos = copy.startpos;
			this->endpos = copy.endpos;
		}

		return *this;
	}

	kafka_topic_partition_t *get_raw_ptr() { return this->ptr; }

	struct list_head *get_list() { return &this->list; }

	struct list_head *get_record() { return &this->ptr->record_list; }

	void set_error(short error) { this->ptr->error = error; }
	int get_error() const { return this->ptr->error; }

	void add_record(KafkaRecord&& record)
	{
		KafkaRecord *tmp = new KafkaRecord;

		*tmp =std::move(record);
		list_add_tail(tmp->get_list(), &this->ptr->record_list);
	}

	void record_rewind()
	{
		this->curpos = &this->ptr->record_list;
	}

	KafkaRecord *get_record_next()
	{
		if (this->curpos->next == &this->ptr->record_list)
			return NULL;

		this->curpos = this->curpos->next;
		return list_entry(this->curpos, KafkaRecord, list);
	}

	void del_record_cur()
	{
		assert(this->curpos != &this->ptr->record_list);
		this->curpos = this->curpos->prev;
		list_del(this->curpos->next);
	}

	struct list_head *get_record_startpos()
	{
		return this->startpos;
	}

	struct list_head *get_record_endpos()
	{
		return this->endpos;
	}

	void restore_record_curpos()
	{
		this->curpos = this->startpos;
		this->endpos = NULL;
	}

	void save_record_startpos()
	{
		this->startpos = this->curpos;
	}

	void save_record_endpos()
	{
		this->endpos = this->curpos->next;
	}

	bool record_reach_end()
	{
		return this->endpos == &this->ptr->record_list;
	}

	void record_rollback()
	{
		this->curpos = this->curpos->prev;
	}

	KafkaRecord *get_tail_record()
	{
		if (&this->ptr->record_list != this->ptr->record_list.prev)
		{
			return (KafkaRecord *)list_entry(this->ptr->record_list.prev,
					KafkaRecord, list);
		}
		else
		{
			return NULL;
		}
	}

private:
	struct list_head list;
	kafka_topic_partition_t *ptr;
	std::atomic<int> *ref;
	struct list_head *curpos;
	struct list_head *startpos;
	struct list_head *endpos;

	friend class KafkaMessage;
	friend class KafkaRequest;
	friend class KafkaResponse;
	friend class KafkaList<KafkaToppar>;
	friend class KafkaCgroup;

	friend KafkaToppar *get_toppar(const char *topic, int partition,
								   KafkaTopparList *toppar_list);
};

class KafkaBroker
{
public:
	const char *get_host() const
	{
		return this->ptr->host;
	}

	int get_port() const
	{
		return this->ptr->port;
	}

	std::string get_host_port() const
	{
		std::string host_port(this->ptr->host);
		host_port += ":";
		host_port += std::to_string(this->ptr->port);
		return host_port;
	}

	int get_error()
	{
		return this->ptr->error;
	}

public:
	KafkaBroker()
	{
		this->ptr = new kafka_broker_t;
		kafka_broker_init(this->ptr);
		this->ref = new std::atomic<int>(1);
	}

	~KafkaBroker()
	{
		if (this->ref && --*this->ref == 0)
		{
			kafka_broker_deinit(this->ptr);
			delete this->ptr;
			delete this->ref;
		}
	}

	KafkaBroker(kafka_broker_t *ptr)
	{
		this->ptr = ptr;
		this->ref = NULL;
	}

	KafkaBroker(KafkaBroker&& move)
	{
		this->ptr = move.ptr;
		this->ref = move.ref;
		move.ptr = new kafka_broker_t;
		kafka_broker_init(move.ptr);
		move.ref = new std::atomic<int>(1);
	}

	KafkaBroker& operator= (KafkaBroker&& move)
	{
		if (this != &move)
		{
			this->~KafkaBroker();
			this->ptr = move.ptr;
			this->ref = move.ref;
			move.ptr = new kafka_broker_t;
			kafka_broker_init(move.ptr);
			move.ref = new std::atomic<int>(1);
		}

		return *this;
	}

	KafkaBroker(const KafkaBroker& copy)
	{
		this->ptr = copy.ptr;
		this->ref = copy.ref;
		if (this->ref)
			++*this->ref;
	}

	KafkaBroker& operator= (const KafkaBroker& copy)
	{
		if (this != &copy)
		{
			this->~KafkaBroker();
			this->ptr = copy.ptr;
			this->ref = copy.ref;
			if (this->ref)
				++*this->ref;
		}

		return *this;
	}

	bool operator< (const KafkaBroker& broker) const
	{
		return this->get_host_port() < broker.get_host_port();
	}

	bool operator> (const KafkaBroker& broker) const
	{
		return this->get_host_port() > broker.get_host_port();
	}

	kafka_broker_t *get_raw_ptr() const { return this->ptr; }

	struct list_head *get_list() { return &this->list; }

	struct rb_node *get_rb() { return &this->rb; }

	int get_node_id() const { return this->ptr->node_id; }

	int get_id () const { return this->ptr->node_id; }

private:
	struct list_head list;
	struct rb_node rb;
	kafka_broker_t *ptr;
	std::atomic<int> *ref;

	friend class KafkaList<KafkaBroker>;
	friend class KafkaMap<KafkaBroker>;
};

class KafkaMeta
{
public:
	const char *get_topic() const { return this->ptr->topic_name; }

	const kafka_broker_t *get_broker(int partition) const
	{
		if (partition >= this->ptr->partition_elements)
			return NULL;

		for (int i = 0; i < this->ptr->partition_elements; ++i)
		{
			if (partition == this->ptr->partitions[i]->partition_index)
				return &this->ptr->partitions[i]->leader;
		}

		return NULL;
	}

	kafka_partition_t **get_partitions() const { return this->ptr->partitions; }

	int get_partition_elements() const { return this->ptr->partition_elements; }

public:
	KafkaMeta()
	{
		this->ptr = new kafka_meta_t;
		kafka_meta_init(this->ptr);
		this->ref = new std::atomic<int>(1);
	}

	~KafkaMeta()
	{
		if (--*this->ref == 0)
		{
			kafka_meta_deinit(this->ptr);
			delete this->ptr;
			delete this->ref;
		}
	}

	KafkaMeta(KafkaMeta&& move)
	{
		this->ptr = move.ptr;
		this->ref = move.ref;
		move.ptr = new kafka_meta_t;
		kafka_meta_init(move.ptr);
		move.ref = new std::atomic<int>(1);
	}

	KafkaMeta& operator= (KafkaMeta&& move)
	{
		if (this != &move)
		{
			this->~KafkaMeta();
			this->ptr = move.ptr;
			this->ref = move.ref;
			move.ptr = new kafka_meta_t;
			kafka_meta_init(move.ptr);
			move.ref = new std::atomic<int>(1);
		}

		return *this;
	}

	KafkaMeta(const KafkaMeta& copy)
	{
		this->ptr = copy.ptr;
		this->ref = copy.ref;
		++*this->ref;
	}

	KafkaMeta& operator= (const KafkaMeta& copy)
	{
		if (this != &copy)
		{
			this->~KafkaMeta();
			this->ptr = copy.ptr;
			this->ref = copy.ref;
			++*this->ref;
		}

		return *this;
	}

	kafka_meta_t *get_raw_ptr() { return this->ptr; }

	bool set_topic(const std::string& topic)
	{
		return kafka_meta_set_topic(topic.c_str(), this->ptr) == 0;
	}

	struct list_head *get_list() { return &this->list; }

	int get_error() const { return this->ptr->error; }

	bool create_partitions(int partition_cnt);

	bool create_replica_nodes(int partition_idx, int replica_cnt)
	{
		int *replica_nodes = (int *)malloc(replica_cnt * 4);

		if (!replica_nodes)
			return false;

		this->ptr->partitions[partition_idx]->replica_nodes = replica_nodes;
		this->ptr->partitions[partition_idx]->replica_node_elements = replica_cnt;
		return true;
	}

	bool create_isr_nodes(int partition_idx, int isr_cnt)
	{
		int *isr_nodes = (int *)malloc(isr_cnt * 4);

		if (!isr_nodes)
			return false;

		this->ptr->partitions[partition_idx]->isr_nodes = isr_nodes;
		this->ptr->partitions[partition_idx]->isr_node_elements = isr_cnt;
		return true;
	}

private:
	struct list_head list;
	kafka_meta_t *ptr;
	std::atomic<int> *ref;

	friend class KafkaList<KafkaMeta>;

	friend const KafkaMeta *get_meta(const char *topic, KafkaMetaList *meta_list);
};

class KafkaMetaSubscriber
{
public:
	void set_meta(KafkaMeta *meta)
	{
		this->meta = meta;
	}

	const KafkaMeta *get_meta() const
	{
		return this->meta;
	}

	void add_member(kafka_member_t *member)
	{
		this->member_vec.push_back(member);
	}

	const std::vector<kafka_member_t *> *get_member() const
	{
		return &this->member_vec;
	}

	void sort_by_member();

private:
	KafkaMeta *meta;
	std::vector<kafka_member_t *> member_vec;
};

class KafkaCgroup
{
public:
	const char *get_group() const { return this->ptr->group_name; }

	const char *get_protocol_type() const { return this->ptr->protocol_type; }

	const char *get_protocol_name() const { return this->ptr->protocol_name; }

	int get_generation_id() const { return this->ptr->generation_id; }

	const char *get_member_id() const { return this->ptr->member_id; }

public:
	KafkaCgroup();

	~KafkaCgroup();

	KafkaCgroup(KafkaCgroup&& move);

	KafkaCgroup& operator= (KafkaCgroup&& move);

	KafkaCgroup(const KafkaCgroup& copy);

	KafkaCgroup& operator= (const KafkaCgroup& copy);

	kafka_cgroup_t *get_raw_ptr() { return this->ptr; }

	void set_group(const std::string& group)
	{
		char *p = new char[group.size() + 1];
		strncpy(p, group.c_str(), group.size());
		p[group.size()] = 0;
		this->ptr->group_name = p;
	}

	struct list_head *get_list() { return &this->list; }

	int get_error() const { return this->ptr->error; }

	bool is_leader() const
	{
		return strcmp(this->ptr->leader_id, this->ptr->member_id) == 0;
	}

	struct list_head *get_group_protocol()
	{
		return &this->ptr->group_protocol_list;
	}

	void set_member_id(const char *p)
	{
		free(this->ptr->member_id);
		this->ptr->member_id = strdup(p);
	}

	void set_error(short error) { this->ptr->error = error; }

	bool create_members(int member_cnt);

	kafka_member_t **get_members() const { return this->ptr->members; }

	int get_member_elements() { return this->ptr->member_elements; }

	void add_assigned_toppar(KafkaToppar *toppar);

	struct list_head *get_assigned_toppar_list()
	{
		return &this->ptr->assigned_toppar_list;
	}

	KafkaToppar *get_assigned_toppar_by_pos(struct list_head *pos)
	{
		return list_entry(pos, KafkaToppar, list);
	}

	void assigned_toppar_rewind();

	KafkaToppar *get_assigned_toppar_next();

	void del_assigned_toppar_cur();

	KafkaBroker *get_coordinator()
	{
		if (!this->coordinator)
			this->coordinator = new KafkaBroker(&this->ptr->coordinator);

		return this->coordinator;
	}

	int run_assignor(KafkaMetaList *meta_list, const char *protocol_name);

	void add_subscriber(KafkaMetaList *meta_list,
						std::vector<KafkaMetaSubscriber> *subscribers);

	static int kafka_range_assignor(kafka_member_t **members,
									int member_elements,
									void *meta_topic);

	static int kafka_roundrobin_assignor(kafka_member_t **members,
										 int member_elements,
										 void *meta_topic);

private:
	struct list_head list;
	kafka_cgroup_t *ptr;
	std::atomic<int> *ref;
	struct list_head *curpos;
	KafkaBroker *coordinator;
};

class KafkaBlock
{
public:
	KafkaBlock()
	{
		this->ptr = new kafka_block_t;
		kafka_block_init(this->ptr);
	}

	~KafkaBlock()
	{
		kafka_block_deinit(this->ptr);
		delete this->ptr;
	}

	KafkaBlock(KafkaBlock&& move)
	{
		this->ptr = move.ptr;
		move.ptr = new kafka_block_t;
		kafka_block_init(move.ptr);
	}

	KafkaBlock& operator= (KafkaBlock&& move)
	{
		if (this != &move)
		{
			this->~KafkaBlock();
			this->ptr = move.ptr;
			move.ptr = new kafka_block_t;
			kafka_block_init(move.ptr);
		}

		return *this;
	}

	kafka_block_t *get_raw_ptr() const { return this->ptr; }

	struct list_head *get_list() { return &this->list; }

	void *get_block() const { return this->ptr->buf; }

	size_t get_len() const { return this->ptr->len; }

	bool allocate(size_t len)
	{
		void *p = malloc(len);

		if (!p)
			return false;

		free(this->ptr->buf);
		this->ptr->buf = p;
		this->ptr->len = len;
		return true;
	}

	bool reallocate(size_t len)
	{
		void *p = realloc(this->ptr->buf, len);

		if (p)
		{
			this->ptr->buf = p;
			this->ptr->len = len;
			return true;
		}
		else
			return false;
	}

	bool set_block(void *buf, size_t len)
	{
		if (!this->allocate(len))
			return false;

		memcpy(this->ptr->buf, buf, len);
		return true;
	}

	void set_block_nocopy(void *buf, size_t len)
	{
		this->ptr->buf = buf;
		this->ptr->len = len;
	}

	void set_len(size_t len) { this->ptr->len = len; }

private:
	struct list_head list;
	kafka_block_t *ptr;

	friend class KafkaBuffer;
	friend class KafkaList<KafkaBlock>;
};

class KafkaBuffer
{
public:
	KafkaBuffer()
	{
		this->insert_pos = NULL;
		this->insert_curpos = NULL;
		this->buf_size = 0;
		this->inited = false;
		this->insert_buf_size = 0;
		this->insert_flag = false;
	}

	void backup(size_t n)
	{
		this->buf_size -= n;
	}

	void list_splice(KafkaBuffer *buffer);

	void add_item(KafkaBlock block)
	{
		if (this->insert_flag)
			this->insert_buf_size += block.get_len();

		this->buf_size += block.get_len();
		this->block_list.add_item(std::move(block));
	}

	void set_insert_pos()
	{
		this->insert_pos = this->block_list.get_tail();
		this->insert_flag = true;
		this->insert_buf_size = 0;
	}

	void block_insert_rewind()
	{
		this->insert_flag = false;
		this->insert_curpos = this->insert_pos;
	}

	KafkaBlock *get_block_insert_next()
	{
		if (this->insert_curpos->next == this->block_list.get_head())
			return NULL;

		this->insert_curpos = this->insert_curpos->next;
		return list_entry(this->insert_curpos, KafkaBlock, list);
	}

	KafkaBlock *get_block_tail()
	{
		return this->block_list.get_tail_entry();
	}

	void insert_list(KafkaBlock *block)
	{
		this->buf_size += block->get_len();
		this->block_list.insert_pos(block->get_list(), this->insert_pos);
		this->insert_pos = this->insert_pos->next;
	}

	KafkaBlock *get_block_first()
	{
		this->block_list.rewind();
		return this->block_list.get_next();
	}

	KafkaBlock *get_block_next()
	{
		return this->block_list.get_next();
	}

	void append(const char *bytes, size_t n)
	{
		KafkaBlock block;

		block.set_block((void *)bytes, n);
		this->block_list.add_item(std::move(block));
		this->buf_size += n;
	}

	size_t get_size() const
	{
		return this->buf_size;
	}

	size_t peek(const char **buf);

	long seek(long offset)
	{
		this->cur_pos.second += offset;
		return offset;
	}

	struct list_head *get_head()
	{
		return this->block_list.get_head();
	}

private:
	KafkaList<KafkaBlock> block_list;
	std::pair<KafkaBlock *, size_t> cur_pos;
	struct list_head *insert_pos;
	struct list_head *insert_curpos;
	size_t buf_size;
	size_t insert_buf_size;
	bool inited;
	bool insert_flag;
};

class KafkaSnappySink : public snappy::Sink
{
public:
	KafkaSnappySink(KafkaBuffer *buffer)
	{
		this->buffer = buffer;
	}

	virtual void Append(const char *bytes, size_t n)
	{
		this->buffer->append(bytes, n);
	}

	size_t size() const
	{
		return this->buffer->get_size();
	}

	KafkaBuffer *get_buffer() const
	{
		return buffer;
	}

private:
	KafkaBuffer *buffer;
};

class KafkaSnappySource : public snappy::Source
{
public:
	KafkaSnappySource(KafkaBuffer *buffer)
	{
		this->buffer = buffer;
		this->buf_size = this->buffer->get_size();
		this->pos = 0;
	}

	virtual size_t Available() const
	{
		return this->buf_size - this->pos;
	}

	virtual const char *Peek(size_t *len)
	{
		const char *pos;

		*len = this->buffer->peek(&pos);
		return pos;
	}

	virtual void Skip(size_t n)
	{
		this->pos += this->buffer->seek(n);
	}

private:
	KafkaBuffer *buffer;
	size_t buf_size;
	size_t pos;
};

}

#endif
