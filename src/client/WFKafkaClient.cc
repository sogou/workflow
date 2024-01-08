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
           Xie Han (xiehan@sogou-inc.com)
           Liu Kai (liukaidx@sogou-inc.com)
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <utility>
#include <vector>
#include <set>
#include <map>
#include <atomic>
#include <mutex>
#include "WFTaskError.h"
#include "WFKafkaClient.h"
#include "StringUtil.h"

#define KAFKA_HEARTBEAT_INTERVAL	(3 * 1000 * 1000)

#define KAFKA_CGROUP_UNINIT		0
#define KAFKA_CGROUP_DOING		1
#define KAFKA_CGROUP_DONE		2
#define KAFKA_CGROUP_NONE		3

#define KAFKA_HEARTBEAT_UNINIT	0
#define KAFKA_HEARTBEAT_DOING	1
#define KAFKA_HEARTBEAT_DONE	2

#define KAFKA_DEINIT			(1<<30)

using namespace protocol;

using ComplexKafkaTask = WFComplexClientTask<KafkaRequest, KafkaResponse, int>;

class KafkaMember
{
public:
	KafkaMember() : scheme("kafka://"), ref(1)
	{
		this->transport_type = TT_TCP;
		this->cgroup_status = KAFKA_CGROUP_NONE;
		this->heartbeat_status = KAFKA_HEARTBEAT_UNINIT;
		this->meta_doing = false;
		this->cgroup_outdated = false;
		this->client_deinit = false;
		this->heartbeat_series = NULL;
	}

	void incref()
	{
		++this->ref;
	}

	void decref()
	{
		if (--this->ref == 0)
			delete this;
	}

	enum TransportType transport_type;
	std::string scheme;
	std::vector<std::string> broker_hosts;
	KafkaCgroup cgroup;
	KafkaMetaList meta_list;
	KafkaBrokerMap broker_map;
	KafkaConfig config;
	std::map<std::string, bool> meta_status;
	std::mutex mutex;
	char cgroup_status;
	char heartbeat_status;
	bool meta_doing;
	bool cgroup_outdated;
	bool client_deinit;
	void *heartbeat_series;
	size_t cgroup_wait_cnt;
	size_t meta_wait_cnt;
	std::atomic<int> ref;
};

class KafkaClientTask : public WFKafkaTask
{
public:
	KafkaClientTask(const std::string& query, int retry_max,
					kafka_callback_t&& callback,
					WFKafkaClient *client) :
		WFKafkaTask(retry_max, std::move(callback))
	{
		this->api_type = Kafka_Unknown;
		this->kafka_error = 0;
		this->member = client->member;
		this->query = query;

		this->member->incref();
		this->member->mutex.lock();
		this->config = client->member->config;
		if (!this->member->broker_hosts.empty())
		{
			int rpos = rand() % this->member->broker_hosts.size();
			this->url = this->member->broker_hosts.at(rpos);
		}
		this->member->mutex.unlock();

		this->info_generated = false;
		this->msg = NULL;
	}

	virtual ~KafkaClientTask()
	{
		this->member->decref();
	}

	std::string *get_url() { return &this->url; }

protected:
	virtual bool add_topic(const std::string& topic);

	virtual bool add_toppar(const KafkaToppar& toppar);

	virtual bool add_produce_record(const std::string& topic, int partition,
									KafkaRecord record);

	virtual bool add_offset_toppar(const KafkaToppar& toppar);

	virtual void dispatch();

	virtual void parse_query();
	virtual void generate_info();

private:
	static void kafka_meta_callback(__WFKafkaTask *task);

	static void kafka_merge_meta_list(KafkaMetaList *dst,
									  KafkaMetaList *src);

	static void kafka_merge_broker_list(const std::string& scheme,
										std::vector<std::string> *hosts,
										KafkaBrokerMap *dst,
										KafkaBrokerList *src);

	static void kafka_cgroup_callback(__WFKafkaTask *task);

	static void kafka_offsetcommit_callback(__WFKafkaTask *task);

	static void kafka_parallel_callback(const ParallelWork *pwork);

	static void kafka_timer_callback(WFTimerTask *task);

	static void kafka_heartbeat_callback(__WFKafkaTask *task);

	static void kafka_leavegroup_callback(__WFKafkaTask *task);

	static void kafka_rebalance_proc(KafkaMember *member, SeriesWork *series);

	static void kafka_rebalance_callback(__WFKafkaTask *task);

	void kafka_move_task_callback(__WFKafkaTask *task);

	void kafka_process_toppar_offset(KafkaToppar *task_toppar);

	bool compare_topics(KafkaClientTask *task);

	bool check_cgroup();

	bool check_meta();

	int arrange_toppar(int api_type);

	int arrange_produce();

	int arrange_fetch();

	int arrange_commit();

	int arrange_offset();

	int dispatch_locked();

	inline KafkaBroker *get_broker(int node_id)
	{
		return this->member->broker_map.find_item(node_id);
	}

	int get_node_id(const KafkaToppar *toppar);

	bool get_meta_status(KafkaMetaList **uninit_meta_list);
	void set_meta_status(bool status);

	std::string get_userinfo() { return this->userinfo; }

private:
	KafkaMember *member;
	KafkaBroker broker;
	std::map<int, KafkaTopparList> toppar_list_map;
	std::string url;
	std::string query;
	std::set<std::string> topic_set;
	std::string userinfo;
	bool info_generated;
	bool wait_cgroup;
	void *msg;

	friend class WFKafkaClient;
};

int KafkaClientTask::get_node_id(const KafkaToppar *toppar)
{
	int preferred_read_replica = toppar->get_preferred_read_replica();
	if (preferred_read_replica >= 0)
		return preferred_read_replica;

	bool flag = false;
	this->member->meta_list.rewind();
	KafkaMeta *meta;
	while ((meta = this->member->meta_list.get_next()) != NULL)
	{
		if (strcmp(meta->get_topic(), toppar->get_topic()) == 0)
		{
			flag = true;
			break;
		}
	}

	const kafka_broker_t *broker = NULL;
	if (flag)
		broker = meta->get_broker(toppar->get_partition());

	if (!broker)
		return -1;

	return broker->node_id;
}

void KafkaClientTask::kafka_offsetcommit_callback(__WFKafkaTask *task)
{
	KafkaClientTask *t = (KafkaClientTask *)task->user_data;
	if (task->get_state() == WFT_STATE_SUCCESS)
		t->result.set_resp(std::move(*task->get_resp()), 0);

	t->finish = true;
	t->state = task->get_state();
	t->error = task->get_error();
	t->kafka_error = *static_cast<ComplexKafkaTask *>(task)->get_mutable_ctx();
}

void KafkaClientTask::kafka_leavegroup_callback(__WFKafkaTask *task)
{
	KafkaClientTask *t = (KafkaClientTask *)task->user_data;
	t->finish = true;
	t->state = task->get_state();
	t->error = task->get_error();
	t->kafka_error = *static_cast<ComplexKafkaTask *>(task)->get_mutable_ctx();
}

void KafkaClientTask::kafka_rebalance_callback(__WFKafkaTask *task)
{
	KafkaMember *member = (KafkaMember *)task->user_data;
	SeriesWork *series = series_of(task);
	size_t max;

	member->mutex.lock();
	if (member->client_deinit)
	{
		member->mutex.unlock();
		member->decref();
		return;
	}

	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		member->cgroup_status = KAFKA_CGROUP_DONE;
		member->cgroup = std::move(*(task->get_resp()->get_cgroup()));

		if (member->heartbeat_status == KAFKA_HEARTBEAT_UNINIT)
		{
			__WFKafkaTask *kafka_task;
			KafkaBroker *coordinator = member->cgroup.get_coordinator();
			kafka_task = __WFKafkaTaskFactory::create_kafka_task(member->transport_type,
																 coordinator->get_host(),
																 coordinator->get_port(),
																 "", 0,
																 kafka_heartbeat_callback);
			kafka_task->user_data = member;
			kafka_task->get_req()->set_api_type(Kafka_Heartbeat);
			kafka_task->get_req()->set_cgroup(member->cgroup);
			kafka_task->get_req()->set_broker(*coordinator);
			series->push_back(kafka_task);

			member->heartbeat_status = KAFKA_HEARTBEAT_DOING;
			member->heartbeat_series = series;
		}

		max = member->cgroup_wait_cnt;
		char name[64];
		snprintf(name, 64, "%p.cgroup", member);
		member->mutex.unlock();

		WFTaskFactory::signal_by_name(name, NULL, max);
	}
	else
		kafka_rebalance_proc(member, series);
}

void KafkaClientTask::kafka_rebalance_proc(KafkaMember *member, SeriesWork *series)
{
	KafkaBroker *coordinator = member->cgroup.get_coordinator();
	__WFKafkaTask *task;
	task = __WFKafkaTaskFactory::create_kafka_task(member->transport_type,
												   coordinator->get_host(),
												   coordinator->get_port(),
												   "", 0,
												   kafka_rebalance_callback);
	task->user_data = member;
	task->get_req()->set_config(member->config);
	task->get_req()->set_api_type(Kafka_FindCoordinator);
	task->get_req()->set_cgroup(member->cgroup);
	task->get_req()->set_meta_list(member->meta_list);

	member->cgroup_status = KAFKA_CGROUP_DOING;
	member->heartbeat_status = KAFKA_HEARTBEAT_UNINIT;
	member->cgroup_outdated = false;

	series->push_back(task);

	member->mutex.unlock();
}

void KafkaClientTask::kafka_heartbeat_callback(__WFKafkaTask *task)
{
	KafkaMember *member = (KafkaMember *)task->user_data;
	SeriesWork *series = series_of(task);
	KafkaResponse *resp = task->get_resp();

	member->mutex.lock();

	if (member->client_deinit || member->heartbeat_series != series)
	{
		member->mutex.unlock();
		member->decref();
		return;
	}

	if (resp->get_cgroup()->get_error() != 0)
	{
		kafka_rebalance_proc(member, series);
		return;
	}
	else
	{
		member->heartbeat_status = KAFKA_HEARTBEAT_DONE;
		WFTimerTask *timer_task;
		timer_task = WFTaskFactory::create_timer_task(KAFKA_HEARTBEAT_INTERVAL,
													  kafka_timer_callback);
		timer_task->user_data = member;
		series->push_back(timer_task);
	}

	member->mutex.unlock();
}

void KafkaClientTask::kafka_timer_callback(WFTimerTask *task)
{
	KafkaMember *member = (KafkaMember *)task->user_data;
	SeriesWork *series = series_of(task);

	member->mutex.lock();
	if (member->client_deinit || member->heartbeat_series != series)
	{
		member->mutex.unlock();
		member->decref();
		return;
	}

	member->heartbeat_status = KAFKA_HEARTBEAT_DOING;

	__WFKafkaTask *kafka_task;
	KafkaBroker *coordinator = member->cgroup.get_coordinator();
	kafka_task = __WFKafkaTaskFactory::create_kafka_task(member->transport_type,
														 coordinator->get_host(),
														 coordinator->get_port(),
														 "", 0,
														 kafka_heartbeat_callback);

	kafka_task->user_data = member;
	kafka_task->get_req()->set_config(member->config);
	kafka_task->get_req()->set_api_type(Kafka_Heartbeat);
	kafka_task->get_req()->set_cgroup(member->cgroup);
	kafka_task->get_req()->set_broker(*coordinator);
	series->push_back(kafka_task);

	member->mutex.unlock();
}

void KafkaClientTask::kafka_merge_meta_list(KafkaMetaList *dst,
											KafkaMetaList *src)
{
	src->rewind();
	KafkaMeta *src_meta;
	while ((src_meta = src->get_next()) != NULL)
	{
		dst->rewind();

		KafkaMeta *dst_meta;
		while ((dst_meta = dst->get_next()) != NULL)
		{
			if (strcmp(dst_meta->get_topic(), src_meta->get_topic()) == 0)
			{
				dst->del_cur();
				delete dst_meta;
				break;
			}
		}

		dst->add_item(*src_meta);
	}
}

void KafkaClientTask::kafka_merge_broker_list(const std::string& scheme,
											  std::vector<std::string> *hosts,
											  KafkaBrokerMap *dst,
											  KafkaBrokerList *src)
{
	hosts->clear();
	src->rewind();
	KafkaBroker *src_broker;
	while ((src_broker = src->get_next()) != NULL)
	{
		std::string host = scheme + src_broker->get_host() + ":" +
						   std::to_string(src_broker->get_port());
		hosts->emplace_back(std::move(host));

		if (!dst->find_item(src_broker->get_node_id()))
			dst->add_item(*src_broker, src_broker->get_node_id());
	}
}

void KafkaClientTask::kafka_meta_callback(__WFKafkaTask *task)
{
	KafkaClientTask *t = (KafkaClientTask *)task->user_data;
	void *msg = NULL;
	size_t max;

	t->member->mutex.lock();
	t->state = task->get_state();
	t->error = task->get_error();
	t->kafka_error = *static_cast<ComplexKafkaTask *>(task)->get_mutable_ctx();
	if (t->state == WFT_STATE_SUCCESS)
	{
		kafka_merge_meta_list(&t->member->meta_list,
							  task->get_resp()->get_meta_list());

		t->meta_list.rewind();
		KafkaMeta *meta;
		while ((meta = t->meta_list.get_next()) != NULL)
			(t->member->meta_status)[meta->get_topic()] = true;

		kafka_merge_broker_list(t->member->scheme,
								&t->member->broker_hosts,
								&t->member->broker_map,
								task->get_resp()->get_broker_list());
	}
	else
	{
		t->meta_list.rewind();
		KafkaMeta *meta;
		while ((meta = t->meta_list.get_next()) != NULL)
			(t->member->meta_status)[meta->get_topic()] = false;

		t->finish = true;
		msg = t;
	}

	t->member->meta_doing = false;
	max = t->member->meta_wait_cnt;
	char name[64];
	snprintf(name, 64, "%p.meta", t->member);
	t->member->mutex.unlock();

	WFTaskFactory::signal_by_name(name, msg, max);
}

void KafkaClientTask::kafka_cgroup_callback(__WFKafkaTask *task)
{
	KafkaClientTask *t = (KafkaClientTask *)task->user_data;
	SeriesWork *heartbeat_series = NULL;
	void *msg = NULL;
	size_t max;

	t->member->mutex.lock();
	t->state = task->get_state();
	t->error = task->get_error();
	t->kafka_error = *static_cast<ComplexKafkaTask *>(task)->get_mutable_ctx();

	if (t->state == WFT_STATE_SUCCESS)
	{
		t->member->cgroup = std::move(*(task->get_resp()->get_cgroup()));

		kafka_merge_meta_list(&t->member->meta_list,
							  task->get_resp()->get_meta_list());

		t->meta_list.rewind();
		KafkaMeta *meta;
		while ((meta = t->meta_list.get_next()) != NULL)
			(t->member->meta_status)[meta->get_topic()] = true;

		kafka_merge_broker_list(t->member->scheme,
								&t->member->broker_hosts,
								&t->member->broker_map,
								task->get_resp()->get_broker_list());

		t->member->cgroup_status = KAFKA_CGROUP_DONE;

		if (t->member->heartbeat_status == KAFKA_HEARTBEAT_UNINIT)
		{
			__WFKafkaTask *kafka_task;
			KafkaBroker *coordinator = t->member->cgroup.get_coordinator();
			kafka_task = __WFKafkaTaskFactory::create_kafka_task(t->member->transport_type,
																 coordinator->get_host(),
																 coordinator->get_port(),
																 "", 0,
																 kafka_heartbeat_callback);
			kafka_task->user_data = t->member;
			t->member->incref();

			kafka_task->get_req()->set_config(t->member->config);
			kafka_task->get_req()->set_api_type(Kafka_Heartbeat);
			kafka_task->get_req()->set_cgroup(t->member->cgroup);
			kafka_task->get_req()->set_broker(*coordinator);

			heartbeat_series = Workflow::create_series_work(kafka_task, nullptr);
			t->member->heartbeat_status = KAFKA_HEARTBEAT_DOING;
			t->member->heartbeat_series = heartbeat_series;
		}
	}
	else
	{
		t->member->cgroup_status = KAFKA_CGROUP_UNINIT;
		t->member->heartbeat_status = KAFKA_HEARTBEAT_UNINIT;
		t->member->heartbeat_series = NULL;
		t->finish = true;
		msg = t;
	}

	max = t->member->cgroup_wait_cnt;
	char name[64];
	snprintf(name, 64, "%p.cgroup", t->member);
	t->member->mutex.unlock();

	WFTaskFactory::signal_by_name(name, msg, max);

	if (heartbeat_series)
		heartbeat_series->start();
}

void KafkaClientTask::kafka_parallel_callback(const ParallelWork *pwork)
{
	KafkaClientTask *t = (KafkaClientTask *)pwork->get_context();
	t->finish = true;
	t->state = WFT_STATE_TASK_ERROR;
	t->error = 0;

	std::pair<int32_t, int32_t> *state_error;
	bool flag = false;
	int16_t state = WFT_STATE_SUCCESS;
	int16_t error = 0;
	int kafka_error = 0;
	for (size_t i = 0; i < pwork->size(); i++)
	{
		state_error = (std::pair<int32_t, int32_t> *)pwork->series_at(i)->get_context();
		if ((state_error->first >> 16) != WFT_STATE_SUCCESS)
		{
			if (!flag)
			{
				flag = true;
				t->member->mutex.lock();
				t->set_meta_status(false);
				t->member->mutex.unlock();
			}
			state = state_error->first >> 16;
			error = state_error->first & 0xffff;
			kafka_error = state_error->second;
		}
		else
		{
			t->state = WFT_STATE_SUCCESS;
		}

		delete state_error;
	}

	if (t->state != WFT_STATE_SUCCESS)
	{
		t->state = state;
		t->error = error;
		t->kafka_error = kafka_error;
	}
}

void KafkaClientTask::kafka_process_toppar_offset(KafkaToppar *task_toppar)
{
	KafkaToppar *toppar;

	struct list_head *pos;
	list_for_each(pos, this->member->cgroup.get_assigned_toppar_list())
	{
		toppar = this->member->cgroup.get_assigned_toppar_by_pos(pos);
		if (strcmp(toppar->get_topic(), task_toppar->get_topic()) == 0 &&
			toppar->get_partition() == task_toppar->get_partition())
		{
			long long offset = task_toppar->get_offset() - 1;
			KafkaRecord *last_record = task_toppar->get_tail_record();
			if (last_record)
				offset = last_record->get_offset();
			toppar->set_offset(offset + 1);
			toppar->set_low_watermark(task_toppar->get_low_watermark());
			toppar->set_high_watermark(task_toppar->get_high_watermark());
		}
	}
}

void KafkaClientTask::kafka_move_task_callback(__WFKafkaTask *task)
{
	auto *state_error = new std::pair<int32_t, int32_t>;
	int16_t state = task->get_state();
	int16_t error = task->get_error();

	/* 'state' is always positive. */
	state_error->first = (state << 16) | error;
	state_error->second = *static_cast<ComplexKafkaTask *>(task)->get_mutable_ctx();
	series_of(task)->set_context(state_error);

	KafkaTopparList *toppar_list = task->get_resp()->get_toppar_list();

	if (task->get_state() == WFT_STATE_SUCCESS &&
		task->get_resp()->get_api_type() == Kafka_Fetch)
	{
		toppar_list->rewind();
		KafkaToppar *task_toppar;

		while ((task_toppar = toppar_list->get_next()) != NULL)
			kafka_process_toppar_offset(task_toppar);
	}

	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		long idx = (long)(task->user_data);
		this->result.set_resp(std::move(*task->get_resp()), idx);
	}
}

void KafkaClientTask::generate_info()
{
	if (this->info_generated)
		return;

	if (this->config.get_sasl_mech())
	{
		const char *username = this->config.get_sasl_username();
		const char *password = this->config.get_sasl_password();

		this->userinfo.clear();
		if (username)
			this->userinfo += StringUtil::url_encode_component(username);
		this->userinfo += ":";
		if (password)
			this->userinfo += StringUtil::url_encode_component(password);
		this->userinfo += ":";
		this->userinfo += this->config.get_sasl_mech();
		this->userinfo += ":";
		this->userinfo += std::to_string((intptr_t)this->member);
	}
	else
	{
		char buf[64];
		snprintf(buf, 64, "user:pass:sasl:%p", this->member);
		this->userinfo = buf;
	}

	const char *hostport = this->url.c_str() + this->member->scheme.size();
	this->url = this->member->scheme + this->userinfo + "@" + hostport;
	this->info_generated = true;
}

void KafkaClientTask::parse_query()
{
	auto query_kv = URIParser::split_query_strict(this->query);
	int api_type = this->api_type;
	for (const auto &kv : query_kv)
	{
		if (strcasecmp(kv.first.c_str(), "api") == 0 &&
			api_type == Kafka_Unknown)
		{
			for (auto& v : kv.second)
			{
				if (strcasecmp(v.c_str(), "fetch") == 0)
					this->api_type = Kafka_Fetch;
				else if (strcasecmp(v.c_str(), "produce") == 0)
					this->api_type = Kafka_Produce;
				else if (strcasecmp(v.c_str(), "commit") == 0)
					this->api_type = Kafka_OffsetCommit;
				else if (strcasecmp(v.c_str(), "meta") == 0)
					this->api_type = Kafka_Metadata;
				else if (strcasecmp(v.c_str(), "leavegroup") == 0)
					this->api_type = Kafka_LeaveGroup;
				else if (strcasecmp(v.c_str(), "listoffsets") == 0)
					this->api_type = Kafka_ListOffsets;
			}
		}
		else if (strcasecmp(kv.first.c_str(), "topic") == 0)
		{
			for (auto& v : kv.second)
				this->add_topic(v);
		}
	}
}

bool KafkaClientTask::get_meta_status(KafkaMetaList **uninit_meta_list)
{
	this->meta_list.rewind();
	KafkaMeta *meta;
	std::set<std::string> unique;
	bool status = true;

	while ((meta = this->meta_list.get_next()) != NULL)
	{
		if (!unique.insert(meta->get_topic()).second)
			continue;

		if (!this->member->meta_status[meta->get_topic()])
		{
			if (status)
			{
				*uninit_meta_list = new KafkaMetaList;
				status = false;
			}

			(*uninit_meta_list)->add_item(*meta);
		}
	}

	return status;
}

void KafkaClientTask::set_meta_status(bool status)
{
	this->member->meta_list.rewind();
	KafkaMeta *meta;
	while ((meta = this->member->meta_list.get_next()) != NULL)
		this->member->meta_status[meta->get_topic()] = false;
}

bool KafkaClientTask::compare_topics(KafkaClientTask *task)
{
	auto first1 = topic_set.cbegin(), last1 = topic_set.cend();
	auto first2 = task->topic_set.cbegin(), last2 = task->topic_set.cend();
	int cmp;

	// check whether task->topic_set is a subset of topic_set
	while (first1 != last1 && first2 != last2)
	{
		cmp = first1->compare(*first2);
		if (cmp == 0)
		{
			++first1;
			++first2;
		}
		else if (cmp < 0)
			++first1;
		else
			return false;
	}

	return first2 == last2;
}

bool KafkaClientTask::check_cgroup()
{
	if (this->member->cgroup_outdated &&
		this->member->cgroup_status != KAFKA_CGROUP_DOING)
	{
		this->member->cgroup_outdated = false;
		this->member->cgroup_status = KAFKA_CGROUP_UNINIT;
		this->member->heartbeat_series = NULL;
		this->member->heartbeat_status = KAFKA_HEARTBEAT_UNINIT;
	}

	if (this->member->cgroup_status == KAFKA_CGROUP_DOING)
	{
		WFConditional *cond;
		char name[64];
		snprintf(name, 64, "%p.cgroup", this->member);
		this->wait_cgroup = true;
		cond = WFTaskFactory::create_conditional(name, this, &this->msg);
		series_of(this)->push_front(cond);
		this->member->cgroup_wait_cnt++;
		return false;
	}

	if ((this->api_type == Kafka_Fetch || this->api_type == Kafka_OffsetCommit) &&
		(this->member->cgroup_status == KAFKA_CGROUP_UNINIT))
	{
		__WFKafkaTask *task;

		task = __WFKafkaTaskFactory::create_kafka_task(this->url,
													   this->retry_max,
													   kafka_cgroup_callback);
		task->user_data = this;
		task->get_req()->set_config(this->config);
		task->get_req()->set_api_type(Kafka_FindCoordinator);
		task->get_req()->set_cgroup(this->member->cgroup);
		task->get_req()->set_meta_list(this->member->meta_list);
		series_of(this)->push_front(this);
		series_of(this)->push_front(task);
		this->member->cgroup_status = KAFKA_CGROUP_DOING;
		this->member->cgroup_wait_cnt = 0;
		return false;
	}

	return true;
}

bool KafkaClientTask::check_meta()
{
	KafkaMetaList *uninit_meta_list;

	if (this->get_meta_status(&uninit_meta_list))
		return true;

	if (this->member->meta_doing)
	{
		WFConditional *cond;
		char name[64];
		snprintf(name, 64, "%p.meta", this->member);
		this->wait_cgroup = false;
		cond = WFTaskFactory::create_conditional(name, this, &this->msg);
		series_of(this)->push_front(cond);
		this->member->meta_wait_cnt++;
	}
	else
	{
		__WFKafkaTask *task;

		task = __WFKafkaTaskFactory::create_kafka_task(this->url,
													   this->retry_max,
													   kafka_meta_callback);
		task->user_data = this;
		task->get_req()->set_config(this->config);
		task->get_req()->set_api_type(Kafka_Metadata);
		task->get_req()->set_meta_list(*uninit_meta_list);
		series_of(this)->push_front(this);
		series_of(this)->push_front(task);
		this->member->meta_wait_cnt = 0;
		this->member->meta_doing = true;
	}

	delete uninit_meta_list;
	return false;
}

int KafkaClientTask::dispatch_locked()
{
	KafkaMember *member = this->member;
	KafkaBroker *coordinator;
	__WFKafkaTask *task;
	ParallelWork *parallel;
	SeriesWork *series;

	if (this->check_cgroup() == false)
		return member->cgroup_wait_cnt > 0;

	if (this->check_meta() == false)
		return member->meta_wait_cnt > 0;

	if (arrange_toppar(this->api_type) < 0)
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_KAFKA_ARRANGE_FAILED;
		this->finish = true;
		return 0;
	}

	if (this->member->cgroup_outdated)
	{
		series_of(this)->push_front(this);
		return 0;
	}

	switch(this->api_type)
	{
	case Kafka_Produce:
		if (this->toppar_list_map.size() == 0)
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_KAFKA_PRODUCE_FAILED;
			this->finish = true;
			break;
		}

		parallel = Workflow::create_parallel_work(kafka_parallel_callback);
		this->result.create(this->toppar_list_map.size());
		parallel->set_context(this);
		for (auto &v : this->toppar_list_map)
		{
			auto cb = std::bind(&KafkaClientTask::kafka_move_task_callback, this,
								std::placeholders::_1);
			KafkaBroker *broker = get_broker(v.first);
			task = __WFKafkaTaskFactory::create_kafka_task(member->transport_type,
														   broker->get_host(),
														   broker->get_port(),
														   this->get_userinfo(),
														   this->retry_max,
														   std::move(cb));
			task->get_req()->set_config(this->config);
			task->get_req()->set_toppar_list(v.second);
			task->get_req()->set_broker(*broker);
			task->get_req()->set_api_type(Kafka_Produce);
			task->user_data = (void *)parallel->size();
			series = Workflow::create_series_work(task, nullptr);
			parallel->add_series(series);
		}
		series_of(this)->push_front(this);
		series_of(this)->push_front(parallel);
		break;

	case Kafka_Fetch:
		if (this->toppar_list_map.size() == 0)
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_KAFKA_FETCH_FAILED;
			this->finish = true;
			break;
		}

		parallel = Workflow::create_parallel_work(kafka_parallel_callback);
		this->result.create(this->toppar_list_map.size());
		parallel->set_context(this);
		for (auto &v : this->toppar_list_map)
		{
			auto cb = std::bind(&KafkaClientTask::kafka_move_task_callback, this,
								std::placeholders::_1);
			KafkaBroker *broker = get_broker(v.first);
			task = __WFKafkaTaskFactory::create_kafka_task(member->transport_type,
														   broker->get_host(),
														   broker->get_port(),
														   this->get_userinfo(),
														   this->retry_max,
														   std::move(cb));

			task->get_req()->set_config(this->config);
			task->get_req()->set_toppar_list(v.second);
			task->get_req()->set_broker(*broker);
			task->get_req()->set_api_type(Kafka_Fetch);
			task->user_data = (void *)parallel->size();
			series = Workflow::create_series_work(task, nullptr);
			parallel->add_series(series);
		}

		series_of(this)->push_front(this);
		series_of(this)->push_front(parallel);
		break;

	case Kafka_Metadata:
		this->finish = true;
		break;

	case Kafka_OffsetCommit:
		if (!member->cgroup.get_group())
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_KAFKA_COMMIT_FAILED;
			this->finish = true;
			break;
		}

		this->result.create(1);
		coordinator = member->cgroup.get_coordinator();
		task = __WFKafkaTaskFactory::create_kafka_task(member->transport_type,
													   coordinator->get_host(),
													   coordinator->get_port(),
													   this->get_userinfo(),
													   this->retry_max,
													   kafka_offsetcommit_callback);
		task->user_data = this;
		task->get_req()->set_config(this->config);
		task->get_req()->set_cgroup(member->cgroup);
		task->get_req()->set_broker(*coordinator);
		task->get_req()->set_toppar_list(this->toppar_list);
		task->get_req()->set_api_type(this->api_type);
		series_of(this)->push_front(this);
		series_of(this)->push_front(task);
		break;

	case Kafka_LeaveGroup:
		if (!member->cgroup.get_group())
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_KAFKA_LEAVEGROUP_FAILED;
			this->finish = true;
			break;
		}

		coordinator = member->cgroup.get_coordinator();
		if (!coordinator->get_host())
			break;

		task = __WFKafkaTaskFactory::create_kafka_task(member->transport_type,
													   coordinator->get_host(),
													   coordinator->get_port(),
													   this->get_userinfo(), 0,
													   kafka_leavegroup_callback);
		task->user_data = this;
		task->get_req()->set_config(this->config);
		task->get_req()->set_api_type(Kafka_LeaveGroup);
		task->get_req()->set_broker(*coordinator);
		task->get_req()->set_cgroup(member->cgroup);
		series_of(this)->push_front(this);
		series_of(this)->push_front(task);
		break;

	case Kafka_ListOffsets:
		if (this->toppar_list_map.size() == 0)
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_KAFKA_LIST_OFFSETS_FAILED;
			this->finish = true;
			break;
		}

		parallel = Workflow::create_parallel_work(kafka_parallel_callback);
		this->result.create(this->toppar_list_map.size());
		parallel->set_context(this);
		for (auto &v : this->toppar_list_map)
		{
			auto cb = std::bind(&KafkaClientTask::kafka_move_task_callback, this,
								std::placeholders::_1);
			KafkaBroker *broker = get_broker(v.first);
			task = __WFKafkaTaskFactory::create_kafka_task(member->transport_type,
														   broker->get_host(),
														   broker->get_port(),
														   this->get_userinfo(),
														   this->retry_max,
														   std::move(cb));
			task->get_req()->set_config(this->config);
			task->get_req()->set_toppar_list(v.second);
			task->get_req()->set_broker(*broker);
			task->get_req()->set_api_type(Kafka_ListOffsets);
			task->user_data = (void *)parallel->size();
			series = Workflow::create_series_work(task, nullptr);
			parallel->add_series(series);
		}
		series_of(this)->push_front(this);
		series_of(this)->push_front(parallel);
		break;

	default:
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_KAFKA_API_UNKNOWN;
		this->finish = true;
		break;
	}

	return 0;
}

void KafkaClientTask::dispatch()
{
	if (this->finish)
	{
		this->subtask_done();
		return;
	}

	if (this->msg)
	{
		KafkaClientTask *task = static_cast<KafkaClientTask *>(this->msg);
		if (this->wait_cgroup || this->compare_topics(task) == true)
		{
			this->state = task->get_state();
			this->error = task->get_error();
			this->kafka_error = get_kafka_error();
			this->finish = true;
			this->subtask_done();
			return;
		}

		this->msg = NULL;
	}

	if (!this->query.empty())
		this->parse_query();

	this->generate_info();

	int flag;
	this->member->mutex.lock();
	flag = this->dispatch_locked();
	if (flag)
		this->subtask_done();
	this->member->mutex.unlock();

	if (!flag)
		this->subtask_done();
}

bool KafkaClientTask::add_topic(const std::string& topic)
{
	bool flag = false;
	this->member->mutex.lock();

	this->topic_set.insert(topic);
	this->member->meta_list.rewind();
	KafkaMeta *meta;
	while ((meta = this->member->meta_list.get_next()) != NULL)
	{
		if (meta->get_topic() == topic)
		{
			flag = true;
			break;
		}
	}

	if (!flag)
	{
		this->member->meta_status[topic] = false;

		KafkaMeta tmp;
		if (!tmp.set_topic(topic))
		{
			this->member->mutex.unlock();
			return false;
		}

		this->meta_list.add_item(tmp);
		this->member->meta_list.add_item(tmp);

		if (this->member->cgroup.get_group())
			this->member->cgroup_outdated = true;
	}
	else
	{
		this->meta_list.rewind();
		KafkaMeta *exist;
		while ((exist = this->meta_list.get_next()) != NULL)
		{
			if (strcmp(exist->get_topic(), meta->get_topic()) == 0)
			{
				this->member->mutex.unlock();
				return true;
			}
		}

		this->meta_list.add_item(*meta);
	}

	this->member->mutex.unlock();

	return true;
}

bool KafkaClientTask::add_toppar(const KafkaToppar& toppar)
{
	if (this->member->cgroup.get_group())
		return false;

	bool flag = false;
	this->member->mutex.lock();

	this->member->meta_list.rewind();
	KafkaMeta *meta;
	while ((meta = this->member->meta_list.get_next()) != NULL)
	{
		if (strcmp(meta->get_topic(), toppar.get_topic()) == 0)
		{
			flag = true;
			break;
		}
	}

	this->topic_set.insert(toppar.get_topic());
	if (!flag)
	{
		KafkaMeta tmp;
		if (!tmp.set_topic(toppar.get_topic()))
		{
			this->member->mutex.unlock();
			return false;
		}

		KafkaToppar new_toppar;
		if (!new_toppar.set_topic_partition(toppar.get_topic(), toppar.get_partition()))
		{
			this->member->mutex.unlock();
			return false;
		}

		new_toppar.set_offset(toppar.get_offset());
		this->toppar_list.add_item(new_toppar);

		this->meta_list.add_item(tmp);
		this->member->meta_list.add_item(tmp);

		if (this->member->cgroup.get_group())
			this->member->cgroup_outdated = true;
	}
	else
	{
		this->toppar_list.rewind();
		KafkaToppar *exist;
		while ((exist = this->toppar_list.get_next()) != NULL)
		{
			if (strcmp(exist->get_topic(), toppar.get_topic()) == 0 &&
				exist->get_partition() == toppar.get_partition())
			{
				this->member->mutex.unlock();
				return true;
			}
		}

		KafkaToppar new_toppar;
		if (!new_toppar.set_topic_partition(toppar.get_topic(), toppar.get_partition()))
		{
			this->member->mutex.unlock();
			return true;
		}

		new_toppar.set_offset(toppar.get_offset());
		this->toppar_list.add_item(new_toppar);

		this->meta_list.add_item(*meta);
	}

	this->member->mutex.unlock();

	return true;
}

bool KafkaClientTask::add_produce_record(const std::string& topic,
										 int partition,
										 KafkaRecord record)
{
	if (!add_topic(topic))
		return false;

	bool flag = false;
	this->toppar_list.rewind();
	KafkaToppar *toppar;
	while ((toppar = this->toppar_list.get_next()) != NULL)
	{
		if (toppar->get_topic() == topic &&
			toppar->get_partition() == partition)
		{
			flag = true;
			break;
		}
	}

	if (!flag)
	{
		KafkaToppar new_toppar;
		if (!new_toppar.set_topic_partition(topic, partition))
			return false;

		new_toppar.add_record(std::move(record));
		this->toppar_list.add_item(std::move(new_toppar));
	}
	else
		toppar->add_record(std::move(record));

	return true;
}

static bool check_replace_toppar(KafkaTopparList *toppar_list, KafkaToppar *toppar)
{
	bool flag = false;
	toppar_list->rewind();
	KafkaToppar *exist;
	while ((exist = toppar_list->get_next()) != NULL)
	{
		if (strcmp(exist->get_topic(), toppar->get_topic()) == 0 &&
			exist->get_partition() == toppar->get_partition())
		{
			flag = true;
			if (toppar->get_offset() > exist->get_offset())
			{
				toppar_list->add_item(std::move(*toppar));
				toppar_list->del_cur();
				delete exist;
				return true;
			}
		}
	}

	if (!flag)
	{
		toppar_list->add_item(std::move(*toppar));
		return true;
	}

	return false;
}

int KafkaClientTask::arrange_toppar(int api_type)
{
	switch(api_type)
	{
	case Kafka_Produce:
		return this->arrange_produce();

	case Kafka_Fetch:
		return this->arrange_fetch();

	case Kafka_ListOffsets:
		return this->arrange_offset();

	case Kafka_OffsetCommit:
		return this->arrange_commit();

	default:
		return 0;
	}
}

bool KafkaClientTask::add_offset_toppar(const protocol::KafkaToppar& toppar)
{
	if (!add_topic(toppar.get_topic()))
		return false;

	KafkaToppar *exist;
	bool found = false;
	while ((exist = this->toppar_list.get_next()) != NULL)
	{
		if (strcmp(exist->get_topic(), toppar.get_topic()) == 0 &&
				exist->get_partition() == toppar.get_partition())
		{
			found = true;
			break;
		}
	}

	if (!found)
	{
		KafkaToppar toppar_t;
		toppar_t.set_topic_partition(toppar.get_topic(), toppar.get_partition());
		this->toppar_list.add_item(std::move(toppar_t));
	}

	return true;
}

int KafkaClientTask::arrange_offset()
{
	this->toppar_list.rewind();
	KafkaToppar *toppar;
	while ((toppar = this->toppar_list.get_next()) != NULL)
	{
		int node_id = get_node_id(toppar);
		if (node_id < 0)
			return -1;

		if (this->toppar_list_map.find(node_id) == this->toppar_list_map.end())
			this->toppar_list_map[node_id] = (KafkaTopparList());

		KafkaToppar new_toppar;
		if (!new_toppar.set_topic_partition(toppar->get_topic(), toppar->get_partition()))
			return -1;

		this->toppar_list_map[node_id].add_item(std::move(new_toppar));
	}

	return 0;
}

int KafkaClientTask::arrange_commit()
{
	this->toppar_list.rewind();
	KafkaTopparList new_toppar_list;
	KafkaToppar *toppar;
	while ((toppar = this->toppar_list.get_next()) != NULL)
	{
		check_replace_toppar(&new_toppar_list, toppar);
	}

	this->toppar_list = std::move(new_toppar_list);
	return 0;
}

int KafkaClientTask::arrange_fetch()
{
	this->meta_list.rewind();
	for (auto& topic : topic_set)
	{
		if (this->member->cgroup.get_group())
		{
			this->member->cgroup.assigned_toppar_rewind();
			KafkaToppar *toppar;
			while ((toppar = this->member->cgroup.get_assigned_toppar_next()) != NULL)
			{
				if (topic.compare(toppar->get_topic()) == 0)
				{
					int node_id = get_node_id(toppar);
					if (node_id < 0)
						return -1;

					if (this->toppar_list_map.find(node_id) == this->toppar_list_map.end())
						this->toppar_list_map[node_id] = (KafkaTopparList());

					KafkaToppar new_toppar;
					if (!new_toppar.set_topic_partition(toppar->get_topic(), toppar->get_partition()))
						return -1;

					new_toppar.set_offset(toppar->get_offset());
					new_toppar.set_low_watermark(toppar->get_low_watermark());
					new_toppar.set_high_watermark(toppar->get_high_watermark());
					this->toppar_list_map[node_id].add_item(std::move(new_toppar));
				}
			}
		}
		else
		{
			this->toppar_list.rewind();
			KafkaToppar *toppar;
			while ((toppar = this->toppar_list.get_next()) != NULL)
			{
				if (topic.compare(toppar->get_topic()) == 0)
				{
					int node_id = get_node_id(toppar);
					if (node_id < 0)
						return -1;

					if (this->toppar_list_map.find(node_id) == this->toppar_list_map.end())
						this->toppar_list_map[node_id] = KafkaTopparList();

					KafkaToppar new_toppar;
					if (!new_toppar.set_topic_partition(toppar->get_topic(), toppar->get_partition()))
						return -1;

					new_toppar.set_offset(toppar->get_offset());
					new_toppar.set_low_watermark(toppar->get_low_watermark());
					this->toppar_list_map[node_id].add_item(std::move(new_toppar));
				}
			}
		}
	}

	return 0;
}

int KafkaClientTask::arrange_produce()
{
	this->toppar_list.rewind();
	KafkaToppar *toppar;
	while ((toppar = this->toppar_list.get_next()) != NULL)
	{
		if (toppar->get_partition() < 0)
		{
			toppar->record_rewind();
			KafkaRecord *record;
			while ((record = toppar->get_record_next()) != NULL)
			{
				int partition_num;
				const KafkaMeta *meta;
				meta = get_meta(toppar->get_topic(), &this->member->meta_list);
				if (!meta)
					return -1;

				partition_num = meta->get_partition_elements();
				if (partition_num <= 0)
					return -1;

				int partition = -1;
				if (this->partitioner)
				{
					const void *key;
					size_t key_len;
					record->get_key(&key, &key_len);
					partition = this->partitioner(toppar->get_topic(), key,
												  key_len, partition_num);
				}
				else
					partition = rand() % partition_num;

				KafkaToppar *new_toppar = get_toppar(toppar->get_topic(),
													 partition,
													 &this->toppar_list);
				if (!new_toppar)
				{
					KafkaToppar tmp;
					if (!tmp.set_topic_partition(toppar->get_topic(), partition))
						return -1;

					new_toppar = this->toppar_list.add_item(std::move(tmp));
				}

				record->get_raw_ptr()->toppar = new_toppar->get_raw_ptr();
				new_toppar->add_record(std::move(*record));
				toppar->del_record_cur();
				delete record;
			}
			this->toppar_list.del_cur();
			delete toppar;
		}
		else
		{
			KafkaRecord *record;
			while ((record = toppar->get_record_next()) != NULL)
				record->get_raw_ptr()->toppar = toppar->get_raw_ptr();
		}
	}

	this->toppar_list.rewind();
	KafkaTopparList toppar_list;
	while ((toppar = this->toppar_list.get_next()) != NULL)
	{
		int node_id = get_node_id(toppar);
		if (node_id < 0)
			return -1;

		if (this->toppar_list_map.find(node_id) == this->toppar_list_map.end())
			this->toppar_list_map[node_id] = KafkaTopparList();

		this->toppar_list_map[node_id].add_item(std::move(*toppar));
	}

	return 0;
}

SubTask *WFKafkaTask::done()
{
	SeriesWork *series = series_of(this);

	auto cb = [] (WFTimerTask *task)
	{
		WFKafkaTask *kafka_task = (WFKafkaTask *)task->user_data;
		if (kafka_task->callback)
			kafka_task->callback(kafka_task);

		delete kafka_task;
	};

	if (finish)
	{
		if (this->state == WFT_STATE_TASK_ERROR)
		{
			WFTimerTask *timer;
			timer = WFTaskFactory::create_timer_task(0, 0, std::move(cb));
			timer->user_data = this;
			series->push_front(timer);
		}
		else
		{
			if (this->callback)
				this->callback(this);

			delete this;
		}
	}

	return series->pop();
}

int WFKafkaClient::init(const std::string& broker)
{
	std::vector<std::string> broker_hosts;
	std::string::size_type ppos = 0;
	std::string::size_type pos;
	bool use_ssl;

	use_ssl = (strncasecmp(broker.c_str(), "kafkas://", 9) == 0);
	while (1)
	{
		pos = broker.find(',', ppos);
		std::string host = broker.substr(ppos, pos - ppos);
		if (use_ssl)
		{
			if (strncasecmp(host.c_str(), "kafkas://", 9) != 0)
			{
				errno = EINVAL;
				return -1;
			}
		}
		else if (strncasecmp(host.c_str(), "kafka://", 8) != 0)
		{
			if (strncasecmp(host.c_str(), "kafkas://", 9) == 0)
			{
				errno = EINVAL;
				return -1;
			}

			host = "kafka://" + host;
		}

		broker_hosts.emplace_back(host);
		if (pos == std::string::npos)
			break;

		ppos = pos + 1;
	}

	this->member = new KafkaMember;
	this->member->broker_hosts = std::move(broker_hosts);
	if (use_ssl)
	{
		this->member->transport_type = TT_TCP_SSL;
		this->member->scheme = "kafkas://";
	}

	return 0;
}

int WFKafkaClient::init(const std::string& broker, const std::string& group)
{
	if (this->init(broker) < 0)
		return -1;

	this->member->cgroup.set_group(group);
	this->member->cgroup_status = KAFKA_CGROUP_UNINIT;
	return 0;
}

int WFKafkaClient::deinit()
{
	this->member->mutex.lock();
	this->member->client_deinit = true;
	this->member->mutex.unlock();
	this->member->decref();
	return 0;
}

WFKafkaTask *WFKafkaClient::create_kafka_task(const std::string& query,
											  int retry_max,
											  kafka_callback_t cb)
{
	WFKafkaTask *task = new KafkaClientTask(query, retry_max, std::move(cb),
											this);
	return task;
}

WFKafkaTask *WFKafkaClient::create_kafka_task(int retry_max,
											  kafka_callback_t cb)
{
	WFKafkaTask *task = new KafkaClientTask("", retry_max, std::move(cb), this);
	return task;
}

WFKafkaTask *WFKafkaClient::create_leavegroup_task(int retry_max,
												   kafka_callback_t cb)
{
	WFKafkaTask *task = new KafkaClientTask("api=leavegroup", retry_max,
											std::move(cb), this);
	return task;
}

void WFKafkaClient::set_config(protocol::KafkaConfig conf)
{
	this->member->config = std::move(conf);
}

KafkaMetaList *WFKafkaClient::get_meta_list()
{
	return &this->member->meta_list;
}

