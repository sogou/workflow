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


#include <unistd.h>
#include <stdint.h>
#include <cstddef>
#include <string.h>
#include <set>
#include "WFKafkaClient.h"

#define KAFKA_HEARTBEAT_INTERVAL	(3 * 1000 * 1000)

#define KAFKA_CGROUP_INIT		(1<<3)
#define KAFKA_CGROUP_DOING		(1<<4)
#define KAFKA_CGROUP_DONE		(1<<5)
#define KAFKA_HEARTBEAT_INIT	(1<<6)
#define KAFKA_HEARTBEAT_DOING	(1<<7)
#define KAFKA_HEARTBEAT_DONE	(1<<8)
#define KAFKA_DEINIT			(1<<30)

using namespace protocol;

using KafkaComplexTask = WFComplexClientTask<KafkaRequest, KafkaResponse,
											 __kafka_callback_t>;

enum MetaStatus
{
	META_UNINIT,
	META_DOING,
	META_INITED,
};

class KafkaMember
{
public:
	KafkaMember() : status(0), ref(1) {}

	void incref()
	{
		++this->ref;
	}

	void decref()
	{
		if (--this->ref == 0)
			delete this;
	}

	std::vector<std::string> broker_hosts;
	KafkaCgroup cgroup;
	KafkaMetaList meta_list;
	KafkaBrokerMap broker_map;
	KafkaConfig config;
	std::map<std::string, enum MetaStatus> meta_map;
	std::mutex mutex;
	int status;
	std::atomic<int> ref;
};

class ComplexKafkaTask : public WFKafkaTask
{
public:
	ComplexKafkaTask(const std::string& query, int retry_max,
					 kafka_callback_t&& callback,
					 WFKafkaClient *client) :
		WFKafkaTask(retry_max, std::move(callback))
	{
		this->api_type = Kafka_Unknown;
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
	}

	virtual ~ComplexKafkaTask()
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

	static void kafka_merge_meta_list(KafkaMetaList* dst,
									  KafkaMetaList* src);

	static void kafka_merge_broker_list(std::vector<std::string> *hosts,
										KafkaBrokerMap *dst,
										KafkaBrokerList *src);

	static void kafka_cgroup_callback(__WFKafkaTask *task);

	static void kafka_offsetcommit_callback(__WFKafkaTask *task);

	static void kafka_parallel_callback(const ParallelWork *pwork);

	static void kafka_timer_callback(WFTimerTask *task);

	static void kafka_heartbeat_callback(__WFKafkaTask *task);

	static void kafka_leavegroup_callback(__WFKafkaTask *task);

	static void kafka_rebalance_proc(KafkaMember *member);

	static void kafka_rebalance_callback(__WFKafkaTask *task);

	void kafka_move_task_callback(__WFKafkaTask *task);

	void kafka_process_toppar_offset(KafkaToppar *task_toppar);

	int arrange_toppar(int api_type);

	int arrange_produce();

	int arrange_fetch();

	int arrange_commit();

	int arrange_offset();

	inline KafkaBroker *get_broker(int node_id)
	{
		return this->member->broker_map.find_item(node_id);
	}

	int get_node_id(const KafkaToppar *toppar);

	enum MetaStatus get_meta_status();
	void set_meta_status(enum MetaStatus status);

	std::string get_userinfo() { return this->userinfo; }

private:
	KafkaMember *member;
	KafkaBroker broker;
	std::map<int, KafkaTopparList> toppar_list_map;
	std::string url;
	std::string query;
	std::set<std::string> topic_set;
	std::string userinfo;

	friend class WFKafkaClient;
};

int ComplexKafkaTask::get_node_id(const KafkaToppar *toppar)
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

void ComplexKafkaTask::kafka_offsetcommit_callback(__WFKafkaTask *task)
{
	ComplexKafkaTask *t = (ComplexKafkaTask *)task->user_data;
	if (task->get_state() == WFT_STATE_SUCCESS)
		t->result.set_resp(std::move(*task->get_resp()), 0);

	t->finish = true;
	t->state = task->get_state();
	t->error = task->get_error();
}

void ComplexKafkaTask::kafka_leavegroup_callback(__WFKafkaTask *task)
{
	ComplexKafkaTask *t = (ComplexKafkaTask *)task->user_data;
	t->finish = true;
	t->state = task->get_state();
	t->error = task->get_error();
}

void ComplexKafkaTask::kafka_rebalance_callback(__WFKafkaTask *task)
{
	KafkaMember *member = (KafkaMember *)task->user_data;

	member->mutex.lock();
	if (member->status & KAFKA_DEINIT)
	{
		member->mutex.unlock();
		member->decref();
		return;
	}


	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		member->status |= KAFKA_CGROUP_DONE;
		member->status &= (~(KAFKA_CGROUP_INIT|KAFKA_CGROUP_DOING));

		if (member->status & KAFKA_HEARTBEAT_INIT)
		{
			__WFKafkaTask *kafka_task;
			KafkaBroker *coordinator = member->cgroup.get_coordinator();

			const struct sockaddr *addr;
			socklen_t socklen;
			coordinator->get_broker_addr(&addr, &socklen);

			kafka_task = __WFKafkaTaskFactory::create_kafka_task(addr,
																 socklen,
																 "",
																 0,
																 kafka_heartbeat_callback);
			kafka_task->user_data = member;
			kafka_task->get_req()->set_api_type(Kafka_Heartbeat);
			kafka_task->get_req()->set_cgroup(member->cgroup);
			kafka_task->get_req()->set_broker(*coordinator);
			kafka_task->start();
			member->status |= KAFKA_HEARTBEAT_DOING;
			member->status &= ~KAFKA_HEARTBEAT_INIT;
		}

		member->mutex.unlock();

		char name[64];
		snprintf(name, 64, "%p.cgroup", member);
		WFTaskFactory::count_by_name(name, (unsigned int)-1);
	}
	else
		kafka_rebalance_proc(member);
}

void ComplexKafkaTask::kafka_rebalance_proc(KafkaMember *member)
{
	KafkaBroker *coordinator = member->cgroup.get_coordinator();

	const struct sockaddr *addr;
	socklen_t socklen;
	coordinator->get_broker_addr(&addr, &socklen);

	__WFKafkaTask *task;
	task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen, "", 0,
												   kafka_rebalance_callback);
	task->user_data = member;
	task->get_req()->set_config(member->config);
	task->get_req()->set_api_type(Kafka_FindCoordinator);
	task->get_req()->set_cgroup(member->cgroup);
	task->get_req()->set_meta_list(member->meta_list);

	member->status |= KAFKA_CGROUP_DOING;
	member->status &= (~(KAFKA_CGROUP_DONE|KAFKA_CGROUP_INIT));

	member->status |= KAFKA_HEARTBEAT_INIT;
	member->status &= (~(KAFKA_HEARTBEAT_DONE|KAFKA_HEARTBEAT_DOING));

	task->start();

	member->mutex.unlock();
}

void ComplexKafkaTask::kafka_heartbeat_callback(__WFKafkaTask *task)
{
	KafkaMember *member = (KafkaMember *)task->user_data;

	member->mutex.lock();
	if (member->status & KAFKA_DEINIT)
	{
		member->mutex.unlock();
		member->decref();
		return;
	}


	if (member->cgroup.get_error() != 0)
	{
		kafka_rebalance_proc(member);
		return;
	}
	else
	{
		member->status |= KAFKA_HEARTBEAT_DONE;
		member->status &= ~KAFKA_HEARTBEAT_DOING;
		WFTimerTask *timer_task;
		timer_task = WFTaskFactory::create_timer_task(KAFKA_HEARTBEAT_INTERVAL,
													  kafka_timer_callback);
		timer_task->user_data = member;
		timer_task->start();
	}

	member->mutex.unlock();
}

void ComplexKafkaTask::kafka_timer_callback(WFTimerTask *task)
{
	KafkaMember *member = (KafkaMember *)task->user_data;

	member->mutex.lock();
	if (member->status & KAFKA_DEINIT)
	{
		member->mutex.unlock();
		member->decref();
		return;
	}

	member->status |= KAFKA_HEARTBEAT_DOING;
	__WFKafkaTask *kafka_task;
	KafkaBroker *coordinator = member->cgroup.get_coordinator();

	const struct sockaddr *addr;
	socklen_t socklen;
	coordinator->get_broker_addr(&addr, &socklen);

	kafka_task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen, "", 0,
														 kafka_heartbeat_callback);

	kafka_task->user_data = member;
	kafka_task->get_req()->set_config(member->config);
	kafka_task->get_req()->set_api_type(Kafka_Heartbeat);
	kafka_task->get_req()->set_cgroup(member->cgroup);
	kafka_task->get_req()->set_broker(*coordinator);
	kafka_task->start();

	member->mutex.unlock();
}

void ComplexKafkaTask::kafka_merge_meta_list(KafkaMetaList *dst,
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

void ComplexKafkaTask::kafka_merge_broker_list(std::vector<std::string> *hosts,
											   KafkaBrokerMap *dst,
											   KafkaBrokerList *src)
{
	hosts->clear();
	src->rewind();
	KafkaBroker *src_broker;
	while ((src_broker = src->get_next()) != NULL)
	{
		std::string host = "kafka://";
		host = host + src_broker->get_host() + ":" +
			std::to_string(src_broker->get_port());
		hosts->emplace_back(std::move(host));

		if (!dst->find_item(src_broker->get_node_id()))
			dst->add_item(*src_broker, src_broker->get_node_id());
	}
}

void ComplexKafkaTask::kafka_meta_callback(__WFKafkaTask *task)
{
	ComplexKafkaTask *t = (ComplexKafkaTask *)task->user_data;
	t->member->mutex.lock();
	t->state = task->get_state();
	t->error = task->get_error();
	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		kafka_merge_meta_list(&t->member->meta_list,
							  task->get_resp()->get_meta_list());

		t->meta_list.rewind();
		KafkaMeta *meta;
		while ((meta = t->meta_list.get_next()) != NULL)
			(t->member->meta_map)[meta->get_topic()] = META_INITED;

		kafka_merge_broker_list(&t->member->broker_hosts,
								&t->member->broker_map,
								task->get_resp()->get_broker_list());
	}
	else
	{
		t->meta_list.rewind();
		KafkaMeta *meta;
		while ((meta = t->meta_list.get_next()) != NULL)
			(t->member->meta_map)[meta->get_topic()] = META_UNINIT;

		t->finish = true;
	}

	char name[64];
	snprintf(name, 64, "%p.meta", t->member);
	t->member->mutex.unlock();
	WFTaskFactory::count_by_name(name, (unsigned int)-1);
}

void ComplexKafkaTask::kafka_cgroup_callback(__WFKafkaTask *task)
{
	ComplexKafkaTask *t = (ComplexKafkaTask *)task->user_data;
	t->member->mutex.lock();
	t->state = task->get_state();
	t->error = task->get_error();
	if (task->get_state() == 0)
	{
		kafka_merge_meta_list(&t->member->meta_list,
							  task->get_resp()->get_meta_list());

		t->meta_list.rewind();
		KafkaMeta *meta;
		while ((meta = t->meta_list.get_next()) != NULL)
			(t->member->meta_map)[meta->get_topic()] = META_INITED;

		kafka_merge_broker_list(&t->member->broker_hosts,
								&t->member->broker_map,
								task->get_resp()->get_broker_list());

		t->member->status |= KAFKA_CGROUP_DONE;
		t->member->status &= (~(KAFKA_CGROUP_INIT|KAFKA_CGROUP_DOING));

		if (t->member->status & KAFKA_HEARTBEAT_INIT)
		{
			t->member->incref();
			__WFKafkaTask *kafka_task;
			KafkaBroker *coordinator = t->member->cgroup.get_coordinator();

			const struct sockaddr *addr;
			socklen_t socklen;
			coordinator->get_broker_addr(&addr, &socklen);

			kafka_task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen,
																 "", 0,
																 kafka_heartbeat_callback);
			kafka_task->user_data = t->member;
			kafka_task->get_req()->set_config(t->member->config);
			kafka_task->get_req()->set_api_type(Kafka_Heartbeat);
			kafka_task->get_req()->set_cgroup(t->member->cgroup);
			kafka_task->get_req()->set_broker(*coordinator);
			kafka_task->start();
			t->member->status |= KAFKA_HEARTBEAT_DOING;
			t->member->status &= ~KAFKA_HEARTBEAT_INIT;
		}
	}
	else
	{
		t->member->status |= KAFKA_CGROUP_INIT;
		t->member->status &= (~(KAFKA_CGROUP_DONE|KAFKA_CGROUP_DOING));
		t->finish = true;
	}

	char name[64];
	snprintf(name, 64, "%p.cgroup", t->member);
	t->member->mutex.unlock();
	WFTaskFactory::count_by_name(name, (unsigned int)-1);
}

void ComplexKafkaTask::kafka_parallel_callback(const ParallelWork *pwork)
{
	ComplexKafkaTask *t = (ComplexKafkaTask *)pwork->get_context();
	t->finish = true;
	t->state = WFT_STATE_TASK_ERROR;
	t->error = 0;

	std::pair<int, int> *state_error;
	bool flag = false;
	int error = 0;
	for (size_t i = 0; i < pwork->size(); i++)
	{
		state_error = (std::pair<int, int> *)pwork->series_at(i)->get_context();
		if (state_error->first != WFT_STATE_SUCCESS)
		{
			if (!flag)
			{
				flag = true;
				t->member->mutex.lock();
				t->set_meta_status(META_UNINIT);
				t->member->mutex.unlock();
			}
			error = state_error->second;
		}
		else
		{
			t->state = WFT_STATE_SUCCESS;
		}

		delete state_error;
	}

	if (t->state != WFT_STATE_SUCCESS)
		t->error = error;
}

void ComplexKafkaTask::kafka_process_toppar_offset(KafkaToppar *task_toppar)
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

void ComplexKafkaTask::kafka_move_task_callback(__WFKafkaTask *task)
{
	std::pair<int, int> *state_error = new std::pair<int, int>;

	state_error->first = task->get_state();
	state_error->second = task->get_error();
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

void ComplexKafkaTask::generate_info()
{
	if (this->config.get_sasl_mech())
	{
		this->userinfo = this->config.get_sasl_username();
		this->userinfo += ":";
		this->userinfo += this->config.get_sasl_password();
		this->userinfo += ":";
		this->userinfo += this->config.get_sasl_mech();
		this->userinfo += ":";
		this->userinfo += std::to_string((intptr_t)this->member);
		this->userinfo += "@";
		this->url = "kafka://" + this->userinfo +
		  this->url.substr(this->url.find("kafka://") + 8);
	}
	else
	{
		char buf[64];
		snprintf(buf, sizeof(buf), "user:pass:sasl:%p@", this->member);
		this->userinfo = buf;
		this->url = "kafka://" + this->userinfo +
			this->url.substr(this->url.find("kafka://") + 8);
	}
}

void ComplexKafkaTask::parse_query()
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

enum MetaStatus ComplexKafkaTask::get_meta_status()
{
	this->meta_list.rewind();
	KafkaMeta *meta;
	enum MetaStatus ret = META_INITED;
	std::set<std::string> unique;
	while ((meta = this->meta_list.get_next()) != NULL)
	{
		if (!unique.insert(meta->get_topic()).second)
			continue;

		switch(this->member->meta_map[meta->get_topic()])
		{
		case META_DOING:
			return META_DOING;

		case META_INITED:
			this->meta_list.del_cur();
			delete meta;
			break;

		case META_UNINIT:
			ret = META_UNINIT;
			this->member->meta_map[meta->get_topic()] = META_DOING;
			break;
		}
	}

	return ret;
}

void ComplexKafkaTask::set_meta_status(enum MetaStatus status)
{
	this->member->meta_list.rewind();
	KafkaMeta *meta;
	while ((meta = this->member->meta_list.get_next()) != NULL)
		this->member->meta_map[meta->get_topic()] = status;
}

void ComplexKafkaTask::dispatch()
{
	__WFKafkaTask *task;
	WFCounterTask *counter;
	ParallelWork *parallel;

	if (this->finish)
	{
		this->subtask_done();
		return;
	}

	if (!this->query.empty())
		this->parse_query();

	this->generate_info();

	this->member->mutex.lock();

	if (this->member->status & KAFKA_CGROUP_DOING)
	{
		char name[64];
		snprintf(name, 64, "%p.cgroup", this->member);
		counter = WFTaskFactory::create_counter_task(name, 1, nullptr);
		series_of(this)->push_front(this);
		series_of(this)->push_front(counter);
		this->member->mutex.unlock();
		this->subtask_done();
		return;
	}
	else if ((this->api_type == Kafka_Fetch || this->api_type == Kafka_OffsetCommit) &&
			 (this->member->status & KAFKA_CGROUP_INIT))
	{
		task = __WFKafkaTaskFactory::create_kafka_task(this->url,
													   this->retry_max,
													   kafka_cgroup_callback);
		task->user_data = this;
		task->get_req()->set_config(this->config);
		task->get_req()->set_api_type(Kafka_FindCoordinator);
		task->get_req()->set_cgroup(this->member->cgroup);
		task->get_req()->set_meta_list(this->meta_list);
		series_of(this)->push_front(this);
		series_of(this)->push_front(task);
		this->member->status |= KAFKA_CGROUP_DOING;
		this->member->mutex.unlock();
		this->subtask_done();
		return;
	}

	char name[64];
	switch(this->get_meta_status())
	{
	case META_UNINIT:
		task = __WFKafkaTaskFactory::create_kafka_task(this->url,
													   this->retry_max,
													   kafka_meta_callback);
		task->user_data = this;
		task->get_req()->set_config(this->config);
		task->get_req()->set_api_type(Kafka_Metadata);
		task->get_req()->set_meta_list(this->meta_list);
		series_of(this)->push_front(this);
		series_of(this)->push_front(task);
		this->member->mutex.unlock();
		this->subtask_done();
		return;

	case META_DOING:
		snprintf(name, 64, "%p.meta", this->member);
		counter = WFTaskFactory::create_counter_task(name, 1, nullptr);
		series_of(this)->push_front(this);
		series_of(this)->push_front(counter);
		this->member->mutex.unlock();
		this->subtask_done();
		return;

	case META_INITED:
		break;
	}

	if (arrange_toppar(this->api_type) < 0)
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_KAFKA_ARRANGE_FAILED;
		this->finish = true;
		this->member->mutex.unlock();
		this->subtask_done();
		return;
	}

	SeriesWork *series;
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
			auto cb = std::bind(&ComplexKafkaTask::kafka_move_task_callback, this,
								std::placeholders::_1);
			KafkaBroker *broker = get_broker(v.first);
			if (broker->is_to_addr())
			{
				const struct sockaddr *addr;
				socklen_t socklen;
				broker->get_broker_addr(&addr, &socklen);

				task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen,
															   this->get_userinfo(),
															   this->retry_max,
															   nullptr);
			}
			else
			{
				task = __WFKafkaTaskFactory::create_kafka_task(broker->get_host(),
															   broker->get_port(),
															   this->get_userinfo(),
															   this->retry_max,
															   nullptr);
			}

			task->get_req()->set_config(this->config);
			task->get_req()->set_toppar_list(v.second);
			task->get_req()->set_broker(*broker);
			task->get_req()->set_api_type(Kafka_Produce);
			task->user_data = (void *)parallel->size();
			KafkaComplexTask *ctask = static_cast<KafkaComplexTask *>(task);
			*ctask->get_mutable_ctx() = cb;
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
			auto cb = std::bind(&ComplexKafkaTask::kafka_move_task_callback, this,
								std::placeholders::_1);
			KafkaBroker *broker = get_broker(v.first);
			if (broker->is_to_addr())
			{
				const struct sockaddr *addr;
				socklen_t socklen;
				broker->get_broker_addr(&addr, &socklen);

				task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen,
															   this->get_userinfo(),
															   this->retry_max,
															   nullptr);
			}
			else
			{
				task = __WFKafkaTaskFactory::create_kafka_task(broker->get_host(),
															   broker->get_port(),
															   this->get_userinfo(),
															   this->retry_max,
															   nullptr);
			}

			task->get_req()->set_config(this->config);
			task->get_req()->set_toppar_list(v.second);
			task->get_req()->set_broker(*broker);
			task->get_req()->set_api_type(Kafka_Fetch);
			task->user_data = (void *)parallel->size();
			KafkaComplexTask *ctask = static_cast<KafkaComplexTask *>(task);
			*ctask->get_mutable_ctx() = cb;
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
		if (!this->member->cgroup.get_group())
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_KAFKA_COMMIT_FAILED;
			this->finish = true;
			break;
		}
		else
		{
			this->result.create(1);
			KafkaBroker *coordinator = this->member->cgroup.get_coordinator();

			const struct sockaddr *addr;
			socklen_t socklen;
			coordinator->get_broker_addr(&addr, &socklen);

			task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen,
														   this->get_userinfo(),
														   this->retry_max,
														   kafka_offsetcommit_callback);
			task->user_data = this;
			task->get_req()->set_config(this->config);
			task->get_req()->set_cgroup(this->member->cgroup);
			task->get_req()->set_broker(*coordinator);
			task->get_req()->set_toppar_list(this->toppar_list);
			task->get_req()->set_api_type(this->api_type);
			series_of(this)->push_front(this);
			series_of(this)->push_front(task);
			break;
		}

	case Kafka_LeaveGroup:
		if (!this->member->cgroup.get_group())
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_KAFKA_LEAVEGROUP_FAILED;
			this->finish = true;
			break;
		}
		else
		{
			KafkaBroker *coordinator = this->member->cgroup.get_coordinator();

			const struct sockaddr *addr;
			socklen_t socklen;
			coordinator->get_broker_addr(&addr, &socklen);

			if (coordinator->is_to_addr())
			{
				task = __WFKafkaTaskFactory::create_kafka_task(addr,
															   socklen,
															   this->get_userinfo(),
															   0,
															   kafka_leavegroup_callback);
				task->user_data = this;
				task->get_req()->set_config(this->config);
				task->get_req()->set_api_type(Kafka_LeaveGroup);
				task->get_req()->set_broker(*coordinator);
				task->get_req()->set_cgroup(this->member->cgroup);
				series_of(this)->push_front(this);
				series_of(this)->push_front(task);
			}
		}
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
			auto cb = std::bind(&ComplexKafkaTask::kafka_move_task_callback, this,
								std::placeholders::_1);
			KafkaBroker *broker = get_broker(v.first);
			if (broker->is_to_addr())
			{
				const struct sockaddr *addr;
				socklen_t socklen;
				broker->get_broker_addr(&addr, &socklen);

				task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen,
															   this->get_userinfo(),
															   this->retry_max,
															   nullptr);
			}
			else
			{
				task = __WFKafkaTaskFactory::create_kafka_task(broker->get_host(),
															   broker->get_port(),
															   this->get_userinfo(),
															   this->retry_max,
															   nullptr);
			}

			task->get_req()->set_config(this->config);
			task->get_req()->set_toppar_list(v.second);
			task->get_req()->set_broker(*broker);
			task->get_req()->set_api_type(Kafka_ListOffsets);
			task->user_data = (void *)parallel->size();
			KafkaComplexTask *ctask = static_cast<KafkaComplexTask *>(task);
			*ctask->get_mutable_ctx() = cb;
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

	this->member->mutex.unlock();
	this->subtask_done();
}

bool ComplexKafkaTask::add_topic(const std::string& topic)
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
		this->member->meta_map[topic] = META_UNINIT;

		KafkaMeta tmp;
		if (!tmp.set_topic(topic))
		{
			this->member->mutex.unlock();
			return false;
		}

		this->meta_list.add_item(tmp);
		this->member->meta_list.add_item(tmp);

		if (this->member->cgroup.get_group())
		{
			this->member->status |= KAFKA_CGROUP_INIT;
			this->member->status &= (~(KAFKA_CGROUP_DONE|KAFKA_CGROUP_DOING));
		}
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

bool ComplexKafkaTask::add_toppar(const KafkaToppar& toppar)
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
		{
			this->member->status |= KAFKA_CGROUP_INIT;
			this->member->status &= (~(KAFKA_CGROUP_DONE|KAFKA_CGROUP_DOING));
		}
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

bool ComplexKafkaTask::add_produce_record(const std::string& topic,
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

int ComplexKafkaTask::arrange_toppar(int api_type)
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

bool ComplexKafkaTask::add_offset_toppar(const protocol::KafkaToppar& toppar)
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

int ComplexKafkaTask::arrange_offset()
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

int ComplexKafkaTask::arrange_commit()
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

int ComplexKafkaTask::arrange_fetch()
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

int ComplexKafkaTask::arrange_produce()
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
	std::string::size_type pos = broker.find(',');
	std::string::size_type ppos = 0;

	if (pos == std::string::npos)
	{
		std::string host = broker;
		if (host.find("kafka://") != 0)
			host = "kafka://" + host;
		broker_hosts.emplace_back(host);
	}
	else
	{
		do
		{
			std::string host = broker.substr(ppos, pos - ppos);
			if (host.find("kafka://") != 0)
				host = "kafka://" + host;
			broker_hosts.emplace_back(host);

			ppos = pos + 1;
			pos = broker.find(',', ppos);
		} while (pos != std::string::npos);

		std::string host = broker.substr(ppos, pos - ppos);
		if (host.find("kafka://") != 0)
			host = "kafka://" + host;
		broker_hosts.emplace_back(host);
	}

	this->member = new KafkaMember;
	this->member->broker_hosts = std::move(broker_hosts);
	return 0;
}

int WFKafkaClient::init(const std::string& broker, const std::string& group)
{
	this->init(broker);
	this->member->cgroup.set_group(group);
	this->member->status |= KAFKA_CGROUP_INIT | KAFKA_HEARTBEAT_INIT;
	return 0;
}

int WFKafkaClient::deinit()
{
	this->member->mutex.lock();
	this->member->status |= KAFKA_DEINIT;
	this->member->mutex.unlock();
	this->member->decref();
	return 0;
}

WFKafkaTask *WFKafkaClient::create_kafka_task(const std::string& query,
											  int retry_max,
											  kafka_callback_t cb)
{
	WFKafkaTask *task = new ComplexKafkaTask(query, retry_max, std::move(cb),
											 this);
	return task;
}

WFKafkaTask *WFKafkaClient::create_kafka_task(int retry_max,
											  kafka_callback_t cb)
{
	WFKafkaTask *task = new ComplexKafkaTask("", retry_max, std::move(cb), this);
	return task;
}

WFKafkaTask *WFKafkaClient::create_leavegroup_task(int retry_max,
												   kafka_callback_t cb)
{
	WFKafkaTask *task = new ComplexKafkaTask("api=leavegroup", retry_max,
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

