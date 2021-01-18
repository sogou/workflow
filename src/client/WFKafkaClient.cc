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
#include "WFKafkaClient.h"

static size_t KAFKA_HEARTBEAT_TIMEOUT = 3 * 1000;

#define KAFKA_META_INIT			(1<<0)
#define KAFKA_META_DOING		(1<<1)
#define KAFKA_META_DONE			(1<<2)
#define KAFKA_CGROUP_INIT		(1<<3)
#define KAFKA_CGROUP_DOING		(1<<4)
#define KAFKA_CGROUP_DONE		(1<<5)
#define KAFKA_HEARTBEAT_INIT	(1<<6)
#define KAFKA_HEARTBEAT_DOING	(1<<7)
#define KAFKA_HEARTBEAT_DONE	(1<<8)

using namespace protocol;

using KafkaComplexTask = WFComplexClientTask<KafkaRequest, KafkaResponse,
											 __kafka_callback_t>;

class KafkaLockStatus
{
public:
	KafkaLockStatus()
	{
		this->status = new int(0);
		this->cnt = new std::atomic<int>(1);
		this->mutex = new std::mutex;
		this->ref = new std::atomic<int>(1);
	}

	~KafkaLockStatus()
	{
		if (--*this->ref == 0)
		{
			delete this->ref;
			delete this->cnt;
			delete this->status;
			delete this->mutex;
		}
	}

	KafkaLockStatus(const KafkaLockStatus& copy)
	{
		this->~KafkaLockStatus();
		this->ref = copy.ref;
		++*this->ref;
		this->cnt = copy.cnt;
		this->mutex = copy.mutex;
		this->status = copy.status;
	}

	KafkaLockStatus& operator= (const KafkaLockStatus& copy)
	{
		this->~KafkaLockStatus();
		this->ref = copy.ref;
		++*this->ref;
		this->cnt = copy.cnt;
		this->mutex = copy.mutex;
		this->status = copy.status;
		return *this;
	}

	std::mutex *get_mutex() { return this->mutex; }
	int *get_status() { return this->status; }

	std::atomic<int> *get_cnt()
	{
		return this->cnt;
	}

	void add_cnt()
	{
		(*this->cnt)++;
	}

	void dec_cnt()
	{
		(*this->cnt)--;
	}

private:
	std::mutex *mutex;
	int *status;
	std::atomic<int> *cnt;
	std::atomic<int> *ref;
};

class KafkaMember
{
public:
	KafkaMember()
	{
		this->ref = new std::atomic<int>(1);
		this->broker_hosts = new std::vector<ParsedURI>;
		this->cgroup = new KafkaCgroup;
		this->meta_list = new KafkaMetaList;
		this->broker_list = new KafkaBrokerList;
		this->lock_status = new KafkaLockStatus;
	}

	~KafkaMember()
	{
		if (--*this->ref == 0)
		{
			delete this->ref;
			delete this->broker_hosts;
			delete this->cgroup;
			delete this->meta_list;
			delete this->broker_list;
			delete this->lock_status;
		}
	}

	std::vector<ParsedURI> *broker_hosts;
	KafkaCgroup *cgroup;
	KafkaMetaList *meta_list;
	KafkaBrokerList *broker_list;
	KafkaLockStatus *lock_status;

private:
	std::atomic<int> *ref;
};

class KafkaHeartbeat
{
public:
	void set_cgroup(const KafkaCgroup& cgroup)
	{
		this->cgroup = cgroup;
	}

	KafkaCgroup *get_cgroup()
	{
		return &this->cgroup;
	}

	void set_meta_list(const KafkaMetaList& meta_list)
	{
		this->meta_list = meta_list;
	}

	KafkaMetaList *get_meta_list()
	{
		return &this->meta_list;
	}

	void set_config(const KafkaConfig& config)
	{
		this->config = config;
	}

	KafkaConfig *get_config()
	{
		return &this->config;
	}

	void set_uri(const ParsedURI& uri)
	{
		this->uri = uri;
	}

	ParsedURI *get_uri()
	{
		return &this->uri;
	}

	void set_lock_status(const KafkaLockStatus& lock_status)
	{
		this->lock_status = lock_status;
	}

	KafkaLockStatus *get_lock_status()
	{
		return &this->lock_status;
	}

	void set_client(WFKafkaClient *client)
	{
		this->client = client;
	}

	WFKafkaClient *get_client()
	{
		return this->client;
	}

private:
	KafkaCgroup cgroup;
	KafkaMetaList meta_list;
	KafkaConfig config;
	ParsedURI uri;
	KafkaLockStatus lock_status;
	WFKafkaClient *client;
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
		this->client = client;
		this->lock_status = *client->member->lock_status;
		this->lock_status.add_cnt();
		this->cgroup = *client->member->cgroup;
		this->client_meta_list = *client->member->meta_list;
		this->client_broker_list = *client->member->broker_list;
		this->query = query;

		if (!client->member->broker_hosts->empty())
		{
			int rpos = rand() % client->member->broker_hosts->size();
			this->uri = client->member->broker_hosts->at(rpos);
		}
	}

	virtual ~ComplexKafkaTask()
	{
		this->lock_status.get_cnt()->fetch_sub(1);
	}

	ParsedURI *get_uri() { return &this->uri; }

protected:
	virtual bool add_topic(const std::string& topic);

	virtual bool add_toppar(const KafkaToppar& toppar);

	virtual bool add_produce_record(const std::string& topic, int partition,
									KafkaRecord record);

	virtual void dispatch();

	virtual void parse_query();

private:
	static void kafka_merge_meta_list(KafkaMetaList* dst,
									  KafkaMetaList* src);

	static void kafka_merge_broker_list(KafkaBrokerList *dst,
										KafkaBrokerList *src);

	static void kafka_meta_callback(__WFKafkaTask *task);

	static void kafka_cgroup_callback(__WFKafkaTask *task);

	static void kafka_offsetcommit_callback(__WFKafkaTask *task);

	static void kafka_parallel_callback(const ParallelWork *pwork);

	static void kafka_timer_callback(WFTimerTask *task);

	static void kafka_heartbeat_callback(__WFKafkaTask *task);

	static void kafka_leavegroup_callback(__WFKafkaTask *task);

	static void kafka_rebalance_proc(KafkaHeartbeat *t);

	static void kafka_rebalance_callback(__WFKafkaTask *task);

	void kafka_move_task_callback(__WFKafkaTask *task);

	void kafka_process_toppar_offset(KafkaToppar *task_toppar);

	int arrange_produce();

	int arrange_fetch();

	int arrange_commit();

	KafkaBroker *get_broker(int node_id);

	int get_node_id(const KafkaToppar *toppar);

private:
	WFKafkaClient *client;
	KafkaLockStatus lock_status;
	KafkaMetaList client_meta_list;
	KafkaBrokerList client_broker_list;
	KafkaCgroup cgroup;
	std::map<int, KafkaTopparList> toppar_list_map;
	ParsedURI uri;
	std::string query;

	friend class WFKafkaClient;
};

KafkaBroker *ComplexKafkaTask::get_broker(int node_id)
{
	bool flag = false;
	this->client_broker_list.rewind();
	KafkaBroker *broker;
	while ((broker = this->client_broker_list.get_next()) != NULL)
	{
		if (broker->get_node_id() == node_id)
		{
			flag = true;
			break;
		}
	}

	if (flag)
		return broker;
	else
		return NULL;
}

int ComplexKafkaTask::get_node_id(const KafkaToppar *toppar)
{
	bool flag = false;
	this->client_meta_list.rewind();
	KafkaMeta *meta;
	while ((meta = this->client_meta_list.get_next()) != NULL)
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
	if (task->get_state() == 0)
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
	KafkaHeartbeat *t = (KafkaHeartbeat *)task->user_data;

	if (task->get_state() == WFT_STATE_ABORTED ||
		t->get_lock_status()->get_cnt()->fetch_add(0) == 1)
	{
		delete t;
		return;
	}

	t->get_lock_status()->get_mutex()->lock();

	if (task->get_state() == 0)
	{
		*t->get_lock_status()->get_status() |= KAFKA_CGROUP_DONE;
		*t->get_lock_status()->get_status() &= (~(KAFKA_CGROUP_INIT|KAFKA_CGROUP_DOING));
		t->get_cgroup()->set_coordinator(task->get_resp()->get_broker());

		if (*t->get_lock_status()->get_status() & KAFKA_HEARTBEAT_INIT)
		{
			__WFKafkaTask *kafka_task;
			KafkaBroker *coordinator = t->get_cgroup()->get_coordinator();

			const struct sockaddr *addr;
			socklen_t socklen;
			coordinator->get_broker_addr(&addr, &socklen);

			kafka_task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen,
												  0, kafka_heartbeat_callback);
			kafka_task->user_data = t;
			kafka_task->get_req()->set_api(Kafka_Heartbeat);
			kafka_task->get_req()->set_cgroup(*t->get_cgroup());
			kafka_task->get_req()->set_broker(*coordinator);
			kafka_task->start();
			*t->get_lock_status()->get_status() |= KAFKA_HEARTBEAT_DOING;
			*t->get_lock_status()->get_status() &= ~KAFKA_HEARTBEAT_INIT;
		}

		t->get_lock_status()->get_mutex()->unlock();

		char name[64];
		snprintf(name, 64, "%p.cgroup", t->get_client());
		WFTaskFactory::count_by_name(name, (unsigned int)-1);
	}
	else
		kafka_rebalance_proc(t);
}

void ComplexKafkaTask::kafka_rebalance_proc(KafkaHeartbeat *t)
{
	if (t->get_lock_status()->get_cnt()->fetch_add(0) == 1)
	{
		t->get_lock_status()->get_mutex()->unlock();
		delete t;
		return;
	}

	__WFKafkaTask *task;
	task = __WFKafkaTaskFactory::create_kafka_task(*t->get_uri(), 0,
												   kafka_rebalance_callback);
	task->user_data = t;
	task->get_req()->set_config(*t->get_config());
	task->get_req()->set_api(Kafka_FindCoordinator);
	task->get_req()->set_cgroup(*t->get_cgroup());
	task->get_req()->set_meta_list(*t->get_meta_list());

	*t->get_lock_status()->get_status() |= KAFKA_CGROUP_DOING;
	*t->get_lock_status()->get_status() &= (~(KAFKA_CGROUP_DONE|KAFKA_CGROUP_INIT));

	*t->get_lock_status()->get_status() |= KAFKA_HEARTBEAT_INIT;
	*t->get_lock_status()->get_status() &= (~(KAFKA_HEARTBEAT_DONE|KAFKA_HEARTBEAT_DOING));

	t->get_lock_status()->get_mutex()->unlock();

	task->start();
}

void ComplexKafkaTask::kafka_heartbeat_callback(__WFKafkaTask *task)
{
	KafkaHeartbeat *t = (KafkaHeartbeat *)task->user_data;

	if (task->get_state() == WFT_STATE_ABORTED ||
		t->get_lock_status()->get_cnt()->fetch_add(0) == 1)
	{
		delete t;
		return;
	}

	t->get_lock_status()->get_mutex()->lock();

	if (t->get_cgroup()->get_error() != 0)
	{
		kafka_rebalance_proc(t);
		return;
	}
	else
	{
		*t->get_lock_status()->get_status() |= KAFKA_HEARTBEAT_DONE;
		*t->get_lock_status()->get_status() &= ~KAFKA_HEARTBEAT_DOING;
		WFTimerTask *timer_task;
		timer_task = WFTaskFactory::create_timer_task(KAFKA_HEARTBEAT_TIMEOUT,
													  kafka_timer_callback);
		timer_task->user_data = t;
		timer_task->start();
	}

	t->get_lock_status()->get_mutex()->unlock();
}

void ComplexKafkaTask::kafka_timer_callback(WFTimerTask *task)
{
	KafkaHeartbeat *t = (KafkaHeartbeat *)task->user_data;

	if (task->get_state() == WFT_STATE_ABORTED ||
		t->get_lock_status()->get_cnt()->fetch_add(0) == 1)
	{
		delete t;
		return;
	}

	t->get_lock_status()->get_mutex()->lock();

	*t->get_lock_status()->get_status() |= KAFKA_HEARTBEAT_DOING;
	__WFKafkaTask *kafka_task;
	KafkaBroker *coordinator = t->get_cgroup()->get_coordinator();

	const struct sockaddr *addr;
	socklen_t socklen;
	coordinator->get_broker_addr(&addr, &socklen);

	kafka_task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen, 0,
														 kafka_heartbeat_callback);

	kafka_task->user_data = t;
	kafka_task->get_req()->set_api(Kafka_Heartbeat);
	kafka_task->get_req()->set_cgroup(*t->get_cgroup());
	kafka_task->get_req()->set_broker(*coordinator);
	kafka_task->start();

	t->get_lock_status()->get_mutex()->unlock();
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

void ComplexKafkaTask::kafka_merge_broker_list(KafkaBrokerList *dst,
											   KafkaBrokerList *src)
{
	src->rewind();
	KafkaBroker *src_broker;
	while ((src_broker = src->get_next()) != NULL)
	{
		dst->rewind();

		KafkaBroker *dst_broker;
		while ((dst_broker = dst->get_next()) != NULL)
		{
			if (dst_broker->get_node_id() == src_broker->get_node_id())
			{
				dst->del_cur();
				delete dst_broker;
				break;
			}
		}

		dst->add_item(std::move(*src_broker));
		src->del_cur();
		delete src_broker;
	}
}

void ComplexKafkaTask::kafka_meta_callback(__WFKafkaTask *task)
{
	ComplexKafkaTask *t = (ComplexKafkaTask *)task->user_data;
	t->lock_status.get_mutex()->lock();
	if (task->get_state() == WFT_STATE_SUCCESS)
	{
		kafka_merge_meta_list(&t->client_meta_list,
							  task->get_resp()->get_meta_list());
		kafka_merge_broker_list(&t->client_broker_list,
								task->get_resp()->get_broker_list());

		*t->lock_status.get_status() |= KAFKA_META_DONE;
		*t->lock_status.get_status() &= (~(KAFKA_META_INIT|KAFKA_META_DOING));

		t->state = WFT_STATE_SUCCESS;
		t->error = 0;
	}
	else
	{
		*t->lock_status.get_status() |= KAFKA_META_INIT;
		*t->lock_status.get_status() &= (~(KAFKA_META_DONE|KAFKA_META_DOING));

		t->state = WFT_STATE_TASK_ERROR;
		t->error = WFT_ERR_KAFKA_META_FAILED;
		t->finish = true;
	}

	char name[64];
	snprintf(name, 64, "%p.meta", t->client);
	WFTaskFactory::count_by_name(name, (unsigned int)-1);
	t->lock_status.get_mutex()->unlock();
}

void ComplexKafkaTask::kafka_cgroup_callback(__WFKafkaTask *task)
{
	ComplexKafkaTask *t = (ComplexKafkaTask *)task->user_data;
	t->lock_status.get_mutex()->lock();
	if (task->get_state() == 0)
	{
		*t->lock_status.get_status() |= KAFKA_CGROUP_DONE;
		*t->lock_status.get_status() &= (~(KAFKA_CGROUP_INIT|KAFKA_CGROUP_DOING));
		t->cgroup.set_coordinator(task->get_resp()->get_broker());

		if (*t->lock_status.get_status() & KAFKA_HEARTBEAT_INIT)
		{
			KafkaHeartbeat *hb = new KafkaHeartbeat;
			hb->set_cgroup(t->cgroup);
			hb->set_meta_list(t->client_meta_list);
			hb->set_config(t->config);
			hb->set_uri(t->uri);
			t->lock_status.add_cnt();
			hb->set_lock_status(t->lock_status);
			hb->set_client(t->client);
			__WFKafkaTask *kafka_task;
			KafkaBroker *coordinator = t->cgroup.get_coordinator();

			const struct sockaddr *addr;
			socklen_t socklen;
			coordinator->get_broker_addr(&addr, &socklen);

			kafka_task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen,
																 t->retry_max,
																 kafka_heartbeat_callback);
			kafka_task->user_data = hb;
			kafka_task->get_req()->set_api(Kafka_Heartbeat);
			kafka_task->get_req()->set_cgroup(t->cgroup);
			kafka_task->get_req()->set_broker(*coordinator);
			kafka_task->start();
			*t->lock_status.get_status() |= KAFKA_HEARTBEAT_DOING;
			*t->lock_status.get_status() &= ~KAFKA_HEARTBEAT_INIT;
		}

		t->state = WFT_STATE_SUCCESS;
		t->error = 0;
	}
	else
	{
		*t->lock_status.get_status() |= KAFKA_CGROUP_INIT;
		*t->lock_status.get_status() &= (~(KAFKA_CGROUP_DONE|KAFKA_CGROUP_DOING));

		t->state = WFT_STATE_TASK_ERROR;
		t->error = WFT_ERR_KAFKA_CGROUP_FAILED;
		t->finish = true;
	}

	char name[64];
	snprintf(name, 64, "%p.cgroup", t->client);
	WFTaskFactory::count_by_name(name, (unsigned int)-1);
	t->lock_status.get_mutex()->unlock();
}

void ComplexKafkaTask::kafka_parallel_callback(const ParallelWork *pwork)
{
	ComplexKafkaTask *t = (ComplexKafkaTask *)pwork->get_context();
	t->finish = true;
	t->state = WFT_STATE_SUCCESS;
	t->error = 0;

	std::pair<int, int> *state_error;

	for (size_t i = 0; i < pwork->size(); i++)
	{
		state_error = (std::pair<int, int> *)pwork->series_at(i)->get_context();
		if (state_error->first != WFT_STATE_SUCCESS)
		{
			t->state = state_error->first;
			t->error = state_error->second;
		}

		delete state_error;
	}
}

void ComplexKafkaTask::kafka_process_toppar_offset(KafkaToppar *task_toppar)
{
	KafkaToppar *toppar;

	struct list_head *pos;
	list_for_each(pos, this->cgroup.get_assigned_toppar_list())
	{
		toppar = this->cgroup.get_assigned_toppar_by_pos(pos);
		if (strcmp(toppar->get_topic(), task_toppar->get_topic()) == 0 &&
			toppar->get_partition() == task_toppar->get_partition())
		{
			if (task_toppar->get_error() == KAFKA_OFFSET_OUT_OF_RANGE &&
				task_toppar->get_offset() < task_toppar->get_low_watermark())
			{
				toppar->set_offset(-1);
			}
			else if (task_toppar->get_error() == KAFKA_NONE)
			{
				toppar->set_offset(task_toppar->get_offset() + 1);
			}
			else
				toppar->set_offset(task_toppar->get_offset());

			if (task_toppar->get_low_watermark() > 0)
				toppar->set_low_watermark(task_toppar->get_low_watermark());

			break;
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

	if (task->get_resp()->get_api() == Kafka_Fetch)
	{
		toppar_list->rewind();
		KafkaToppar *task_toppar;

		while ((task_toppar = toppar_list->get_next()) != NULL)
			kafka_process_toppar_offset(task_toppar);
	}

	long idx = (long)(task->user_data);
	this->result.set_resp(std::move(*task->get_resp()), idx);
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
			}
		}
		else if (strcasecmp(kv.first.c_str(), "topic") == 0)
		{
			for (auto& v : kv.second)
				this->add_topic(v);
		}
	}
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
		parse_query();

	this->lock_status.get_mutex()->lock();

	if (*this->lock_status.get_status() & KAFKA_META_INIT)
	{
		task = __WFKafkaTaskFactory::create_kafka_task(this->uri,
													   this->retry_max,
													   kafka_meta_callback);
		task->user_data = this;
		task->get_req()->set_config(this->config);
		task->get_req()->set_api(Kafka_Metadata);
		task->get_req()->set_meta_list(this->meta_list);
		series_of(this)->push_front(this);
		series_of(this)->push_front(task);
		*this->lock_status.get_status() |= KAFKA_META_DOING;
		this->lock_status.get_mutex()->unlock();
		this->subtask_done();
		return;
	}
	else if (*this->lock_status.get_status() & KAFKA_META_DOING)
	{
		char name[64];
		snprintf(name, 64, "%p.meta", this->client);
		counter = WFTaskFactory::create_counter_task(name, 1, nullptr);
		series_of(this)->push_front(this);
		series_of(this)->push_front(counter);
		this->lock_status.get_mutex()->unlock();
		this->subtask_done();
		return;
	}

	if ((this->api_type == Kafka_Fetch || this->api_type == Kafka_OffsetCommit) &&
		(*this->lock_status.get_status() & KAFKA_CGROUP_INIT))
	{
		task = __WFKafkaTaskFactory::create_kafka_task(this->uri,
													   this->retry_max,
													   kafka_cgroup_callback);
		task->user_data = this;
		task->get_req()->set_config(this->config);
		task->get_req()->set_api(Kafka_FindCoordinator);
		task->get_req()->set_cgroup(this->cgroup);
		task->get_req()->set_meta_list(this->client_meta_list);
		series_of(this)->push_front(this);
		series_of(this)->push_front(task);
		*this->lock_status.get_status() |= KAFKA_CGROUP_DOING;
		this->lock_status.get_mutex()->unlock();
		this->subtask_done();
		return;
	}
	else if (*this->lock_status.get_status() & KAFKA_CGROUP_DOING)
	{
		char name[64];
		snprintf(name, 64, "%p.cgroup", this->client);
		counter = WFTaskFactory::create_counter_task(name, 1, nullptr);
		series_of(this)->push_front(this);
		series_of(this)->push_front(counter);
		this->lock_status.get_mutex()->unlock();
		this->subtask_done();
		return;
	}

	SeriesWork *series;
	switch(this->api_type)
	{
	case Kafka_Produce:
		if (arrange_produce() < 0 ||
			this->toppar_list_map.size() == 0)
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
															   this->retry_max,
															   nullptr);
			}
			else
			{
				task = __WFKafkaTaskFactory::create_kafka_task(broker->get_host(),
															   broker->get_port(),
															   this->retry_max,
															   nullptr);
			}

			task->get_req()->set_config(this->config);
			task->get_req()->set_toppar_list(v.second);
			task->get_req()->set_broker(*broker);
			task->get_req()->set_api(Kafka_Produce);
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
		if (arrange_fetch() < 0 ||
			this->toppar_list_map.size() == 0)
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
															   this->retry_max,
															   nullptr);
			}
			else
			{
				task = __WFKafkaTaskFactory::create_kafka_task(broker->get_host(),
															   broker->get_port(),
															   this->retry_max,
															   nullptr);
			}

			task->get_req()->set_config(this->config);
			task->get_req()->set_toppar_list(v.second);
			task->get_req()->set_broker(*broker);
			task->get_req()->set_api(Kafka_Fetch);
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
		if (!this->cgroup.get_group() || arrange_commit() < 0)
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_KAFKA_COMMIT_FAILED;
			this->finish = true;
			break;
		}
		else
		{
			this->result.create(1);
			KafkaBroker *coordinator = this->cgroup.get_coordinator();

			const struct sockaddr *addr;
			socklen_t socklen;
			coordinator->get_broker_addr(&addr, &socklen);

			task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen,
														   this->retry_max,
														   kafka_offsetcommit_callback);
			task->user_data = this;
			task->get_req()->set_config(this->config);
			task->get_req()->set_cgroup(this->cgroup);
			task->get_req()->set_broker(*coordinator);
			task->get_req()->set_toppar_list(this->toppar_list);
			task->get_req()->set_api(this->api_type);
			series_of(this)->push_front(this);
			series_of(this)->push_front(task);
			break;
		}

	case Kafka_LeaveGroup:
		if (!this->cgroup.get_group())
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_KAFKA_LEAVEGROUP_FAILED;
			this->finish = true;
			break;
		}
		else
		{
			KafkaBroker *coordinator = this->cgroup.get_coordinator();

			const struct sockaddr *addr;
			socklen_t socklen;
			coordinator->get_broker_addr(&addr, &socklen);

			if (coordinator->is_to_addr())
			{
				task = __WFKafkaTaskFactory::create_kafka_task(addr, socklen,
											   0, kafka_leavegroup_callback);
				task->user_data = this;
				task->get_req()->set_api(Kafka_LeaveGroup);
				task->get_req()->set_broker(*coordinator);
				task->get_req()->set_cgroup(this->cgroup);
				series_of(this)->push_front(this);
				series_of(this)->push_front(task);
			}
		}
		break;

	default:
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_KAFKA_API_UNKNOWN;
		this->finish = true;
		break;
	}

	this->lock_status.get_mutex()->unlock();
	this->subtask_done();
}

bool ComplexKafkaTask::add_topic(const std::string& topic)
{
	bool flag = false;
	this->lock_status.get_mutex()->lock();

	this->client_meta_list.rewind();
	KafkaMeta *meta;
	while ((meta = this->client_meta_list.get_next()) != NULL)
	{
		if (meta->get_topic() == topic)
		{
			flag = true;
			break;
		}
	}

	if (!flag)
	{
		KafkaMeta tmp;
		if (!tmp.set_topic(topic))
		{
			this->lock_status.get_mutex()->unlock();
			return false;
		}

		this->meta_list.add_item(tmp);
		this->client_meta_list.add_item(tmp);
		*this->lock_status.get_status() |= KAFKA_META_INIT;
		*this->lock_status.get_status() &= (~(KAFKA_META_DONE|KAFKA_META_DOING));

		if (this->cgroup.get_group())
		{
			*this->lock_status.get_status() |= KAFKA_CGROUP_INIT;
			*this->lock_status.get_status() &= (~(KAFKA_CGROUP_DONE|KAFKA_CGROUP_DOING));
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
				this->lock_status.get_mutex()->unlock();
				return true;
			}
		}

		this->meta_list.add_item(*meta);
	}

	this->lock_status.get_mutex()->unlock();

	return true;
}

bool ComplexKafkaTask::add_toppar(const KafkaToppar& toppar)
{
	if (this->cgroup.get_group())
		return false;

	bool flag = false;
	this->lock_status.get_mutex()->lock();

	this->client_meta_list.rewind();
	KafkaMeta *meta;
	while ((meta = this->client_meta_list.get_next()) != NULL)
	{
		if (strcmp(meta->get_topic(), toppar.get_topic()) == 0)
		{
			flag = true;
			break;
		}
	}

	if (!flag)
	{
		KafkaMeta tmp;
		if (!tmp.set_topic(toppar.get_topic()))
		{
			this->lock_status.get_mutex()->unlock();
			return false;
		}

		KafkaToppar new_toppar;
		new_toppar.set_topic_partition(toppar.get_topic(), toppar.get_partition());
		new_toppar.set_offset(toppar.get_offset());
		this->toppar_list.add_item(new_toppar);

		this->meta_list.add_item(tmp);
		this->client_meta_list.add_item(tmp);
		*this->lock_status.get_status() |= KAFKA_META_INIT;
		*this->lock_status.get_status() &= (~(KAFKA_META_DONE|KAFKA_META_DOING));

		if (this->cgroup.get_group())
		{
			*this->lock_status.get_status() |= KAFKA_CGROUP_INIT;
			*this->lock_status.get_status() &= (~(KAFKA_CGROUP_DONE|KAFKA_CGROUP_DOING));
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
				this->lock_status.get_mutex()->unlock();
				return true;
			}
		}

		KafkaToppar new_toppar;
		new_toppar.set_topic_partition(toppar.get_topic(), toppar.get_partition());
		new_toppar.set_offset(toppar.get_offset());
		this->toppar_list.add_item(new_toppar);

		this->meta_list.add_item(*meta);
	}

	this->lock_status.get_mutex()->unlock();

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
	KafkaMeta *meta;
	while ((meta = this->meta_list.get_next()) != NULL)
	{
		if (this->cgroup.get_group())
		{
			this->cgroup.assigned_toppar_rewind();
			KafkaToppar *toppar;
			while ((toppar = this->cgroup.get_assigned_toppar_next()) != NULL)
			{
				if (strcmp(toppar->get_topic(), meta->get_topic()) == 0)
				{
					int node_id = get_node_id(toppar);
					if (node_id < 0)
					{
						this->lock_status.get_mutex()->unlock();
						return -1;
					}

					if (this->toppar_list_map.find(node_id) == this->toppar_list_map.end())
						this->toppar_list_map[node_id] = (KafkaTopparList());

					KafkaToppar new_toppar;
					new_toppar.set_topic_partition(toppar->get_topic(), toppar->get_partition());
					new_toppar.set_offset(toppar->get_offset());
					new_toppar.set_low_watermark(toppar->get_low_watermark());
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
				if (strcmp(toppar->get_topic(), meta->get_topic()) == 0)
				{
					int node_id = get_node_id(toppar);
					if (node_id < 0)
					{
						this->lock_status.get_mutex()->unlock();
						return -1;
					}

					if (this->toppar_list_map.find(node_id) == this->toppar_list_map.end())
						this->toppar_list_map[node_id] = (KafkaTopparList());

					KafkaToppar new_toppar;
					new_toppar.set_topic_partition(toppar->get_topic(), toppar->get_partition());
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
				meta = get_meta(toppar->get_topic(), &this->client_meta_list);
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
			WFTimerTask *timer = WFTaskFactory::create_timer_task(0, std::move(cb));
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
	std::vector<ParsedURI> broker_hosts;
	std::string::size_type pos = broker.find(',');
	std::string::size_type ppos = 0;

	if (pos == std::string::npos)
	{
		std::string host = broker;
		ParsedURI uri;

		if (host.find("kafka://") != 0)
			host = "kafka://" + host;

		if (URIParser::parse(host, uri) != 0)
			return -1;

		broker_hosts.emplace_back(uri);
	}
	else
	{
		do
		{
			std::string host = broker.substr(ppos, pos - ppos);
			ParsedURI uri;

			if (host.find("kafka://") != 0)
				host = "kafka://" + host;

			if (URIParser::parse(host, uri) != 0)
				return -1;

			broker_hosts.emplace_back(uri);

			ppos = pos + 1;
			pos = broker.find(',', ppos);
		} while (pos != std::string::npos);

		std::string host = broker.substr(ppos, pos - ppos);
		ParsedURI uri;

		if (host.find("kafka://") != 0)
			host = "kafka://" + host;

		if (URIParser::parse(host, uri) != 0)
			return -1;

		broker_hosts.emplace_back(uri);
	}

	this->member = new KafkaMember;
	*this->member->broker_hosts = std::move(broker_hosts);
	*this->member->lock_status->get_status() = KAFKA_META_INIT;

	return 0;
}

int WFKafkaClient::init(const std::string& broker, const std::string& group)
{
	if (this->init(broker) == 0)
	{
		this->member->cgroup->set_group(group);

		*this->member->lock_status->get_status() |=
			KAFKA_CGROUP_INIT | KAFKA_HEARTBEAT_INIT;

		return 0;
	}
	else
		return -1;
}

void WFKafkaClient::set_heartbeat_interval(size_t interval_ms)
{
	KAFKA_HEARTBEAT_TIMEOUT = interval_ms;
}

void WFKafkaClient::deinit()
{
	this->member->lock_status->dec_cnt();
	delete this->member;
	this->member = NULL;
}

WFKafkaClient::WFKafkaClient()
{
	this->member = NULL;
}

WFKafkaClient::~WFKafkaClient()
{
	delete this->member;
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

KafkaMetaList *WFKafkaClient::get_meta_list()
{
	return this->member->meta_list;
}

KafkaBrokerList *WFKafkaClient::get_broker_list()
{
	return this->member->broker_list;
}
