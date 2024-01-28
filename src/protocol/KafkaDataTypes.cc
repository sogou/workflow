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

#include <errno.h>
#include <assert.h>
#include <algorithm>
#include "KafkaDataTypes.h"

#define MIN(x, y)	((x) <= (y) ? (x) : (y))

namespace protocol
{

std::string KafkaConfig::get_sasl_info() const
{
	std::string info;

	if (strcasecmp(this->ptr->mechanisms, "plain") == 0)
	{
		info += this->ptr->mechanisms;
		info += "|";
		info += this->ptr->username;
		info += "|";
		info += this->ptr->password;
		info += "|";
	}
	else if (strncasecmp(this->ptr->mechanisms, "SCRAM", 5) == 0)
	{
		info += this->ptr->mechanisms;
		info += "|";
		info += this->ptr->username;
		info += "|";
		info += this->ptr->password;
		info += "|";
	}

	return info;
}

static bool compare_member(const kafka_member_t *m1, const kafka_member_t *m2)
{
	return strcmp(m1->member_id, m2->member_id) < 0;
}

inline void KafkaMetaSubscriber::sort_by_member()
{
	std::sort(this->member_vec.begin(), this->member_vec.end(), compare_member);
}

static bool operator<(const KafkaMetaSubscriber& s1, const KafkaMetaSubscriber& s2)
{
	return strcmp(s1.get_meta()->get_topic(), s2.get_meta()->get_topic()) < 0;
}

/*
 * For example, suppose there are two consumers C0 and C1, two topics t0 and t1, and each topic has 3 partitions,
 * resulting in partitions t0p0, t0p1, t0p2, t1p0, t1p1, and t1p2.
 *
 * The assignment will be:
 * C0: [t0p0, t0p1, t1p0, t1p1]
 * C1: [t0p2, t1p2]
 */
int KafkaCgroup::kafka_range_assignor(kafka_member_t **members,
									  int member_elements,
									  void *meta_topic)
{
	std::vector<KafkaMetaSubscriber> *subscribers =
		static_cast<std::vector<KafkaMetaSubscriber> *>(meta_topic);

	/* The range assignor works on a per-topic basis. */
	for (auto& subscriber : *subscribers)
	{
		subscriber.sort_by_member();

		int num_partitions_per_consumer =
				subscriber.get_meta()->get_partition_elements() /
				subscriber.get_member()->size();

		/* If it does not evenly divide, then the first few consumers
		 * will have one extra partition. */
		int consumers_with_extra_partition =
				subscriber.get_meta()->get_partition_elements() %
				subscriber.get_member()->size();

		for (int i = 0 ; i < (int)subscriber.get_member()->size(); i++)
		{
			int start = num_partitions_per_consumer * i +
					MIN(i, consumers_with_extra_partition);
			int length = num_partitions_per_consumer +
					(i + 1 > consumers_with_extra_partition ? 0 : 1);

			if (length == 0)
				continue;

			for (int j = start; j < length + start; ++j)
			{
				KafkaToppar *toppar = new KafkaToppar;
				if (!toppar->set_topic_partition(subscriber.get_meta()->get_topic(), j))
				{
					delete toppar;
					return -1;
				}

				list_add_tail(&toppar->list, &subscriber.get_member()->at(i)->assigned_toppar_list);
			}
		}
	}

	return 0;
}

/*
 * For example, suppose there are two consumers C0 and C1, two topics t0 and
 * t1, and each topic has 3 partitions, resulting in partitions t0p0, t0p1,
 * t0p2, t1p0, t1p1, and t1p2.
 *
 * The assignment will be:
 * C0: [t0p0, t0p2, t1p1]
 * C1: [t0p1, t1p0, t1p2]
 */
int KafkaCgroup::kafka_roundrobin_assignor(kafka_member_t **members,
										   int member_elements,
										   void *meta_topic)
{
	std::vector<KafkaMetaSubscriber> *subscribers =
		static_cast<std::vector<KafkaMetaSubscriber> *>(meta_topic);

	int next = -1;

	std::sort(subscribers->begin(), subscribers->end());
	std::sort(members, members + member_elements, compare_member);

	for (const auto& subscriber : *subscribers)
	{
		int partition_elements = subscriber.get_meta()->get_partition_elements();

		for (int partition = 0; partition < partition_elements; ++partition)
		{
			next = (next + 1) % subscriber.get_member()->size();
			struct list_head *pos;
			KafkaToppar *toppar;

			int i = 0;
			for (; i < member_elements; i++)
			{
				bool flag = false;
				list_for_each(pos, &members[next + i]->toppar_list)
				{
					toppar = list_entry(pos, KafkaToppar, list);
					if (strcmp(subscriber.get_meta()->get_topic(), toppar->get_topic()) == 0)
					{
						flag = true;
						break;
					}
				}

				if (flag)
					break;
			}

			if (i >= member_elements)
				return -1;

			toppar = new KafkaToppar;
			if (!toppar->set_topic_partition(subscriber.get_meta()->get_topic(),
											 partition))
			{
				delete toppar;
				return -1;
			}

			list_add_tail(toppar->get_list(), &members[next]->assigned_toppar_list);
		}
	}

	return 0;
}

bool KafkaMeta::create_partitions(int partition_cnt)
{
	if (partition_cnt <= 0)
		return true;

	kafka_partition_t **partitions;
	partitions = (kafka_partition_t **)malloc(sizeof(void *) * partition_cnt);
	if (!partitions)
		return false;

	int i;

	for (i = 0; i < partition_cnt; ++i)
	{
		partitions[i] = (kafka_partition_t *)malloc(sizeof(kafka_partition_t));
		if (!partitions[i])
			break;

		kafka_partition_init(partitions[i]);
	}

	if (i != partition_cnt)
	{
		while (--i >= 0)
		{
			kafka_partition_deinit(partitions[i]);
			free(partitions[i]);
		}

		free(partitions);
		return false;
	}

	for (i = 0; i < this->ptr->partition_elements; ++i)
	{
		kafka_partition_deinit(this->ptr->partitions[i]);
		free(this->ptr->partitions[i]);
	}

	free(this->ptr->partitions);

	this->ptr->partitions = partitions;
	this->ptr->partition_elements = partition_cnt;
	return true;
}

void KafkaCgroup::add_subscriber(KafkaMetaList *meta_list, 
								 std::vector<KafkaMetaSubscriber> *subscribers)
{
	meta_list->rewind();
	KafkaMeta *meta;

	while ((meta = meta_list->get_next()) != NULL)
	{
		KafkaMetaSubscriber subscriber;

		subscriber.set_meta(meta);
		for (int i = 0; i < this->get_member_elements(); ++i)
		{
			struct list_head *pos;
			KafkaToppar *toppar;
			bool flag = false;

			list_for_each(pos, &this->get_members()[i]->toppar_list)
			{
				toppar = list_entry(pos, KafkaToppar, list);
				if (strcmp(meta->get_topic(), toppar->get_topic()) == 0)
				{
					flag = true;
					break;
				}
			}

			if (flag)
				subscriber.add_member(this->get_members()[i]);
		}

		if (!subscriber.get_member()->empty())
			subscribers->emplace_back(subscriber);
	}
}

int KafkaCgroup::run_assignor(KafkaMetaList *meta_list,
							  const char *protocol_name)
{
	std::vector<KafkaMetaSubscriber> subscribers;
	this->add_subscriber(meta_list, &subscribers);

	struct list_head *pos;
	kafka_group_protocol_t *protocol;
	bool flag = false;
	list_for_each(pos, this->get_group_protocol())
	{
		protocol = list_entry(pos, kafka_group_protocol_t, list);
		if (strcmp(protocol_name, protocol->protocol_name) == 0)
		{
			flag = true;
			break;
		}
	}

	if (!flag)
	{
		errno = EBADMSG;
		return -1;
	}

	return protocol->assignor(this->get_members(), this->get_member_elements(),
							  &subscribers);
}

KafkaCgroup::KafkaCgroup()
{
	this->ptr = new kafka_cgroup_t;
	kafka_cgroup_init(this->ptr);
	kafka_group_protocol_t *protocol = new kafka_group_protocol_t;
	protocol->protocol_name = new char[strlen("range") + 1];
	memcpy(protocol->protocol_name, "range", strlen("range") + 1);
	protocol->assignor = kafka_range_assignor;
	list_add_tail(&protocol->list, &this->ptr->group_protocol_list);
	protocol = new kafka_group_protocol_t;
	protocol->protocol_name = new char[strlen("roundrobin") + 1];
	memcpy(protocol->protocol_name, "roundrobin", strlen("roundrobin") + 1);
	protocol->assignor = kafka_roundrobin_assignor;
	list_add_tail(&protocol->list, &this->ptr->group_protocol_list);
	this->ref = new std::atomic<int>(1);
	this->coordinator = NULL;
}

KafkaCgroup::~KafkaCgroup()
{
	if (--*this->ref == 0)
	{
		for (int i = 0; i < this->ptr->member_elements; ++i)
		{
			kafka_member_t *member = this->ptr->members[i];
			KafkaToppar *toppar;
			struct list_head *pos, *tmp;

			list_for_each_safe(pos, tmp, &member->toppar_list)
			{
				toppar = list_entry(pos, KafkaToppar, list);
				list_del(pos);
				delete toppar;
			}

			list_for_each_safe(pos, tmp, &member->assigned_toppar_list)
			{
				toppar = list_entry(pos, KafkaToppar, list);
				list_del(pos);
				delete toppar;
			}
		}

		kafka_cgroup_deinit(this->ptr);

		struct list_head *tmp, *pos;
		KafkaToppar *toppar;

		list_for_each_safe(pos, tmp, &this->ptr->assigned_toppar_list)
		{
			toppar = list_entry(pos, KafkaToppar, list);
			list_del(pos);
			delete toppar;
		}

		kafka_group_protocol_t *protocol;
		list_for_each_safe(pos, tmp, &this->ptr->group_protocol_list)
		{
			protocol = list_entry(pos, kafka_group_protocol_t, list);
			list_del(pos);
			delete []protocol->protocol_name;
			delete protocol;
		}

		delete []this->ptr->group_name;

		delete this->ptr;
		delete this->ref;
	}

	delete this->coordinator;
}

KafkaCgroup::KafkaCgroup(KafkaCgroup&& move)
{
	this->ptr = move.ptr;
	this->ref = move.ref;
	move.ptr = new kafka_cgroup_t;
	kafka_cgroup_init(move.ptr);
	move.ref = new std::atomic<int>(1);
	this->coordinator = move.coordinator;
	move.coordinator = NULL;
}

KafkaCgroup& KafkaCgroup::operator= (KafkaCgroup&& move)
{
	if (this != &move)
	{
		this->~KafkaCgroup();
		this->ptr = move.ptr;
		this->ref = move.ref;
		move.ptr = new kafka_cgroup_t;
		kafka_cgroup_init(move.ptr);
		move.ref = new std::atomic<int>(1);
		this->coordinator = move.coordinator;
		move.coordinator = NULL;
	}

	return *this;
}

KafkaCgroup::KafkaCgroup(const KafkaCgroup& copy)
{
	this->ptr = copy.ptr;
	this->ref = copy.ref;
	++*this->ref;

	if (copy.coordinator)
		this->coordinator = new KafkaBroker(copy.coordinator->get_raw_ptr());
	else
		this->coordinator = NULL;
}

KafkaCgroup& KafkaCgroup::operator= (const KafkaCgroup& copy)
{
	this->~KafkaCgroup();
	this->ptr = copy.ptr;
	this->ref = copy.ref;
	++*this->ref;

	if (copy.coordinator)
		this->coordinator = new KafkaBroker(copy.coordinator->get_raw_ptr());
	else
		this->coordinator = NULL;

	return *this;
}

bool KafkaCgroup::create_members(int member_cnt)
{
	if (member_cnt == 0)
		return true;

	kafka_member_t **members;
	members = (kafka_member_t **)malloc(sizeof(void *) * member_cnt);
	if (!members)
		return false;

	int i;

	for (i = 0; i < member_cnt; ++i)
	{
		members[i] = (kafka_member_t *)malloc(sizeof(kafka_member_t));
		if (!members[i])
			break;

		kafka_member_init(members[i]);
		INIT_LIST_HEAD(&members[i]->toppar_list);
		INIT_LIST_HEAD(&members[i]->assigned_toppar_list);
	}

	if (i != member_cnt)
	{
		while (--i >= 0)
		{
			KafkaToppar *toppar;
			struct list_head *pos, *tmp;
			list_for_each_safe(pos, tmp, &members[i]->toppar_list)
			{
				toppar = list_entry(pos, KafkaToppar, list);
				list_del(pos);
				delete toppar;
			}

			list_for_each_safe(pos, tmp, &members[i]->assigned_toppar_list)
			{
				toppar = list_entry(pos, KafkaToppar, list);
				list_del(pos);
				delete toppar;
			}

			kafka_member_deinit(members[i]);
			free(members[i]);
		}

		free(members);
		return false;
	}

	for (i = 0; i < this->ptr->member_elements; ++i)
	{
		KafkaToppar *toppar;
		struct list_head *pos, *tmp;

		list_for_each_safe(pos, tmp, &this->ptr->members[i]->toppar_list)
		{
			toppar = list_entry(pos, KafkaToppar, list);
			list_del(pos);
			delete toppar;
		}

		list_for_each_safe(pos, tmp, &this->ptr->members[i]->assigned_toppar_list)
		{
			toppar = list_entry(pos, KafkaToppar, list);
			list_del(pos);
			delete toppar;
		}

		kafka_member_deinit(this->ptr->members[i]);
		free(this->ptr->members[i]);
	}

	free(this->ptr->members);

	this->ptr->members = members;
	this->ptr->member_elements = member_cnt;
	return true;
}

void KafkaCgroup::add_assigned_toppar(KafkaToppar *toppar)
{
	list_add_tail(toppar->get_list(), &this->ptr->assigned_toppar_list);
}

void KafkaCgroup::assigned_toppar_rewind()
{
	this->curpos = &this->ptr->assigned_toppar_list;
}

KafkaToppar *KafkaCgroup::get_assigned_toppar_next()
{
	if (this->curpos->next == &this->ptr->assigned_toppar_list)
		return NULL;

	this->curpos = this->curpos->next;
	return list_entry(this->curpos, KafkaToppar, list);
}

void KafkaCgroup::del_assigned_toppar_cur()
{
	assert(this->curpos != &this->ptr->assigned_toppar_list);
	this->curpos = this->curpos->prev;
	list_del(this->curpos->next);
}

bool KafkaRecord::add_header_pair(const void *key, size_t key_len,
								  const void *val, size_t val_len)
{
	kafka_record_header_t *header;

	header = (kafka_record_header_t *)malloc(sizeof(kafka_record_header_t));
	if (!header)
		return false;

	kafka_record_header_init(header);
	if (kafka_record_header_set_kv(key, key_len, val, val_len, header) < 0)
	{
		free(header);
		return false;
	}

	list_add_tail(&header->list, &this->ptr->header_list);
	return true;
}

bool KafkaRecord::add_header_pair(const std::string& key,
								  const std::string& val)
{
	return add_header_pair(key.c_str(), key.size(), val.c_str(), val.size());
}

KafkaToppar::~KafkaToppar()
{
	if (--*this->ref == 0)
	{
		kafka_topic_partition_deinit(this->ptr);

		struct list_head *tmp, *pos;
		KafkaRecord *record;
		list_for_each_safe(pos, tmp, &this->ptr->record_list)
		{
			record = list_entry(pos, KafkaRecord, list);
			list_del(pos);
			delete record;
		}

		delete this->ptr;
		delete this->ref;
	}
}

void KafkaBuffer::list_splice(KafkaBuffer *buffer)
{
	struct list_head *pre_insert;
	struct list_head *pre_tail;

	this->buf_size -= this->insert_buf_size;

	pre_insert = this->insert_pos->next;
	__list_splice(buffer->get_head(), this->insert_pos, pre_insert);

	pre_tail = this->block_list.get_tail();
	buffer->get_head()->prev->next = this->block_list.get_head();
	this->block_list.get_head()->prev = buffer->get_head()->prev;

	buffer->get_head()->next = pre_insert;
	buffer->get_head()->prev = pre_tail;
	pre_tail->next = buffer->get_head();

	pre_insert->prev = buffer->get_head();

	this->buf_size += buffer->get_size();
}

size_t KafkaBuffer::peek(const char **buf)
{
	if (!this->inited)
	{
		this->inited = true;
		this->cur_pos = std::make_pair(this->block_list.get_next(), 0);
	}

	if (this->cur_pos.first == this->block_list.get_tail_entry() &&
		this->cur_pos.second == this->block_list.get_tail_entry()->get_len())
	{
		*buf = NULL;
		return 0;
	}

	KafkaBlock *block = this->cur_pos.first;

	if (this->cur_pos.second >= block->get_len())
	{
		block = this->block_list.get_next();
		this->cur_pos = std::make_pair(block, 0);
	}

	*buf = (char *)block->get_block() + this->cur_pos.second;

	return block->get_len() - this->cur_pos.second;
}

KafkaToppar *get_toppar(const char *topic, int partition,
						KafkaTopparList *toppar_list)
{
	struct list_head *pos;
	KafkaToppar *toppar;
	list_for_each(pos, toppar_list->get_head())
	{
		toppar = list_entry(pos, KafkaToppar, list);
		if (strcmp(toppar->get_topic(), topic) == 0 &&
			toppar->get_partition() == partition)
			return toppar;
	}

	return NULL;
}

const KafkaMeta *get_meta(const char *topic, KafkaMetaList *meta_list)
{
	struct list_head *pos;
	const KafkaMeta *meta;
	list_for_each(pos, meta_list->get_head())
	{
		meta = list_entry(pos, KafkaMeta, list);
		if (strcmp(meta->get_topic(), topic) == 0)
			return meta;
	}

	return NULL;
}

} /* namespace protocol */
