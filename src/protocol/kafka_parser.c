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

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "kafka_parser.h"


#define MIN(a, b)	((x) <= (y) ? (x) : (y))

static kafka_api_version_t kafka_api_version_queryable[] = {
	{ Kafka_ApiVersions, 0, 0 }
};

static kafka_api_version_t kafka_api_version_0_9_0[] = {
	{ Kafka_Produce, 0, 1 },
	{ Kafka_Fetch, 0, 1 },
	{ Kafka_ListOffsets, 0, 0 },
	{ Kafka_Metadata, 0, 0 },
	{ Kafka_OffsetCommit, 0, 2 },
	{ Kafka_OffsetFetch, 0, 1 },
	{ Kafka_FindCoordinator, 0, 0 },
	{ Kafka_JoinGroup, 0, 0 },
	{ Kafka_Heartbeat, 0, 0 },
	{ Kafka_LeaveGroup, 0, 0 },
	{ Kafka_SyncGroup, 0, 0 },
	{ Kafka_DescribeGroups, 0, 0 },
	{ Kafka_ListGroups, 0, 0 }
};

static kafka_api_version_t kafka_api_version_0_8_2[] = {
	{ Kafka_Produce, 0, 0 },
	{ Kafka_Fetch, 0, 0 },
	{ Kafka_ListOffsets, 0, 0 },
	{ Kafka_Metadata, 0, 0 },
	{ Kafka_OffsetCommit, 0, 1 },
	{ Kafka_OffsetFetch, 0, 1 },
	{ Kafka_FindCoordinator, 0, 0 }
};

static kafka_api_version_t kafka_api_version_0_8_1[] = {
	{ Kafka_Produce, 0, 0 },
	{ Kafka_Fetch, 0, 0 },
	{ Kafka_ListOffsets, 0, 0 },
	{ Kafka_Metadata, 0, 0 },
	{ Kafka_OffsetCommit, 0, 1 },
	{ Kafka_OffsetFetch, 0, 0 }
};

static kafka_api_version_t kafka_api_version_0_8_0[] = {
	{ Kafka_Produce, 0, 0 },
	{ Kafka_Fetch, 0, 0 },
	{ Kafka_ListOffsets, 0, 0 },
	{ Kafka_Metadata, 0, 0 }
};

static const struct kafka_feature_map {
	unsigned feature;
	kafka_api_version_t depends[Kafka_ApiNums];
} kafka_feature_map[] = {
	{
		.feature = KAFKA_FEATURE_MSGVER1,
		.depends = {
			{ Kafka_Produce, 2, 2 },
			{ Kafka_Fetch, 2, 2 },
			{ Kafka_Unknown, 0, 0 },
		},
	},
	{
		.feature = KAFKA_FEATURE_MSGVER2,
		.depends = {
			{ Kafka_Produce, 3, 3 },
			{ Kafka_Fetch, 4, 4 },
			{ Kafka_Unknown, 0, 0 },
		},
	},
	{
		.feature = KAFKA_FEATURE_APIVERSION,
		.depends = {
			{ Kafka_ApiVersions, 0, 0 },
			{ Kafka_Unknown, 0, 0 },
		},
	},
	{
		.feature = KAFKA_FEATURE_BROKER_GROUP_COORD,
		.depends = {
			{ Kafka_FindCoordinator, 0, 0 },
			{ Kafka_Unknown, 0, 0 },
		},
	},
	{
		.feature = KAFKA_FEATURE_BROKER_BALANCED_CONSUMER,
		.depends = {
			{ Kafka_FindCoordinator, 0, 0 },
			{ Kafka_OffsetCommit, 1, 2 },
			{ Kafka_OffsetFetch, 1, 1 },
			{ Kafka_JoinGroup, 0, 0 },
			{ Kafka_SyncGroup, 0, 0 },
			{ Kafka_Heartbeat, 0, 0 },
			{ Kafka_LeaveGroup, 0, 0 },
			{ Kafka_Unknown, 0, 0 },
		},
	},
	{
		.feature = KAFKA_FEATURE_THROTTLETIME,
		.depends = {
			{ Kafka_Produce, 1, 2 },
			{ Kafka_Fetch, 1, 2 },
			{ Kafka_Unknown, 0, 0 },
		},

	},
	{
		.feature = KAFKA_FEATURE_LZ4,
		.depends = {
			{ Kafka_FindCoordinator, 0, 0 },
			{ Kafka_Unknown, 0, 0 },
		},
	},
	{
		.feature = KAFKA_FEATURE_OFFSET_TIME,
		.depends = {
			{ Kafka_ListOffsets, 1, 1 },
			{ Kafka_Unknown, 0, 0 },
		}
	},
	{
		.feature = KAFKA_FEATURE_ZSTD,
		.depends = {
			{ Kafka_Produce, 7, 7 },
			{ Kafka_Fetch, 10, 10 },
			{ Kafka_Unknown, 0, 0 },
		},
	},
	{
		.feature = 0,
	},
};

static int kafka_get_legacy_api_version(const char *broker_version,
										kafka_api_version_t **api,
										size_t *api_cnt)
{
	static const struct {
		const char *pfx;
		kafka_api_version_t *api;
		size_t api_cnt;
	} vermap[] = {
		{ "0.9.0",
		  kafka_api_version_0_9_0,
		  sizeof(kafka_api_version_0_9_0) / sizeof(kafka_api_version_t)
		},
		{ "0.8.2",
		  kafka_api_version_0_8_2,
		  sizeof(kafka_api_version_0_8_2) / sizeof(kafka_api_version_t)
		},
		{ "0.8.1",
		  kafka_api_version_0_8_1,
		  sizeof(kafka_api_version_0_8_1) / sizeof(kafka_api_version_t)
		},
		{ "0.8.0",
		  kafka_api_version_0_8_0,
		  sizeof(kafka_api_version_0_8_0) / sizeof(kafka_api_version_t)
		},
		{ "0.7.", NULL, 0 },
		{ "0.6", NULL, 0 },
		{ "", kafka_api_version_queryable, 1 },
		{ NULL, NULL, 0 }
	};

	int i, ret = 0;
	for (i = 0 ; vermap[i].pfx ; i++)
	{
		if (!strncmp(vermap[i].pfx, broker_version, strlen(vermap[i].pfx)))
		{
			if (!vermap[i].api)
				return -1;
			*api = vermap[i].api;
			*api_cnt = vermap[i].api_cnt;
			break;
		}
	}

	return ret;
}

int kafka_api_version_is_queryable(const char *broker_version,
								   kafka_api_version_t **api,
								   size_t *api_cnt)
{
	int ret = kafka_get_legacy_api_version(broker_version, api, api_cnt);

	if (ret <= 0)
		return ret;

	return *api == kafka_api_version_queryable;
}

static int kafka_api_version_key_cmp(const void *_a, const void *_b)
{
	const kafka_api_version_t *a = _a, *b = _b;

	if (a->api_key > b->api_key)
		return 1;
	else if (a->api_key == b->api_key)
		return 0;
	else
		return -1;
}

static int kafka_api_version_check(const kafka_api_version_t *apis,
								   size_t api_cnt,
								   const kafka_api_version_t *match)
{
	const kafka_api_version_t *api;

	api = bsearch(match, apis, api_cnt, sizeof(*apis),
				  kafka_api_version_key_cmp);
	if (!api)
		return 0;

	return match->min_ver <= api->max_ver && api->min_ver <= match->max_ver;
}

unsigned kafka_get_features(kafka_api_version_t *api, size_t api_cnt)
{
	unsigned features = 0;
	int i, fails, r;
	const kafka_api_version_t *match;

	for (i = 0 ; kafka_feature_map[i].feature != 0 ; i++)
	{
		fails = 0;
		for (match = &kafka_feature_map[i].depends[0];
				match->api_key != -1 ; match++)
		{
			r = kafka_api_version_check(api, api_cnt, match);
			fails += !r;
		}

		if (!fails)
			features |= kafka_feature_map[i].feature;
	}

	return features;
}

int kafka_broker_get_api_version(const kafka_broker_t *broker,
								 int api_key,
								 int min_ver, int max_ver)
{
	kafka_api_version_t sk = { .api_key = api_key };
	kafka_api_version_t *retp;

	retp = bsearch(&sk, broker->api, broker->api_elements,
				   sizeof(*broker->api), kafka_api_version_key_cmp);

	if (!retp)
		return -1;

	if (retp->max_ver < max_ver)
	{
		if (retp->max_ver < min_ver)
			return -1;
		else
			return retp->max_ver;
	}
	else if (retp->min_ver > min_ver)
		return -1;
	else
		return max_ver;
}

void kafka_parser_init(kafka_parser_t *parser)
{
	parser->complete = 0;
	parser->message_size = 0;
	parser->msgbuf = NULL;
	parser->cur_size = 0;
	parser->hsize = 0;
}

void kafka_parser_deinit(kafka_parser_t *parser)
{
	free(parser->msgbuf);
}

void kafka_config_init(kafka_config_t *conf)
{
	conf->produce_timeout = 100;
	conf->produce_msg_max_bytes = 1000000;
	conf->produce_msgset_cnt = 10000;
	conf->produce_msgset_max_bytes = 1000000;
	conf->fetch_timeout = 100;
	conf->fetch_min_bytes = 1;
	conf->fetch_max_bytes = 50 * 1024 * 1024;
	conf->fetch_msg_max_bytes = 1024 * 1024;
	conf->offset_timestamp = -2;
	conf->commit_timestamp = 0;
	conf->session_timeout = 10*1000;
	conf->rebalance_timeout = 10000;
	conf->retention_time_period = 20000;
	conf->produce_acks = -1;
	conf->allow_auto_topic_creation = 1;
	conf->api_version_request = 0;
	conf->api_version_timeout = 10000;
	conf->broker_version = NULL;
	conf->compress_type = Kafka_NoCompress;
	conf->compress_level = 0;
	conf->client_id = NULL;
	conf->check_crcs = 0;
	conf->offset_store = KAFKA_OFFSET_AUTO;
}

void kafka_config_deinit(kafka_config_t *conf)
{
	free(conf->broker_version);
	free(conf->client_id);
}

void kafka_partition_init(kafka_partition_t *partition)
{
	partition->error = KAFKA_NONE;
	partition->partition_index = -1;
	kafka_broker_init(&partition->leader);
	partition->replica_nodes = NULL;
	partition->replica_node_elements = 0;
	partition->isr_nodes = NULL;
	partition->isr_node_elements = 0;
}

void kafka_partition_deinit(kafka_partition_t *partition)
{
    kafka_broker_deinit(&partition->leader);
	free(partition->replica_nodes);
	free(partition->isr_nodes);
}

void kafka_broker_init(kafka_broker_t *broker)
{
	broker->node_id = -1;
	broker->port = 0;
	broker->host = NULL;
	broker->rack = NULL;
	broker->to_addr = 0;
	memset(&broker->addr, 0, sizeof(broker->addr));
	broker->addrlen = 0;
	broker->features = 0;
	broker->api = NULL;
	broker->api_elements = 0;
}

void kafka_broker_deinit(kafka_broker_t *broker)
{
	free(broker->host);
	free(broker->rack);
	free(broker->api);
}

void kafka_meta_init(kafka_meta_t *meta)
{
	meta->error = KAFKA_NONE;
	meta->topic_name = NULL;
	meta->error_message = NULL;
	meta->is_internal = 0;
	meta->partitions = NULL;
	meta->partition_elements = 0;
}

void kafka_meta_deinit(kafka_meta_t *meta)
{
	int i;

	free(meta->topic_name);
	free(meta->error_message);

	for (i = 0; i < meta->partition_elements; ++i)
	{
		kafka_partition_deinit(meta->partitions[i]);
		free(meta->partitions[i]);
	}
	free(meta->partitions);
}

void kafka_topic_partition_init(kafka_topic_partition_t *toppar)
{
	toppar->error = KAFKA_NONE;
	toppar->topic_name = NULL;
	toppar->partition = -1;
	toppar->offset = -1;
	toppar->high_watermark = -1;
	toppar->low_watermark = -2;
	toppar->last_stable_offset = -1;
	toppar->log_start_offset = -1;
	toppar->offset_timestamp = -1;
	toppar->committed_metadata = NULL;
	INIT_LIST_HEAD(&toppar->record_list);
}

void kafka_topic_partition_deinit(kafka_topic_partition_t *toppar)
{
	free(toppar->topic_name);
	free(toppar->committed_metadata);
}

void kafka_record_header_init(kafka_record_header_t *header)
{
	header->key = NULL;
	header->key_len = 0;
	header->key_is_move = 0;
	header->value = NULL;
	header->value_len = 0;
	header->value_is_move = 0;
}

void kafka_record_header_deinit(kafka_record_header_t *header)
{
	if (!header->key_is_move)
		free(header->key);

	if (!header->value_is_move)
		free(header->value);
}

void kafka_record_init(kafka_record_t *record)
{
	record->key = NULL;
	record->key_len = 0;
	record->key_is_move = 0;
	record->value = NULL;
	record->value_len = 0;
	record->value_is_move = 0;
	record->timestamp = 0;
	record->offset = 0;
	INIT_LIST_HEAD(&record->header_list);
	record->status = KAFKA_UNKNOWN_SERVER_ERROR;
	record->toppar = NULL;
}

void kafka_record_deinit(kafka_record_t *record)
{
	struct list_head *tmp, *pos;
	kafka_record_header_t *header;

	if (!record->key_is_move)
		free(record->key);

	if (!record->value_is_move)
		free(record->value);

	list_for_each_safe(pos, tmp, &record->header_list)
	{
		header = list_entry(pos, kafka_record_header_t, list);
		list_del(pos);
		kafka_record_header_deinit(header);
		free(header);
	}
}

void kafka_member_init(kafka_member_t *member)
{
	member->member_id = NULL;
	member->client_id = NULL;
	member->client_host = NULL;
	member->member_metadata = NULL;
	member->member_metadata_len = 0;
}

void kafka_member_deinit(kafka_member_t *member)
{
	free(member->member_id);
	free(member->client_id);
	free(member->client_host);
	//do not need free!
	//free(member->member_metadata);
}

void kafka_cgroup_init(kafka_cgroup_t *cgroup)
{
	INIT_LIST_HEAD(&cgroup->assigned_toppar_list);
	cgroup->error = KAFKA_NONE;
	cgroup->error_msg = NULL;
	kafka_broker_init(&cgroup->coordinator);
	cgroup->leader_id = NULL;
	cgroup->member_id = NULL;
	cgroup->members = NULL;
	cgroup->member_elements = 0;
	cgroup->generation_id = -1;
	cgroup->group_name = NULL;
	cgroup->protocol_type = "consumer";
	cgroup->protocol_name = NULL;
	INIT_LIST_HEAD(&cgroup->group_protocol_list);
}

void kafka_cgroup_deinit(kafka_cgroup_t *cgroup)
{
	int i;

	free(cgroup->error_msg);
	kafka_broker_deinit(&cgroup->coordinator);
	free(cgroup->leader_id);
	free(cgroup->member_id);

	for (i = 0; i < cgroup->member_elements; ++i)
	{
		kafka_member_deinit(cgroup->members[i]);
		free(cgroup->members[i]);
	}

	free(cgroup->members);
	free(cgroup->protocol_name);
}

void kafka_block_init(kafka_block_t *block)
{
	block->buf = NULL;
	block->len = 0;
	block->is_move = 0;
}

void kafka_block_deinit(kafka_block_t *block)
{
	if (!block->is_move)
		free(block->buf);
}

int kafka_parser_append_message(const void *buf, size_t *size,
								kafka_parser_t *parser)
{
	int totaln;

	if (parser->complete)
	{
		*size = 0;
		return 1;
	}

	size_t s = *size;

	if (parser->hsize + *size < 4)
	{
		memcpy(parser->headbuf + parser->hsize, buf, s);
		parser->hsize += s;
		return 0;
	}
	else if (!parser->msgbuf)
	{
		memcpy(parser->headbuf + parser->hsize, buf, 4 - parser->hsize);
		buf = (const char *)buf + 4 - parser->hsize;
		s -= 4 - parser->hsize;
		parser->hsize = 4;
		memcpy(&totaln, parser->headbuf, 4);
		parser->message_size = ntohl(totaln);
		parser->msgbuf = malloc(parser->message_size);
		if (!parser->msgbuf)
			return -1;

		parser->cur_size = 0;
	}

	if (s > parser->message_size - parser->cur_size)
	{
		memcpy(parser->msgbuf + parser->cur_size, buf, parser->message_size - parser->cur_size);
		parser->cur_size = parser->message_size;
	}
	else
	{
		memcpy(parser->msgbuf + parser->cur_size, buf, s);
		parser->cur_size += s;
	}

	if (parser->cur_size < parser->message_size)
		return 0;

	*size -= parser->message_size - parser->cur_size;
	return 1;
}

int kafka_topic_partition_set_tp(const char *topic_name, int partition,
								 kafka_topic_partition_t *toppar)
{
	char *p = strdup(topic_name);

	if (!p)
		return -1;

	free(toppar->topic_name);
	toppar->topic_name = p;
	toppar->partition = partition;
	return 0;
}

int kafka_record_set_key(const void *key, size_t key_len,
						 kafka_record_t *record)
{
	void *k = malloc(key_len);

	if (!k)
		return -1;

	free(record->key);
	memcpy(k, key, key_len);
	record->key = k;
	record->key_len = key_len;
	return 0;
}

int kafka_record_set_value(const void *val, size_t val_len,
						   kafka_record_t *record)
{
	void *v = malloc(val_len);

	if (!v)
		return -1;

	free(record->value);
	memcpy(v, val, val_len);
	record->value = v;
	record->value_len = val_len;
	return 0;
}

int kafka_record_header_set_kv(const void *key, size_t key_len,
							   const void *val, size_t val_len,
							   kafka_record_header_t *header)
{
	void *k = malloc(key_len);

	if (!k)
		return -1;

	void *v = malloc(val_len);

	if (!v)
	{
		free(k);
		return -1;
	}

	memcpy(k, key, key_len);
	memcpy(v, val, val_len);
	header->key = k;
	header->key_len = key_len;
	header->value = v;
	header->value_len = val_len;
	return 0;
}

int kafka_meta_set_topic(const char *topic, kafka_meta_t *meta)
{
	char *t = strdup(topic);

	if (!t)
		return -1;

	free(meta->topic_name);
	meta->topic_name = t;
	return 0;
}

int kafka_cgroup_set_group(const char *group, kafka_cgroup_t *cgroup)
{
	char *t = strdup(group);

	if (!t)
		return -1;

	free(cgroup->group_name);
	cgroup->group_name = t;
	return 0;
}
