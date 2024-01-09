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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "kafka_parser.h"

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
		.feature = KAFKA_FEATURE_SASL_GSSAPI,
		.depends = {
			{ Kafka_JoinGroup, 0, 0},
			{ Kafka_Unknown, 0, 0 },
		},
	},
	{
		.feature = KAFKA_FEATURE_SASL_HANDSHAKE,
		.depends = {
			{ Kafka_SaslHandshake, 0, 0},
			{ Kafka_Unknown, 0, 0 },
		},
	},
	{
		.feature = KAFKA_FEATURE_SASL_AUTH_REQ,
		.depends = {
			{ Kafka_SaslHandshake, 1, 1},
			{ Kafka_SaslAuthenticate, 0, 0},
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
	int i;

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

	return 0;
}

int kafka_api_version_is_queryable(const char *broker_version,
								   kafka_api_version_t **api,
								   size_t *api_cnt)
{
	return kafka_get_legacy_api_version(broker_version, api, api_cnt);
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

	for (i = 0; kafka_feature_map[i].feature != 0; i++)
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

int kafka_broker_get_api_version(const kafka_api_t *api, int api_key,
								 int min_ver, int max_ver)
{
	kafka_api_version_t sk = { .api_key = api_key };
	kafka_api_version_t *retp;

	retp = bsearch(&sk, api->api, api->elements,
				   sizeof(*api->api), kafka_api_version_key_cmp);
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
	conf->fetch_msg_max_bytes = 10 * 1024 * 1024;
	conf->offset_timestamp = KAFKA_TIMESTAMP_LATEST;
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
	conf->rack_id = NULL;
	conf->mechanisms = NULL;
	conf->username = NULL;
	conf->password = NULL;
	conf->recv = NULL;
	conf->client_new = NULL;
}

void kafka_config_deinit(kafka_config_t *conf)
{
	free(conf->broker_version);
	free(conf->client_id);
	free(conf->rack_id);
	free(conf->mechanisms);
	free(conf->username);
	free(conf->password);
}

void kafka_partition_init(kafka_partition_t *partition)
{
	partition->error = 0;
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

void kafka_api_init(kafka_api_t *api)
{
	api->features = 0;
	api->api = NULL;
	api->elements = 0;
}

void kafka_api_deinit(kafka_api_t *api)
{
	free(api->api);
}

void kafka_broker_init(kafka_broker_t *broker)
{
	broker->node_id = -1;
	broker->port = 0;
	broker->host = NULL;
	broker->rack = NULL;
	broker->error = 0;
	broker->status = KAFKA_BROKER_UNINIT;
}

void kafka_broker_deinit(kafka_broker_t *broker)
{
	free(broker->host);
	free(broker->rack);
}

void kafka_meta_init(kafka_meta_t *meta)
{
	meta->error = 0;
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
	toppar->error = 0;
	toppar->topic_name = NULL;
	toppar->partition = -1;
	toppar->preferred_read_replica = -1;
	toppar->offset = KAFKA_OFFSET_UNINIT;
	toppar->high_watermark = KAFKA_OFFSET_UNINIT;
	toppar->low_watermark = KAFKA_OFFSET_UNINIT;
	toppar->last_stable_offset = -1;
	toppar->log_start_offset = -1;
	toppar->offset_timestamp = KAFKA_TIMESTAMP_UNINIT;
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
	header->key_is_moved = 0;
	header->value = NULL;
	header->value_len = 0;
	header->value_is_moved = 0;
}

void kafka_record_header_deinit(kafka_record_header_t *header)
{
	if (!header->key_is_moved)
		free(header->key);

	if (!header->value_is_moved)
		free(header->value);
}

void kafka_record_init(kafka_record_t *record)
{
	record->key = NULL;
	record->key_len = 0;
	record->key_is_moved = 0;
	record->value = NULL;
	record->value_len = 0;
	record->value_is_moved = 0;
	record->timestamp = 0;
	record->offset = 0;
	INIT_LIST_HEAD(&record->header_list);
	record->status = 0;
	record->toppar = NULL;
}

void kafka_record_deinit(kafka_record_t *record)
{
	struct list_head *tmp, *pos;
	kafka_record_header_t *header;

	if (!record->key_is_moved)
		free(record->key);

	if (!record->value_is_moved)
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
	cgroup->error = 0;
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
	block->is_moved = 0;
}

void kafka_block_deinit(kafka_block_t *block)
{
	if (!block->is_moved)
		free(block->buf);
}

int kafka_parser_append_message(const void *buf, size_t *size,
								kafka_parser_t *parser)
{
	size_t s = *size;
	int totaln;

	if (parser->complete)
	{
		*size = 0;
		return 1;
	}

	if (parser->hsize + s < 4)
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
		memcpy((char *)parser->msgbuf + parser->cur_size, buf,
			   parser->message_size - parser->cur_size);
		parser->cur_size = parser->message_size;
	}
	else
	{
		memcpy((char *)parser->msgbuf + parser->cur_size, buf, s);
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
	void *v = malloc(val_len);

	if (!k || !v)
	{
		free(k);
		free(v);
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

static int kafka_sasl_plain_recv(const char *buf, size_t len, void *conf, void *q)
{
	return 0;
}

static int kafka_sasl_plain_client_new(void *p, kafka_sasl_t *sasl)
{
	kafka_config_t *conf = (kafka_config_t *)p;
	size_t ulen = strlen(conf->username);
	size_t plen = strlen(conf->password);
	size_t blen = ulen + plen + 2;
	size_t off = 0;
	char *buf = (char *)malloc(blen);

	if (!buf)
		return -1;

	buf[off++] = '\0';

	memcpy(buf + off, conf->username, ulen);
	off += ulen;
	buf[off++] = '\0';

	memcpy(buf + off, conf->password, plen);

	free(sasl->buf);
	sasl->buf = buf;
	sasl->bsize = blen;

	return 0;
}

static int scram_get_attr(const struct iovec *inbuf, char attr,
						  struct iovec *outbuf)
{
	const char *td;
	size_t len;
	size_t of = 0;
	void *ptr;
	char ochar, nchar;

	for (of = 0; of < inbuf->iov_len;)
	{
		ptr = (char *)inbuf->iov_base + of;
		td = memchr(ptr, ',', inbuf->iov_len - of);
		if (td)
			len = (size_t)((char *)td - (char *)inbuf->iov_base - of);
		else
			len = inbuf->iov_len - of;

		ochar = *((char *)inbuf->iov_base + of);
		nchar = *((char *)inbuf->iov_base + of + 1);
		if (ochar == attr && inbuf->iov_len > of + 1 && nchar == '=')
		{
			outbuf->iov_base = (char *)ptr + 2;
			outbuf->iov_len = len - 2;
			return 0;
		}

		of += len + 1;
	}

	return -1;
}

static char *scram_base64_encode(const struct iovec *in)
{
	char *ret;
	size_t ret_len, max_len;

	if (in->iov_len > INT_MAX)
		return NULL;

	max_len = (((in->iov_len + 2) / 3) * 4) + 1;
	ret = malloc(max_len);
	if (!ret)
		return NULL;

	ret_len = EVP_EncodeBlock((uint8_t *)ret, (uint8_t *)in->iov_base,
							  (int)in->iov_len);
	if (ret_len >= max_len)
	{
		free(ret);
		return NULL;
	}
	ret[ret_len] = 0;

	return ret;
}

static int scram_base64_decode(const struct iovec *in, struct iovec *out)
{
	size_t ret_len;

	if (in->iov_len % 4 != 0 || in->iov_len > INT_MAX)
		return -1;

	ret_len = ((in->iov_len / 4) * 3);
	out->iov_base = malloc(ret_len + 1);
	if (!out->iov_base)
		return -1;

	if (EVP_DecodeBlock((uint8_t*)out->iov_base, (uint8_t*)in->iov_base,
						(int)in->iov_len) == -1)
	{
		free(out->iov_base);
		out->iov_base = NULL;
		return -1;
	}

	if (in->iov_len > 1 && ((char *)(in->iov_base))[in->iov_len - 1] == '=')
	{
		if (in->iov_len > 2 && ((char *)(in->iov_base))[in->iov_len - 2] == '=')
			ret_len -= 2;
		else
			ret_len -= 1;
	}

	((char *)(out->iov_base))[ret_len] = '\0';
	out->iov_len = ret_len;

	return 0;
}

static int scram_hi(const EVP_MD *evp, int itcnt, const struct iovec *in,
					const struct iovec *salt, struct iovec *out)
{
	unsigned int  ressize = 0;
	unsigned char tempres[EVP_MAX_MD_SIZE];
	unsigned char tempdest[EVP_MAX_MD_SIZE];
	unsigned char *saltplus;
	int i, j;

	saltplus = alloca(salt->iov_len + 4);
	if (!saltplus)
		return -1;

	memcpy(saltplus, salt->iov_base, salt->iov_len);
	saltplus[salt->iov_len]	  = '\0';
	saltplus[salt->iov_len + 1] = '\0';
	saltplus[salt->iov_len + 2] = '\0';
	saltplus[salt->iov_len + 3] = '\1';

	if (!HMAC(evp, (const unsigned char *)in->iov_base, (int)in->iov_len,
			  saltplus, salt->iov_len + 4, tempres, &ressize))
	{
		return -1;
	}

	memcpy(out->iov_base, tempres, ressize);

	for (i = 1; i < itcnt; i++)
	{
		if (!HMAC(evp, (const unsigned char *)in->iov_base, (int)in->iov_len,
				  tempres, ressize, tempdest, NULL))
		{
			return -1;
		}

		for (j = 0; j < (int)ressize; j++)
		{
			((char *)(out->iov_base))[j] ^= tempdest[j];
			tempres[j] = tempdest[j];
		}
	}

	out->iov_len = ressize;
	return 0;
}

static int scram_hmac(const EVP_MD *evp, const struct iovec *key,
					  const struct iovec *str, struct iovec *out)
{
	unsigned int outsize;

	if (!HMAC(evp, (const unsigned char *)key->iov_base, (int)key->iov_len,
			  (const unsigned char *)str->iov_base, (int)str->iov_len,
			  (unsigned char *)out->iov_base, &outsize))
	{
		return -1;
	}

	out->iov_len = outsize;

	return 0;
}

static void scram_h(kafka_scram_t *scram, const struct iovec *str,
					struct iovec *out)
{
	scram->scram_h((const unsigned char *)str->iov_base, str->iov_len,
				  (unsigned char *)out->iov_base);
	out->iov_len = scram->scram_h_size;
}

static void scram_build_client_final_message_wo_proof(
		kafka_scram_t *scram, const struct iovec *snonce, struct iovec *out)
{
	const char *attr_c = "biws";

	out->iov_len = 9 + scram->cnonce.iov_len + snonce->iov_len;
	out->iov_base = malloc(out->iov_len + 1);
	if (out->iov_base)
	{
		snprintf((char *)out->iov_base, out->iov_len + 1, "c=%s,r=%.*s%.*s",
				 attr_c, (int)scram->cnonce.iov_len,
				 (char *)scram->cnonce.iov_base, (int)snonce->iov_len,
				 (char *)snonce->iov_base);
	}
}

static int scram_build_client_final_message(kafka_scram_t *scram, int itcnt,
											const struct iovec *salt,
											const struct iovec *server_first_msg,
											const struct iovec *server_nonce,
											struct iovec *out,
											const kafka_config_t *conf)
{
	char salted_pwd[EVP_MAX_MD_SIZE];
	char client_key[EVP_MAX_MD_SIZE];
	char server_key[EVP_MAX_MD_SIZE];
	char stored_key[EVP_MAX_MD_SIZE];
	char client_sign[EVP_MAX_MD_SIZE];
	char server_sign[EVP_MAX_MD_SIZE];
	char client_proof[EVP_MAX_MD_SIZE];
	struct iovec password_iov = {conf->password, strlen(conf->password)};
	struct iovec salted_pwd_iov = {salted_pwd, EVP_MAX_MD_SIZE};
	struct iovec client_key_verbatim_iov = {"Client Key", 10};
	struct iovec server_key_verbatim_iov = {"Server Key", 10};
	struct iovec client_key_iov = {client_key, EVP_MAX_MD_SIZE};
	struct iovec server_key_iov = {server_key, EVP_MAX_MD_SIZE};
	struct iovec stored_key_iov = {stored_key, EVP_MAX_MD_SIZE};
	struct iovec server_sign_iov = {server_sign, EVP_MAX_MD_SIZE};
	struct iovec client_sign_iov = {client_sign, EVP_MAX_MD_SIZE};
	struct iovec client_proof_iov = {client_proof, EVP_MAX_MD_SIZE};
	struct iovec client_final_msg_wo_proof_iov;
	struct iovec auth_message_iov;
	char *server_sign_b64, *client_proof_b64 = NULL;
	int i;

	if (scram_hi((const EVP_MD *)scram->evp, itcnt, &password_iov, salt,
				 &salted_pwd_iov) == -1)
		return -1;

	if (scram_hmac((const EVP_MD *)scram->evp, &salted_pwd_iov,
				   &client_key_verbatim_iov, &client_key_iov) == -1)
		return -1;

	scram_h(scram, &client_key_iov, &stored_key_iov);

	scram_build_client_final_message_wo_proof(scram, server_nonce,
											  &client_final_msg_wo_proof_iov);

	auth_message_iov.iov_len = scram->first_msg.iov_len + 1 +
		server_first_msg->iov_len + 1 + client_final_msg_wo_proof_iov.iov_len;
	auth_message_iov.iov_base = alloca(auth_message_iov.iov_len + 1);
	if (auth_message_iov.iov_base)
	{
		snprintf(auth_message_iov.iov_base, auth_message_iov.iov_len + 1,
				 "%.*s,%.*s,%.*s",
				 (int)scram->first_msg.iov_len,
				 (char *)scram->first_msg.iov_base,
				 (int)server_first_msg->iov_len,
				 (char *)server_first_msg->iov_base,
				 (int)client_final_msg_wo_proof_iov.iov_len,
				 (char *)client_final_msg_wo_proof_iov.iov_base);

		if (scram_hmac((const EVP_MD *)scram->evp, &salted_pwd_iov,
					   &server_key_verbatim_iov, &server_key_iov) == 0 &&
			scram_hmac((const EVP_MD *)scram->evp, &server_key_iov,
					   &auth_message_iov, &server_sign_iov) == 0)
		{
			server_sign_b64 = scram_base64_encode(&server_sign_iov);
			if (server_sign_b64 &&
				scram_hmac((const EVP_MD *)scram->evp, &stored_key_iov,
						   &auth_message_iov, &client_sign_iov) ==0 &&
				client_key_iov.iov_len == client_sign_iov.iov_len)
			{
				scram->server_signature_b64.iov_base = server_sign_b64;
				scram->server_signature_b64.iov_len = strlen(server_sign_b64);
				for (i = 0 ; i < (int)client_key_iov.iov_len; i++)
					((char *)(client_proof_iov.iov_base))[i] =
						((char *)(client_key_iov.iov_base))[i] ^
						((char *)(client_sign_iov.iov_base))[i];
				client_proof_iov.iov_len = client_key_iov.iov_len;

				client_proof_b64 = scram_base64_encode(&client_proof_iov);
				if (client_proof_b64)
				{
					out->iov_len = client_final_msg_wo_proof_iov.iov_len + 3 +
						strlen(client_proof_b64);
					out->iov_base = malloc(out->iov_len + 1);

					snprintf((char *)out->iov_base, out->iov_len + 1, "%.*s,p=%s",
							 (int)client_final_msg_wo_proof_iov.iov_len,
							 (char *)client_final_msg_wo_proof_iov.iov_base,
							 client_proof_b64);
				}
			}
		}
	}

	free(client_proof_b64);
	free(client_final_msg_wo_proof_iov.iov_base);
	return 0;
}

static int scram_handle_server_first_message(const char *buf, size_t len,
											 kafka_config_t *conf,
											 kafka_sasl_t *sasl)
{
	int itcnt;
	int ret = -1;
	const char *endptr;
	struct iovec out, salt, server_nonce;
	const struct iovec in = {(void *)buf, len};

	if (scram_get_attr(&in, 'm', &out) == 0)
		return -1;

	if (scram_get_attr(&in, 'r', &server_nonce) != 0)
		return -1;

	if (server_nonce.iov_len <= sasl->scram.cnonce.iov_len ||
		memcmp(server_nonce.iov_base, sasl->scram.cnonce.iov_base,
			   sasl->scram.cnonce.iov_len) != 0)
	{
		return -1;
	}

	if (scram_get_attr(&in, 's', &out) != 0)
		return -1;

	if (scram_base64_decode(&out, &salt) != 0)
		return -1;

	if (scram_get_attr(&in, 'i', &out) == 0)
	{
		itcnt = (int)strtoul((const char *)out.iov_base, (char **)&endptr, 10);
		if ((const char *)out.iov_base != endptr && *endptr == '\0' &&
			itcnt <= 1000000)
		{
			ret = scram_build_client_final_message(&sasl->scram, itcnt, &salt,
												   &in, &server_nonce, &out,
												   conf);
			if (ret == 0)
			{
				free(sasl->buf);
				sasl->buf = out.iov_base;
				sasl->bsize = out.iov_len;
			}
		}
	}

	free(salt.iov_base);
	return ret;
}

static int scram_handle_server_final_message(const char *buf, size_t len,
											 kafka_config_t *conf,
											 kafka_sasl_t *sasl)
{
	struct iovec attr_v, attr_e;
	const struct iovec in = {(void *)buf, len};

	if (scram_get_attr(&in, 'm', &attr_e) == 0)
		return -1;

	if (scram_get_attr(&in, 'v', &attr_v) == 0)
	{
		if (sasl->scram.server_signature_b64.iov_len == attr_v.iov_len &&
			strncmp((const char *)sasl->scram.server_signature_b64.iov_base,
					(const char *)attr_v.iov_base, attr_v.iov_len) != 0)
		{
			return -1;
		}
	}

	return 0;
}

static int kafka_sasl_scram_recv(const char *buf, size_t len, void *p, void *q)
{
	kafka_config_t *conf = (kafka_config_t *)p;
	kafka_sasl_t *sasl = (kafka_sasl_t *)q;
	int ret = -1;

	switch(sasl->scram.state)
	{
	case KAFKA_SASL_SCRAM_STATE_SERVER_FIRST_MESSAGE:
		ret = scram_handle_server_first_message(buf, len, conf, sasl);
		sasl->scram.state = KAFKA_SASL_SCRAM_STATE_CLIENT_FINAL_MESSAGE;
		break;

	case KAFKA_SASL_SCRAM_STATE_CLIENT_FINAL_MESSAGE:
		ret = scram_handle_server_final_message(buf, len, conf, sasl);
		sasl->scram.state = KAFKA_SASL_SCRAM_STATE_CLIENT_FINISHED;
		break;

	default:
		break;
	}

	return ret;
}

static int jitter(int low, int high)
{
	return (low + (rand() % ((high - low) + 1)));
}

static int scram_generate_nonce(struct iovec *iov)
{
	int i;
	char *ptr = (char *)malloc(33);

	if (!ptr)
		return -1;

	for (i = 0; i < 32; i++)
		ptr[i] = jitter(0x2d, 0x7e);
	ptr[32] = '\0';

	iov->iov_base = ptr;
	iov->iov_len = 32;
	return 0;
}

static int kafka_sasl_scram_client_new(void *p, kafka_sasl_t *sasl)
{
	kafka_config_t *conf = (kafka_config_t *)p;
	size_t ulen = strlen(conf->username);
	size_t tlen = strlen("n,,n=,r=");
	size_t olen = ulen + tlen + 32;
	void *ptr;

	if (sasl->scram.state != KAFKA_SASL_SCRAM_STATE_CLIENT_FIRST_MESSAGE)
		return -1;

	if (scram_generate_nonce(&sasl->scram.cnonce) != 0)
		return -1;

	ptr = malloc(olen + 1);
	if (!ptr)
		return -1;

	snprintf(ptr, olen + 1, "n,,n=%s,r=%.*s", conf->username,
			(int)sasl->scram.cnonce.iov_len,
			(char *)sasl->scram.cnonce.iov_base);
	sasl->buf = ptr;
	sasl->bsize = olen;

	sasl->scram.first_msg.iov_base = (char *)ptr + 3;
	sasl->scram.first_msg.iov_len = olen - 3;
	sasl->scram.state = KAFKA_SASL_SCRAM_STATE_SERVER_FIRST_MESSAGE;
	return 0;
}

int kafka_sasl_set_mechanisms(kafka_config_t *conf)
{
	if (strcasecmp(conf->mechanisms, "plain") == 0)
	{
		conf->recv = kafka_sasl_plain_recv;
		conf->client_new = kafka_sasl_plain_client_new;

		return 0;
	}
	else if (strncasecmp(conf->mechanisms, "SCRAM", 5) == 0)
	{
		conf->recv = kafka_sasl_scram_recv;
		conf->client_new = kafka_sasl_scram_client_new;
	}

	return -1;
}

void kafka_sasl_init(kafka_sasl_t *sasl)
{
	sasl->scram.evp = NULL;
	sasl->scram.scram_h = NULL;
	sasl->scram.scram_h_size = 0;
	sasl->scram.state = KAFKA_SASL_SCRAM_STATE_CLIENT_FIRST_MESSAGE;
	sasl->scram.cnonce.iov_base = NULL;
	sasl->scram.cnonce.iov_len = 0;
	sasl->scram.first_msg.iov_base = NULL;
	sasl->scram.first_msg.iov_len = 0;
	sasl->scram.server_signature_b64.iov_base = NULL;
	sasl->scram.server_signature_b64.iov_len = 0;
	sasl->buf = NULL;
	sasl->bsize = 0;
	sasl->status = 0;
}

void kafka_sasl_deinit(kafka_sasl_t *sasl)
{
	free(sasl->scram.cnonce.iov_base);
	free(sasl->scram.server_signature_b64.iov_base);
	free(sasl->buf);
}

int kafka_sasl_set_username(const char *username, kafka_config_t *conf)
{
	char *t = strdup(username);

	if (!t)
		return -1;

	free(conf->username);
	conf->username = t;
	return 0;
}

int kafka_sasl_set_password(const char *password, kafka_config_t *conf)
{
	char *t = strdup(password);

	if (!t)
		return -1;

	free(conf->password);
	conf->password = t;
	return 0;
}

