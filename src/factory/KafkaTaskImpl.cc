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
*/

#include <assert.h>
#include <stdio.h>
#include <string>
#include <set>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "StringUtil.h"
#include "KafkaTaskImpl.inl"

using namespace protocol;

#define KAFKA_KEEPALIVE_DEFAULT	(60 * 1000)
#define KAFKA_ROUNDTRIP_TIMEOUT (5 * 1000)

static KafkaCgroup __create_cgroup(const KafkaCgroup *c)
{
	KafkaCgroup g;
	const char *member_id = c->get_member_id();

	if (member_id)
		g.set_member_id(member_id);

	g.set_group(c->get_group());

	return g;
}

/**********Client**********/

class __ComplexKafkaTask : public WFComplexClientTask<KafkaRequest, KafkaResponse, int>
{
public:
	__ComplexKafkaTask(int retry_max, __kafka_callback_t&& callback) :
		WFComplexClientTask(retry_max, std::move(callback))
	{
		is_user_request_ = true;
		is_redirect_ = false;
		ctx_ = 0;
	}

protected:
	virtual CommMessageOut *message_out();
	virtual CommMessageIn *message_in();
	virtual bool init_success();
	virtual bool finish_once();

private:
	struct KafkaConnectionInfo
	{
		kafka_api_t api;
		kafka_sasl_t sasl;
		std::string mechanisms;

		KafkaConnectionInfo()
		{
			kafka_api_init(&this->api);
			kafka_sasl_init(&this->sasl);
		}

		~KafkaConnectionInfo()
		{
			kafka_api_deinit(&this->api);
			kafka_sasl_deinit(&this->sasl);
		}

		bool init(const char *mechanisms)
		{
			this->mechanisms = mechanisms;

			if (strncasecmp(mechanisms, "SCRAM", 5) == 0)
			{
				if (strcasecmp(mechanisms, "SCRAM-SHA-1") == 0)
				{
					this->sasl.scram.evp = EVP_sha1();
					this->sasl.scram.scram_h = SHA1;
					this->sasl.scram.scram_h_size = SHA_DIGEST_LENGTH;
				}
				else if (strcasecmp(mechanisms, "SCRAM-SHA-256") == 0)
				{
					this->sasl.scram.evp = EVP_sha256();
					this->sasl.scram.scram_h = SHA256;
					this->sasl.scram.scram_h_size = SHA256_DIGEST_LENGTH;
				}
				else if (strcasecmp(mechanisms, "SCRAM-SHA-512") == 0)
				{
					this->sasl.scram.evp = EVP_sha512();
					this->sasl.scram.scram_h = SHA512;
					this->sasl.scram.scram_h_size = SHA512_DIGEST_LENGTH;
				}
				else
					return false;
			}

			return true;
		}
	};

	virtual int keep_alive_timeout();
	virtual int first_timeout();
	bool has_next();
	bool process_produce();
	bool process_fetch();
	bool process_metadata();
	bool process_list_offsets();
	bool process_find_coordinator();
	bool process_join_group();
	bool process_sync_group();
	bool process_sasl_authenticate();
	bool process_sasl_handshake();

	bool is_user_request_;
	bool is_redirect_;
	std::string user_info_;
};

CommMessageOut *__ComplexKafkaTask::message_out()
{
	long long seqid = this->get_seq();
	if (seqid == 0)
	{
		KafkaConnectionInfo *conn_info = new KafkaConnectionInfo;

		this->get_req()->set_api(&conn_info->api);
		this->get_connection()->set_context(conn_info, [](void *ctx) {
			delete (KafkaConnectionInfo *)ctx;
		});

		if (!this->get_req()->get_config()->get_broker_version())
		{
			KafkaRequest *req  = new KafkaRequest;
			req->duplicate(*this->get_req());
			req->set_api_type(Kafka_ApiVersions);
			is_user_request_ = false;
			return req;
		}
		else
		{
			kafka_api_version_t *api;
			size_t api_cnt;
			const char *v = this->get_req()->get_config()->get_broker_version();
			int ret = kafka_api_version_is_queryable(v, &api, &api_cnt);
			kafka_api_version_t *p = NULL;

			if (ret == 0)
			{
				p = (kafka_api_version_t *)malloc(api_cnt * sizeof(*p));
				if (p)
				{
					memcpy(p, api, api_cnt * sizeof(kafka_api_version_t));
					conn_info->api.api = p;
					conn_info->api.elements = api_cnt;
					conn_info->api.features = kafka_get_features(p, api_cnt);
				}
			}

			if (!p)
				return NULL;

			seqid++;
		}
	}

	if (seqid == 1)
	{
		const char *sasl_mech = this->get_req()->get_config()->get_sasl_mech();
		KafkaConnectionInfo *conn_info =
			(KafkaConnectionInfo *)this->get_connection()->get_context();
		if (sasl_mech && conn_info->sasl.status == 0)
		{
			if (!conn_info->init(sasl_mech))
				return NULL;

			this->get_req()->set_api(&conn_info->api);
			this->get_req()->set_sasl(&conn_info->sasl);

			KafkaRequest *req  = new KafkaRequest;
			req->duplicate(*this->get_req());
			if (conn_info->api.features & KAFKA_FEATURE_SASL_HANDSHAKE)
				req->set_api_type(Kafka_SaslHandshake);
			else
				req->set_api_type(Kafka_SaslAuthenticate);
			req->set_correlation_id(1);
			is_user_request_ = false;
			return req;
		}
	}

	KafkaConnectionInfo *conn_info =
		(KafkaConnectionInfo *)this->get_connection()->get_context();
	this->get_req()->set_api(&conn_info->api);

	if (this->get_req()->get_api_type() == Kafka_Fetch ||
		this->get_req()->get_api_type() == Kafka_ListOffsets)
	{
		KafkaRequest *req = this->get_req();
		req->get_toppar_list()->rewind();
		KafkaToppar *toppar;
		KafkaTopparList toppar_list;
		bool flag = false;

		while ((toppar = req->get_toppar_list()->get_next()) != NULL)
		{
			if (toppar->get_low_watermark() < 0)
				toppar->set_offset_timestamp(KAFKA_TIMESTAMP_EARLIEST);
			else if (toppar->get_high_watermark() < 0)
				toppar->set_offset_timestamp(KAFKA_TIMESTAMP_LATEST);
			else if (toppar->get_offset() == KAFKA_OFFSET_UNINIT)
			{
				long long conf_ts =
					this->get_req()->get_config()->get_offset_timestamp();
				if (conf_ts == KAFKA_TIMESTAMP_EARLIEST)
				{
					toppar->set_offset(toppar->get_low_watermark());
					continue;
				}
				else if (conf_ts == KAFKA_TIMESTAMP_LATEST)
				{
					toppar->set_offset(toppar->get_high_watermark());
					continue;
				}
				else
				{
					toppar->set_offset_timestamp(conf_ts);
				}
			}
			else if (toppar->get_offset() == KAFKA_OFFSET_OVERFLOW)
			{
				if (this->get_req()->get_config()->get_offset_timestamp() ==
					KAFKA_TIMESTAMP_EARLIEST)
				{
					toppar->set_offset(toppar->get_low_watermark());
				}
				else
				{
					toppar->set_offset(toppar->get_high_watermark());
				}
				continue;
			}
			else
			{
				continue;
			}

			toppar_list.add_item(*toppar);
			flag = true;
		}

		if (flag)
		{
			KafkaRequest *new_req = new KafkaRequest;
			new_req->set_api(&conn_info->api);
			new_req->set_broker(*req->get_broker());
			new_req->set_toppar_list(toppar_list);
			new_req->set_config(*req->get_config());
			new_req->set_api_type(Kafka_ListOffsets);
			new_req->set_correlation_id(seqid);
			is_user_request_ = false;
			return new_req;
		}
	}

	this->get_req()->set_correlation_id(seqid);
	return this->WFComplexClientTask::message_out();
}

CommMessageIn *__ComplexKafkaTask::message_in()
{
	KafkaRequest *req = static_cast<KafkaRequest *>(this->get_message_out());
	KafkaResponse *resp = this->get_resp();
	KafkaCgroup *cgroup;

	resp->set_api_type(req->get_api_type());
	resp->set_api_version(req->get_api_version());
	resp->duplicate(*req);

	switch (req->get_api_type())
	{
	case Kafka_FindCoordinator:
	case Kafka_Heartbeat:
		cgroup = req->get_cgroup();
		if (cgroup->get_group())
			resp->set_cgroup(__create_cgroup(cgroup));
		break;
	default:
		break;
	}

	return this->WFComplexClientTask::message_in();
}

bool __ComplexKafkaTask::init_success()
{
	enum TransportType type;

	if (uri_.scheme && strcasecmp(uri_.scheme, "kafka") == 0)
		type = TT_TCP;
	else if (uri_.scheme && strcasecmp(uri_.scheme, "kafkas") == 0)
		type = TT_TCP_SSL;
	else
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_SCHEME_INVALID;
		return false;
	}

	std::string username, password, sasl, client;
	if (uri_.userinfo)
	{
		const char *pos = strchr(uri_.userinfo, ':');
		if (pos)
		{
			username = std::string(uri_.userinfo, pos - uri_.userinfo);
			StringUtil::url_decode(username);
			const char *pos1 = strchr(pos + 1, ':');
			if (pos1)
			{
				password = std::string(pos + 1, pos1 - pos - 1);
				StringUtil::url_decode(password);
				const char *pos2 = strchr(pos1 + 1, ':');
				if (pos2)
				{
					sasl = std::string(pos1 + 1, pos2 - pos1 - 1);
					client = std::string(pos1 + 1);
				}
			}
		}

		if (username.empty() || password.empty() || sasl.empty() || client.empty())
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_URI_SCHEME_INVALID;
			return false;
		}

		user_info_ = uri_.userinfo;
		size_t info_len = username.size() + password.size() + sasl.size() +
			client.size() + 50;
		char *info = new char[info_len];

		snprintf(info, info_len, "%s|user:%s|pass:%s|sasl:%s|client:%s|", "kafka",
				username.c_str(), password.c_str(), sasl.c_str(), client.c_str());

		this->WFComplexClientTask::set_info(info);
		delete []info;
	}

	this->WFComplexClientTask::set_transport_type(type);
	return true;
}

int __ComplexKafkaTask::keep_alive_timeout()
{
	if (this->get_resp()->get_broker()->get_error())
		return 0;

	return this->WFComplexClientTask::keep_alive_timeout();
}

int __ComplexKafkaTask::first_timeout()
{
	KafkaRequest *client_req = this->get_req();
	int ret = 0;

	switch(client_req->get_api_type())
	{
	case Kafka_Fetch:
		ret = client_req->get_config()->get_fetch_timeout();
		break;

	case Kafka_JoinGroup:
		ret = client_req->get_config()->get_session_timeout();
		break;

	case Kafka_SyncGroup:
		ret = client_req->get_config()->get_rebalance_timeout();
		break;

	case Kafka_Produce:
		ret = client_req->get_config()->get_produce_timeout();
		break;

	default:
		return 0;
	}

	return ret + KAFKA_ROUNDTRIP_TIMEOUT;
}

bool __ComplexKafkaTask::process_find_coordinator()
{
	KafkaCgroup *cgroup = this->get_resp()->get_cgroup();
	ctx_ = cgroup->get_error();
	if (ctx_)
	{
		this->error = WFT_ERR_KAFKA_CGROUP_FAILED;
		this->state = WFT_STATE_TASK_ERROR;
		return false;
	}
	else
	{
		this->get_req()->set_cgroup(*cgroup);
		KafkaBroker *coordinator = cgroup->get_coordinator();
		std::string url(uri_.scheme);
		url += "://";
		url += user_info_ + "@";
		url += coordinator->get_host();
		url += ":" + std::to_string(coordinator->get_port());

		ParsedURI uri;
		URIParser::parse(url, uri);
		set_redirect(std::move(uri));
		this->get_req()->set_api_type(Kafka_JoinGroup);
		is_redirect_ = true;
		return true;
	}
}

bool __ComplexKafkaTask::process_join_group()
{
	KafkaResponse *msg = this->get_resp();
	switch(msg->get_cgroup()->get_error())
	{
	case KAFKA_MEMBER_ID_REQUIRED:
		this->get_req()->set_api_type(Kafka_JoinGroup);
		break;

	case KAFKA_UNKNOWN_MEMBER_ID:
		msg->get_cgroup()->set_member_id("");
		this->get_req()->set_api_type(Kafka_JoinGroup);
		break;

	case 0:
		this->get_req()->set_api_type(Kafka_Metadata);
		break;

	default:
		ctx_ = msg->get_cgroup()->get_error();
		this->error = WFT_ERR_KAFKA_CGROUP_FAILED;
		this->state = WFT_STATE_TASK_ERROR;
		return false;
	}

	return true;
}

bool __ComplexKafkaTask::process_sync_group()
{
	ctx_ = this->get_resp()->get_cgroup()->get_error();
	if (ctx_)
	{
		this->error = WFT_ERR_KAFKA_CGROUP_FAILED;
		this->state = WFT_STATE_TASK_ERROR;
		return false;
	}
	else
	{
		this->get_req()->set_api_type(Kafka_OffsetFetch);
		return true;
	}
}

bool __ComplexKafkaTask::process_metadata()
{
	KafkaResponse *msg = this->get_resp();
	msg->get_meta_list()->rewind();
	KafkaMeta *meta;
	while ((meta = msg->get_meta_list()->get_next()) != NULL)
	{
		switch (meta->get_error())
		{
		case KAFKA_LEADER_NOT_AVAILABLE:
			this->get_req()->set_api_type(Kafka_Metadata);
			return true;
		case 0:
			break;
		default:
			ctx_ = meta->get_error();
			this->error = WFT_ERR_KAFKA_META_FAILED;
			this->state = WFT_STATE_TASK_ERROR;
			return false;
		}
	}

	this->get_req()->set_meta_list(*msg->get_meta_list());
	if (msg->get_cgroup()->get_group())
	{
		if (msg->get_cgroup()->is_leader())
		{
			KafkaCgroup *cgroup = msg->get_cgroup();
			if (cgroup->run_assignor(msg->get_meta_list(),
									 cgroup->get_protocol_name()) < 0)
			{
				this->error = WFT_ERR_KAFKA_CGROUP_ASSIGN_FAILED;
				this->state = WFT_STATE_TASK_ERROR;
				return false;
			}
		}

		this->get_req()->set_api_type(Kafka_SyncGroup);
		return true;
	}

	return false;
}

bool __ComplexKafkaTask::process_fetch()
{
	bool ret = false;
	KafkaToppar *toppar;
	this->get_resp()->get_toppar_list()->rewind();
	while ((toppar = this->get_resp()->get_toppar_list()->get_next()) != NULL)
	{
		if (toppar->get_error() == KAFKA_OFFSET_OUT_OF_RANGE &&
			toppar->get_high_watermark() - toppar->get_low_watermark() > 0)
		{
			toppar->set_offset(KAFKA_OFFSET_OVERFLOW);
			toppar->set_low_watermark(KAFKA_OFFSET_UNINIT);
			toppar->set_high_watermark(KAFKA_OFFSET_UNINIT);
			ret = true;
		}

		switch (toppar->get_error())
		{
		case KAFKA_UNKNOWN_TOPIC_OR_PARTITION:
		case KAFKA_LEADER_NOT_AVAILABLE:
		case KAFKA_NOT_LEADER_FOR_PARTITION:
		case KAFKA_BROKER_NOT_AVAILABLE:
		case KAFKA_REPLICA_NOT_AVAILABLE:
		case KAFKA_KAFKA_STORAGE_ERROR:
		case KAFKA_FENCED_LEADER_EPOCH:
			this->get_req()->set_api_type(Kafka_Metadata);
			return true;
		case 0:
		case KAFKA_OFFSET_OUT_OF_RANGE:
			break;
		default:
			ctx_ = toppar->get_error();
			this->error = WFT_ERR_KAFKA_FETCH_FAILED;
			this->state = WFT_STATE_TASK_ERROR;
			return false;
		}
	}
	return ret;
}

bool __ComplexKafkaTask::process_list_offsets()
{
	KafkaToppar *toppar;
	this->get_resp()->get_toppar_list()->rewind();
	while ((toppar = this->get_resp()->get_toppar_list()->get_next()) != NULL)
	{
		if (toppar->get_error())
		{
			this->error = toppar->get_error();
			this->state = WFT_STATE_TASK_ERROR;
		}
	}
	return false;
}

bool __ComplexKafkaTask::process_produce()
{
	KafkaToppar *toppar;
	this->get_resp()->get_toppar_list()->rewind();
	while ((toppar = this->get_resp()->get_toppar_list()->get_next()) != NULL)
	{
		if (!toppar->record_reach_end())
		{
			this->get_req()->set_api_type(Kafka_Produce);
			return true;
		}

		switch (toppar->get_error())
		{
		case KAFKA_UNKNOWN_TOPIC_OR_PARTITION:
		case KAFKA_LEADER_NOT_AVAILABLE:
		case KAFKA_NOT_LEADER_FOR_PARTITION:
		case KAFKA_BROKER_NOT_AVAILABLE:
		case KAFKA_REPLICA_NOT_AVAILABLE:
		case KAFKA_KAFKA_STORAGE_ERROR:
		case KAFKA_FENCED_LEADER_EPOCH:
			this->get_req()->set_api_type(Kafka_Metadata);
			return true;
		case 0:
			break;
		default:
			this->error = toppar->get_error();
			this->state = WFT_STATE_TASK_ERROR;
			return false;
		}
	}
	return false;
}

bool __ComplexKafkaTask::process_sasl_handshake()
{
	ctx_ = this->get_resp()->get_broker()->get_error();
	if (ctx_)
	{
		this->error = WFT_ERR_KAFKA_SASL_DISALLOWED;
		this->state = WFT_STATE_TASK_ERROR;
		return false;
	}
	return true;
}

bool __ComplexKafkaTask::process_sasl_authenticate()
{
	ctx_ = this->get_resp()->get_broker()->get_error();
	if (ctx_)
	{
		this->error = WFT_ERR_KAFKA_SASL_DISALLOWED;
		this->state = WFT_STATE_TASK_ERROR;
	}
	return false;
}

bool __ComplexKafkaTask::has_next()
{
	switch (this->get_resp()->get_api_type())
	{
	case Kafka_Produce:
		return this->process_produce();
	case Kafka_Fetch:
		return this->process_fetch();
	case Kafka_Metadata:
		return this->process_metadata();
	case Kafka_FindCoordinator:
		return this->process_find_coordinator();
	case Kafka_JoinGroup:
		return this->process_join_group();
	case Kafka_SyncGroup:
		return this->process_sync_group();
	case Kafka_SaslHandshake:
		return this->process_sasl_handshake();
	case Kafka_SaslAuthenticate:
		return this->process_sasl_authenticate();
	case Kafka_ListOffsets:
		return this->process_list_offsets();
	case Kafka_OffsetCommit:
	case Kafka_OffsetFetch:
	case Kafka_LeaveGroup:
	case Kafka_DescribeGroups:
	case Kafka_Heartbeat:
		ctx_ = this->get_resp()->get_cgroup()->get_error();
		if (ctx_)
		{
			this->error = WFT_ERR_KAFKA_CGROUP_FAILED;
			this->state = WFT_STATE_TASK_ERROR;
		}

		break;
	case Kafka_ApiVersions:
		break;
	default:
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_KAFKA_API_UNKNOWN;
		break;
	}
	return false;
}

bool __ComplexKafkaTask::finish_once()
{
	bool finish = true;
	if (this->state == WFT_STATE_SUCCESS)
		finish = !has_next();

	if (!is_user_request_)
	{
		delete this->get_message_out();
		this->get_resp()->clear_buf();
	}

	if (is_redirect_ && this->state == WFT_STATE_UNDEFINED)
	{
		this->get_req()->clear_buf();
		is_redirect_ = false;
		return true;
	}

	if (this->state == WFT_STATE_SUCCESS)
	{
		if (!is_user_request_)
		{
			is_user_request_ = true;
			return false;
		}

		if (!finish)
		{
			this->get_req()->clear_buf();
			this->get_resp()->clear_buf();
			return false;
		}
	}
	else
	{
		this->get_resp()->set_api_type(this->get_req()->get_api_type());
		this->get_resp()->set_api_version(this->get_req()->get_api_version());
	}

	return true;
}

/**********Factory**********/
// kafka://user:password:sasl@host:port/api=type&topic=name
__WFKafkaTask *__WFKafkaTaskFactory::create_kafka_task(const std::string& url,
													   int retry_max,
													   __kafka_callback_t callback)
{
	auto *task = new __ComplexKafkaTask(retry_max, std::move(callback));
	ParsedURI uri;

	URIParser::parse(url, uri);
	task->init(std::move(uri));
	task->set_keep_alive(KAFKA_KEEPALIVE_DEFAULT);
	return task;
}

__WFKafkaTask *__WFKafkaTaskFactory::create_kafka_task(const ParsedURI& uri,
													   int retry_max,
													   __kafka_callback_t callback)
{
	auto *task = new __ComplexKafkaTask(retry_max, std::move(callback));

	task->init(uri);
	task->set_keep_alive(KAFKA_KEEPALIVE_DEFAULT);
	return task;
}

__WFKafkaTask *__WFKafkaTaskFactory::create_kafka_task(enum TransportType type,
													   const char *host,
													   unsigned short port,
													   const std::string& info,
													   int retry_max,
													   __kafka_callback_t callback)
{
	auto *task = new __ComplexKafkaTask(retry_max, std::move(callback));

	std::string url = (type == TT_TCP_SSL ? "kafkas://" : "kafka://");

	if (!info.empty())
		url += info + "@";

	url += host;
	url += ":" + std::to_string(port);

	ParsedURI uri;
	URIParser::parse(url, uri);
	task->init(std::move(uri));
	task->set_keep_alive(KAFKA_KEEPALIVE_DEFAULT);
	return task;
}

