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

/**********Client**********/

class __ComplexKafkaTask : public WFComplexClientTask<KafkaRequest, KafkaResponse, std::function<void (__WFKafkaTask *)>>
{
public:
	__ComplexKafkaTask(int retry_max, __kafka_callback_t&& callback) :
		WFComplexClientTask(retry_max, std::move(callback))
	{
		update_metadata_ = false;
		is_user_request_ = true;
		is_redirect_ = false;
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

	virtual int first_timeout();
	bool has_next();
	bool check_redirect();

	bool update_metadata_;
	bool is_user_request_;
	bool is_redirect_;
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
			is_user_request_ = false;
			return req;
		}
	}

	KafkaConnectionInfo *conn_info =
		(KafkaConnectionInfo *)this->get_connection()->get_context();
	this->get_req()->set_api(&conn_info->api);

	if (this->get_req()->get_api_type() == Kafka_Fetch)
	{
		KafkaRequest *req = this->get_req();
		req->get_toppar_list()->rewind();
		KafkaToppar *toppar;
		KafkaTopparList toppar_list;
		bool flag = false;

		while ((toppar = req->get_toppar_list()->get_next()) != NULL)
		{
			if (toppar->get_offset() == -1)
			{
				if (toppar->get_offset_timestamp() == KAFKA_TIMESTAMP_UNINIT)
				{
					long long conf_ts = this->get_req()->get_config()->get_offset_timestamp();
					if (conf_ts != KAFKA_TIMESTAMP_UNINIT)
						toppar->set_offset_timestamp(conf_ts);
					else
						toppar->set_offset_timestamp(KAFKA_TIMESTAMP_EARLIEST);
				}
				else
					toppar->set_offset_timestamp(KAFKA_TIMESTAMP_LATEST);
			}
			else
				continue;

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
			is_user_request_ = false;
			return new_req;
		}
	}

	return this->WFComplexClientTask::message_out();
}

CommMessageIn *__ComplexKafkaTask::message_in()
{
	KafkaRequest *req = static_cast<KafkaRequest *>(this->get_message_out());
	KafkaResponse *resp = this->get_resp();

	resp->set_api_type(req->get_api_type());
	resp->set_api_version(req->get_api_version());
	resp->duplicate(*req);

	return this->WFComplexClientTask::message_in();
}

bool __ComplexKafkaTask::init_success()
{
	if (!uri_.scheme || strcasecmp(uri_.scheme, "kafka") != 0)
	{
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_URI_SCHEME_INVALID;
		return false;
	}

	std::string username, password, sasl;
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
				sasl = std::string(pos1 + 1);
			}
		}

		if (username.empty() || password.empty() || sasl.empty())
		{
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_URI_SCHEME_INVALID;
			return false;
		}
	}

	size_t info_len = username.size() + password.size() + sasl.size() + 50;
	char *info = new char[info_len];

	snprintf(info, info_len, "%s|user:%s|pass:%s|sasl:%s|", "kafka",
			 username.c_str(), password.c_str(), sasl.c_str());

	this->WFComplexClientTask::set_info(info);
	this->WFComplexClientTask::set_transport_type(TT_TCP);

	delete []info;
	return true;
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

bool __ComplexKafkaTask::check_redirect()
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof addr;
	const struct sockaddr *paddr = (const struct sockaddr *)&addr;
	KafkaBroker *coordinator = this->get_req()->get_cgroup()->get_coordinator();

	//always success
	this->get_peer_addr((struct sockaddr *)&addr, &addrlen);
	if (!coordinator->is_equal(paddr, addrlen))
	{
		if (coordinator->is_to_addr())
		{
			const struct sockaddr *addr_coord;
			socklen_t addrlen_coord;

			coordinator->get_broker_addr(&addr_coord, &addrlen_coord);
			set_redirect(TT_TCP, addr_coord, addrlen_coord, "");
		}
		else
		{
			std::string url = "kafka://";
			url += coordinator->get_host();
			url += ":" + std::to_string(coordinator->get_port());

			ParsedURI uri;
			URIParser::parse(url, uri);
			set_redirect(std::move(uri));
		}

		return true;
	}
	else
	{
		this->init(TT_TCP, paddr, addrlen, "");
		return false;
	}
}

bool __ComplexKafkaTask::has_next()
{
	bool ret = true;
	KafkaResponse *msg = this->get_resp();

	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof addr;
	const struct sockaddr *paddr = (const struct sockaddr *)&addr;

	//always success
	this->get_peer_addr((struct sockaddr *)&addr, &addrlen);

	if (!msg->get_broker()->is_to_addr())
	{
		msg->get_broker()->set_broker_addr(paddr, addrlen);
		msg->get_broker()->set_to_addr(1);
	}

	switch (msg->get_api_type())
	{
	case Kafka_FindCoordinator:
		if (msg->get_cgroup()->get_error())
		{
			this->error = msg->get_cgroup()->get_error();
			this->state = WFT_STATE_TASK_ERROR;
			ret = false;
		}
		else
		{
			is_redirect_ = check_redirect();
			this->get_req()->set_api_type(Kafka_JoinGroup);
		}

		break;

	case Kafka_JoinGroup:
		if (!msg->get_cgroup()->get_coordinator()->is_to_addr())
		{
			msg->get_cgroup()->get_coordinator()->set_broker_addr(paddr, addrlen);
			msg->get_cgroup()->get_coordinator()->set_to_addr(1);
		}

		if (msg->get_cgroup()->get_error() == KAFKA_MISSING_TOPIC)
		{
			this->get_req()->set_api_type(Kafka_Metadata);
			update_metadata_ = true;
		}
		else if (msg->get_cgroup()->get_error() == KAFKA_MEMBER_ID_REQUIRED)
		{
			this->get_req()->set_api_type(Kafka_JoinGroup);
		}
		else if (msg->get_cgroup()->get_error() == KAFKA_UNKNOWN_MEMBER_ID)
		{
			msg->get_cgroup()->set_member_id("");
			this->get_req()->set_api_type(Kafka_JoinGroup);
		}
		else if (msg->get_cgroup()->get_error())
		{
			this->error = msg->get_cgroup()->get_error();
			this->state = WFT_STATE_TASK_ERROR;
			ret = false;
		}
		else
			this->get_req()->set_api_type(Kafka_SyncGroup);

		break;

	case Kafka_SyncGroup:
		if (msg->get_cgroup()->get_error())
		{
			this->error = msg->get_cgroup()->get_error();
			this->state = WFT_STATE_TASK_ERROR;
			ret = false;
		}
		else
			this->get_req()->set_api_type(Kafka_OffsetFetch);

		break;

	case Kafka_Metadata:
		if (update_metadata_)
		{
			KafkaCgroup *cgroup = msg->get_cgroup();
			if (cgroup->run_assignor(msg->get_meta_list(),
									 cgroup->get_protocol_name()) < 0)
			{
				this->error = errno;
				this->state = WFT_STATE_TASK_ERROR;
			}
			else
				this->get_req()->set_api_type(Kafka_SyncGroup);
		}
		else
		{
			ret = false;
			msg->get_meta_list()->rewind();
			KafkaMeta *meta;

			while ((meta = msg->get_meta_list()->get_next()) != NULL)
			{
				if (meta->get_error() == KAFKA_LEADER_NOT_AVAILABLE)
				{
					ret = true;
					this->get_req()->set_api_type(Kafka_Metadata);
					break;
				}
			}
		}
		break;

	case Kafka_SaslHandshake:
		if (msg->get_broker()->get_error())
		{
			this->error = msg->get_broker()->get_error();
			this->state = WFT_STATE_TASK_ERROR;
			ret = false;
		}

		break;

	case Kafka_Produce:
		{
			msg->get_toppar_list()->rewind();
			KafkaToppar *toppar;
			while ((toppar = msg->get_toppar_list()->get_next()) != NULL)
			{
				if (!toppar->record_reach_end())
				{
					this->get_req()->set_api_type(Kafka_Produce);
					return true;
				}
			}
		}

	case Kafka_SaslAuthenticate:
		if (msg->get_broker()->get_error())
		{
			this->error = msg->get_broker()->get_error();
			this->state = WFT_STATE_TASK_ERROR;
		}

		ret = false;
		break;

	case Kafka_Fetch:
	case Kafka_OffsetCommit:
	case Kafka_OffsetFetch:
	case Kafka_ListOffsets:
	case Kafka_Heartbeat:
	case Kafka_LeaveGroup:
	case Kafka_ApiVersions:
		ret = false;
		break;

	default:
		ret = false;
		this->state = WFT_STATE_TASK_ERROR;
		this->error = WFT_ERR_KAFKA_API_UNKNOWN;
		break;
	}
	return ret;
}

bool __ComplexKafkaTask::finish_once()
{
	if (this->state == WFT_STATE_SUCCESS)
	{
		if (has_next())
		{
			if (!is_user_request_)
			{
				delete this->get_message_out();
				this->get_resp()->clear_buf();
				return false;
			}

			this->get_req()->clear_buf();
			if (is_redirect_)
			{
				is_redirect_ = false;
				return true;
			}

			this->clear_resp();
			return false;
		}

		if (!is_user_request_)
		{
			is_user_request_ = true;
			delete this->get_message_out();
			this->get_resp()->clear_buf();
			return false;
		}

		if (this->get_resp()->get_api_type() == Kafka_Fetch ||
			this->get_resp()->get_api_type() == Kafka_Produce ||
			this->get_resp()->get_api_type() == Kafka_ApiVersions)
		{
			if (*get_mutable_ctx())
				(*get_mutable_ctx())(this);
		}
	}
	else
	{
		this->disable_retry();

		this->get_resp()->set_api_type(this->get_req()->get_api_type());
		this->get_resp()->set_api_version(this->get_req()->get_api_version());
		this->get_resp()->duplicate(*this->get_req());

		if (*get_mutable_ctx())
			(*get_mutable_ctx())(this);
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

__WFKafkaTask *__WFKafkaTaskFactory::create_kafka_task(const struct sockaddr *addr,
													   socklen_t addrlen,
													   const std::string& info,
													   int retry_max,
													   __kafka_callback_t callback)
{
	auto *task = new __ComplexKafkaTask(retry_max, std::move(callback));

	task->init(TT_TCP, addr, addrlen, info);
	task->set_keep_alive(KAFKA_KEEPALIVE_DEFAULT);
	return task;
}

__WFKafkaTask *__WFKafkaTaskFactory::create_kafka_task(const char *host,
													   unsigned short port,
													   const std::string& info,
													   int retry_max,
													   __kafka_callback_t callback)
{
	auto *task = new __ComplexKafkaTask(retry_max, std::move(callback));

	std::string url = "kafka://";

	if (!info.empty())
		url += info;

	url += host;
	url += ":" + std::to_string(port);

	ParsedURI uri;
	URIParser::parse(url, uri);
	task->init(std::move(uri));
	task->set_keep_alive(KAFKA_KEEPALIVE_DEFAULT);
	return task;
}

