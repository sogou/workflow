/*
  Copyright (c) 2022 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Wang Zhenpeng (wangzhenpeng@sogou-inc.com)
*/

#include <string.h>
#include "json_parser.h"
#include "StringUtil.h"
#include "HttpUtil.h"
#include "WFConsulClient.h"

using namespace protocol;

WFConsulTask::WFConsulTask(const std::string& proxy_url,
						   const std::string& service_namespace,
						   const std::string& service_name,
						   const std::string& service_id,
						   int retry_max, consul_callback_t&& cb) :
	proxy_url(proxy_url),
	callback(std::move(cb))
{
	this->service.service_name = service_name;
	this->service.service_namespace = service_namespace;
	this->service.service_id = service_id;
	this->api_type = CONSUL_API_TYPE_UNKNOWN;
	this->retry_max = retry_max;
	this->finish = false;
	this->consul_index = 0;
}

void WFConsulTask::set_service(const struct protocol::ConsulService *service)
{
	this->service.tags = service->tags;
	this->service.meta = service->meta;
	this->service.tag_override = service->tag_override;
	this->service.service_address = service->service_address;
	this->service.lan = service->lan;
	this->service.lan_ipv4 = service->lan_ipv4;
	this->service.lan_ipv6 = service->lan_ipv6;
	this->service.virtual_address = service->virtual_address;
	this->service.wan = service->wan;
	this->service.wan_ipv4 = service->wan_ipv4;
	this->service.wan_ipv6 = service->wan_ipv6;
}

static bool parse_discover_result(const json_value_t *root,
							std::vector<struct ConsulServiceInstance>& result);
static bool parse_list_service_result(const json_value_t *root,
							std::vector<struct ConsulServiceTags>& result);

bool WFConsulTask::get_discover_result(
	std::vector<struct ConsulServiceInstance>& result)
{
	json_value_t *root;
	int errno_bak;
	bool ret;

	if (this->api_type != CONSUL_API_TYPE_DISCOVER)
	{
		errno = EPERM;
		return false;
	}

	errno_bak = errno;
	errno = EBADMSG;
	root = json_value_parse(this->discover_res.c_str());
	if (!root)
		return false;

	ret = parse_discover_result(root, result);
	json_value_destroy(root);

	if (ret)
		errno = errno_bak;

	return ret;
}

bool WFConsulTask::get_list_service_result(
	std::vector<struct ConsulServiceTags>& result)
{
	json_value_t *root;
	int errno_bak;
	bool ret;

	if (this->api_type != CONSUL_API_TYPE_LIST_SERVICE)
	{
		errno = EPERM;
		return false;
	}

	errno_bak = errno;
	errno = EBADMSG;
	root = json_value_parse(this->list_service_res.c_str());
	if (!root)
		return false;

	ret = parse_list_service_result(root, result);
	json_value_destroy(root);

	if (ret)
		errno = errno_bak;

	return ret;
}

void WFConsulTask::dispatch()
{
	WFHttpTask *task;

	if (this->finish)
	{
		this->subtask_done();
		return;
	}

	switch(this->api_type)
	{
	case CONSUL_API_TYPE_DISCOVER:
		task = create_discover_task();
		break;

	case CONSUL_API_TYPE_LIST_SERVICE:
		task = create_list_service_task();
		break;

	case CONSUL_API_TYPE_DEREGISTER:
		task = create_deregister_task();
		break;

	case CONSUL_API_TYPE_REGISTER:
		task = create_register_task();
		if (this->state == WFT_STATE_UNDEFINED)
			break;
		
		task->dismiss();
		if (0)
		{
	default:
			this->state = WFT_STATE_TASK_ERROR;
			this->error = WFT_ERR_CONSUL_API_UNKNOWN;
		}

		this->finish = true;
		this->subtask_done();
		return;
	}

	series_of(this)->push_front(this);
	series_of(this)->push_front(task);
	this->subtask_done();
}

SubTask *WFConsulTask::done()
{
	SeriesWork *series = series_of(this);

	if (finish)
	{
		if (this->callback)
			this->callback(this);

		delete this;
	}

	return series->pop();
}

static std::string convert_time_to_str(int milliseconds)
{
	std::string str_time;
	int seconds = milliseconds / 1000;

	if (seconds >= 180)
		str_time = std::to_string(seconds / 60) + "m";
	else
		str_time = std::to_string(seconds) + "s";

	return str_time;
}

std::string WFConsulTask::generate_discover_request()
{
	std::string url = this->proxy_url;

	url += "/v1/health/service/" + this->service.service_name;
	url += "?dc=" + this->config.get_datacenter();
	url += "&ns=" + this->service.service_namespace;
	std::string passing = this->config.get_passing() ? "true" : "false";
	url += "&passing=" + passing;
	url += "&token=" + this->config.get_token();
	url += "&filter=" + this->config.get_filter_expr();

	//consul blocking query
	if (this->config.blocking_query())
	{
		url += "&index=" + std::to_string(this->get_consul_index());
		url += "&wait=" + convert_time_to_str(this->config.get_wait_ttl());
	}

	return url;
}

WFHttpTask *WFConsulTask::create_discover_task()
{
	std::string url = generate_discover_request();
	WFHttpTask *task = WFTaskFactory::create_http_task(url, 0, this->retry_max,
													   discover_callback);
	HttpRequest *req = task->get_req();

	req->add_header_pair("Content-Type", "application/json");
	task->user_data = this;
	return task;
}

WFHttpTask *WFConsulTask::create_list_service_task()
{
	std::string url = this->proxy_url;

	url += "/v1/catalog/services?token=" + this->config.get_token();
	url += "&dc=" + this->config.get_datacenter();
	url += "&ns=" + this->service.service_namespace;
	
	WFHttpTask *task = WFTaskFactory::create_http_task(url, 0, this->retry_max,
													   list_service_callback);
	HttpRequest *req = task->get_req();

	req->add_header_pair("Content-Type", "application/json");
	task->user_data = this;
	return task;
}

static void print_json_value(const json_value_t *val, int depth,
							 std::string& json_str);

static bool create_register_request(const json_value_t *root,
									const struct ConsulService *service,
									const ConsulConfig& config);

WFHttpTask *WFConsulTask::create_register_task()
{
	std::string payload;
	bool ret = false;

	std::string url = this->proxy_url;
	url += "/v1/agent/service/register?replace-existing-checks=";
	std::string replace_checks =
					this->config.get_replace_checks() ? "true" : "false";
	url += replace_checks;

	WFHttpTask *task = WFTaskFactory::create_http_task(url, 0, this->retry_max,
													   register_callback);
	HttpRequest *req = task->get_req();

	req->set_method(HttpMethodPut);
	req->add_header_pair("Content-Type", "application/json");

	if (!this->config.get_token().empty())
		req->add_header_pair("X-Consul-Token", this->config.get_token());

	json_value_t *root = json_value_create(JSON_VALUE_OBJECT);
	if (root)
	{
		ret = create_register_request(root, &this->service, this->config);
		if (ret)
		{
			print_json_value(root, 0, payload);
			ret = req->append_output_body(payload);
		}

		json_value_destroy(root);
	}

	if (!ret)
	{
		this->state = WFT_STATE_SYS_ERROR;
		this->error = errno;
	}

	task->user_data = this;
	return task;
}

WFHttpTask *WFConsulTask::create_deregister_task()
{
	std::string url = this->proxy_url;

	url += "/v1/agent/service/deregister/" + this->service.service_id;
	url += "?ns=" + this->service.service_namespace;

	WFHttpTask *task = WFTaskFactory::create_http_task(url, 0, this->retry_max,
													   register_callback);
	HttpRequest *req = task->get_req();

	req->set_method(HttpMethodPut);
	req->add_header_pair("Content-Type", "application/json");
	
	std::string token = this->config.get_token();
	if (!token.empty())
		req->add_header_pair("X-Consul-Token", token);

	task->user_data = this;
	return task;
}

bool WFConsulTask::check_task_result(WFHttpTask *task, WFConsulTask *consul_task)
{
	if (task->get_state() != WFT_STATE_SUCCESS)
	{
		consul_task->state = task->get_state();
		consul_task->error = task->get_error();
		return false;
	}

	protocol::HttpResponse *resp = task->get_resp();
	int http_code = atoi(resp->get_status_code());
	if (http_code < 200 || http_code >= 400)
	{
		consul_task->state = WFT_STATE_TASK_ERROR;
		consul_task->error = WFT_ERR_CONSUL_CHECK_RESPONSE_FAILED;
		consul_task->error_reason = resp->get_reason_phrase();
		return false;
	}

	return true;
}

long long WFConsulTask::get_consul_index(HttpResponse *resp)
{
	long long consul_index = 0;

	// get consul-index from http header
	protocol::HttpHeaderCursor cursor(resp);
	std::string consul_index_str;
	if (cursor.find("X-Consul-Index", consul_index_str))
	{
		consul_index = strtoll(consul_index_str.c_str(), NULL, 10);
		if (consul_index < 0)
			consul_index = 0;
	}

	return consul_index;
}

void WFConsulTask::discover_callback(WFHttpTask *task)
{
	WFConsulTask *t = (WFConsulTask*)task->user_data;

	if (!WFConsulTask::check_task_result(task, t))
	{
		t->finish = true;
		return;
	}

	protocol::HttpResponse *resp = task->get_resp();
	long long consul_index = t->get_consul_index(resp);
	long long last_consul_index = t->get_consul_index();
	t->set_consul_index(consul_index < last_consul_index ? 0 : consul_index);

	t->discover_res = HttpUtil::decode_chunked_body(resp);
	t->state = task->get_state();
	t->finish = true;
}

void WFConsulTask::list_service_callback(WFHttpTask *task)
{
	WFConsulTask *t = (WFConsulTask*)task->user_data;

	if (!WFConsulTask::check_task_result(task, t))
	{
		t->finish = true;
		return;
	}

	t->list_service_res = HttpUtil::decode_chunked_body(task->get_resp());
	t->state = task->get_state();
	t->finish = true;
}

void WFConsulTask::register_callback(WFHttpTask *task)
{
	WFConsulTask *t = (WFConsulTask *)task->user_data;

	if (WFConsulTask::check_task_result(task, t))
		t->state = task->get_state();

	t->finish = true;
}

int WFConsulClient::init(const std::string& proxy_url)
{
	this->proxy_url = proxy_url;
	return 0;
}

int WFConsulClient::init(const std::string& proxy_url, ConsulConfig config)
{
	this->proxy_url = proxy_url;
	this->config = std::move(config);
	return 0;
}

WFConsulTask *WFConsulClient::create_discover_task(
										const std::string& service_namespace,
										const std::string& service_name,
										int retry_max,
										consul_callback_t cb)
{
	WFConsulTask *task = new WFConsulTask(this->proxy_url, service_namespace,
										  service_name, "", retry_max,
										  std::move(cb));
	task->set_api_type(CONSUL_API_TYPE_DISCOVER);
	task->set_config(this->config);
	return task;
}

WFConsulTask *WFConsulClient::create_list_service_task(
										const std::string& service_namespace,
										int retry_max,
										consul_callback_t cb)
{
	WFConsulTask *task = new WFConsulTask(this->proxy_url, service_namespace, "", "",
										  retry_max, std::move(cb));
	task->set_api_type(CONSUL_API_TYPE_LIST_SERVICE);
	task->set_config(this->config);
	return task;
}

WFConsulTask *WFConsulClient::create_register_task(
										const std::string& service_namespace,
										const std::string& service_name,
										const std::string& service_id,
										int retry_max, consul_callback_t cb)
{
	WFConsulTask *task = new WFConsulTask(this->proxy_url, service_namespace,
										  service_name, service_id,
										  retry_max, std::move(cb));
	task->set_api_type(CONSUL_API_TYPE_REGISTER);
	task->set_config(this->config);
	return task;
}

WFConsulTask *WFConsulClient::create_deregister_task(
										const std::string& service_namespace,
										const std::string& service_id,
										int retry_max, consul_callback_t cb)
{
	WFConsulTask *task = new WFConsulTask(this->proxy_url, service_namespace, "",
	                                      service_id, retry_max, std::move(cb));
	task->set_api_type(CONSUL_API_TYPE_DEREGISTER);
	task->set_config(this->config);
	return task;
}

#define CHECK_JSON_VALUE(value)         \
	if (!value)	return false;

static bool create_tagged_address(const ConsulAddress& consul_address,
								  const std::string& name,
								  json_object_t *tagged_obj)
{
	if (consul_address.first.empty())
		return true;

	const json_value_t *val = json_object_append(tagged_obj, name.c_str(),
												 JSON_VALUE_OBJECT);
	CHECK_JSON_VALUE(val)

	json_object_t *obj = json_value_object(val);
	CHECK_JSON_VALUE(obj)

	if (!json_object_append(obj, "Address", JSON_VALUE_STRING,
							consul_address.first.c_str()))
		return false;

	if (!json_object_append(obj, "Port", JSON_VALUE_NUMBER,
							(double)consul_address.second))
		return false;

	return true;
}

static bool create_health_check(const ConsulConfig& config, json_object_t *obj)
{
	const json_value_t *val;
	json_object_t *check_obj;
	std::string str;

	if (!config.get_health_check())
		return true;

	val = json_object_append(obj, "Check", JSON_VALUE_OBJECT);
	CHECK_JSON_VALUE(val)

	check_obj = json_value_object(val);
	CHECK_JSON_VALUE(check_obj)

	str = config.get_check_name();
	if (!json_object_append(check_obj, "Name", JSON_VALUE_STRING, str.c_str()))
		return false;

	str = config.get_check_notes();
	if (!json_object_append(check_obj, "Notes", JSON_VALUE_STRING, str.c_str()))
		return false;

	str = config.get_check_http_url();
	if (!str.empty())
	{
		if (!json_object_append(check_obj, "HTTP", JSON_VALUE_STRING,
								str.c_str()))
			return false;

		str = config.get_check_http_method();
		if (!json_object_append(check_obj, "Method", JSON_VALUE_STRING,
								str.c_str()))
			return false;

		str = config.get_http_body();
		if (!json_object_append(check_obj, "Body", JSON_VALUE_STRING,
								str.c_str()))
			return false;
		
		const json_value_t *header_val = json_object_append(check_obj, "Header",
															JSON_VALUE_OBJECT);
		CHECK_JSON_VALUE(header_val)

		json_object_t *header_obj = json_value_object(header_val);
		CHECK_JSON_VALUE(header_obj)

		for (const auto& header : *config.get_http_headers())
		{
			val = json_object_append(header_obj, header.first.c_str(),
									 JSON_VALUE_ARRAY);
			CHECK_JSON_VALUE(val)

			json_array_t *array = json_value_array(val);
			CHECK_JSON_VALUE(array)

			for (const auto& arr : header.second)
			{
				if (!json_array_append(array, JSON_VALUE_STRING, arr.c_str()))
					return false;
			}
		}
	}

	str = config.get_check_tcp();
	if (!str.empty())
	{
		if (!json_object_append(check_obj, "TCP", JSON_VALUE_STRING,
								str.c_str()))
			return false;
	}

	str = config.get_initial_status();
	if (!json_object_append(check_obj, "Status", JSON_VALUE_STRING,
							str.c_str()))
		return false;

	str = convert_time_to_str(config.get_auto_deregister_time());
	if (!json_object_append(check_obj, "DeregisterCriticalServiceAfter",
							JSON_VALUE_STRING, str.c_str()))
		return false;

	str = convert_time_to_str(config.get_check_interval());
	if (!json_object_append(check_obj, "Interval", JSON_VALUE_STRING,
							str.c_str()))
		return false;

	str = convert_time_to_str(config.get_check_timeout());
	if (!json_object_append(check_obj, "Timeout", JSON_VALUE_STRING,
							str.c_str()))
		return false;

	if (!json_object_append(check_obj, "SuccessBeforePassing",
							JSON_VALUE_NUMBER,
							(double)config.get_success_times()))
		return false;

	if (!json_object_append(check_obj, "FailuresBeforeCritical",
							JSON_VALUE_NUMBER,
							(double)config.get_failure_times()))
		return false;

	return true;
}

static bool create_register_request(const json_value_t *root,
									const struct ConsulService *service,
									const ConsulConfig& config)
{
	json_object_t *obj;
	const json_value_t *val;

	obj = json_value_object(root);
	CHECK_JSON_VALUE(obj)

	if (!json_object_append(obj, "ID", JSON_VALUE_STRING,
							service->service_id.c_str()))
		return false;

	if (!json_object_append(obj, "Name", JSON_VALUE_STRING,
							service->service_name.c_str()))
		return false;

	if (!service->service_namespace.empty())
	{
		if (!json_object_append(obj, "ns", JSON_VALUE_STRING,
								service->service_namespace.c_str()))
			return false;
	}

	val = json_object_append(obj, "Tags", JSON_VALUE_ARRAY);
	CHECK_JSON_VALUE(val)

	json_array_t *tags = json_value_array(val);
	CHECK_JSON_VALUE(tags)

	for (const auto& tag : service->tags)
	{
		if (!json_array_append(tags, JSON_VALUE_STRING, tag.c_str()))
			return false;
	}

	if (!json_object_append(obj, "Address", JSON_VALUE_STRING,
							service->service_address.first.c_str()))
		return false;

	if (!json_object_append(obj, "Port", JSON_VALUE_NUMBER,
							(double)service->service_address.second))
		return false;

	val = json_object_append(obj, "Meta", JSON_VALUE_OBJECT);
	CHECK_JSON_VALUE(val)

	json_object_t *meta_obj = json_value_object(val);
	CHECK_JSON_VALUE(meta_obj)

	for (const auto& meta_kv : service->meta)
	{
		if (!json_object_append(meta_obj, meta_kv.first.c_str(),
								JSON_VALUE_STRING, meta_kv.second.c_str()))
			return false;
	}

	int type = service->tag_override ? JSON_VALUE_TRUE : JSON_VALUE_FALSE;

	if (!json_object_append(obj, "EnableTagOverride", type))
		return false;

	val = json_object_append(obj, "TaggedAddresses", JSON_VALUE_OBJECT);
	CHECK_JSON_VALUE(val)

	json_object_t *tagged_obj = json_value_object(val);
	CHECK_JSON_VALUE(tagged_obj)

	if (!create_tagged_address(service->lan, "lan", tagged_obj))
		return false;

	if (!create_tagged_address(service->lan_ipv4, "lan_ipv4", tagged_obj))
		return false;

	if (!create_tagged_address(service->lan_ipv6, "lan_ipv6", tagged_obj))
		return false;

	if (!create_tagged_address(service->virtual_address, "virtual", tagged_obj))
		return false;

	if (!create_tagged_address(service->wan, "wan", tagged_obj))
		return false;

	if (!create_tagged_address(service->wan_ipv4, "wan_ipv4", tagged_obj))
		return false;

	if (!create_tagged_address(service->wan_ipv6, "wan_ipv6", tagged_obj))
		return false;

	// create health check
	if (!create_health_check(config, obj))
		return false;

	return true;
}

static bool parse_list_service_result(const json_value_t *root,
									  std::vector<struct ConsulServiceTags>& result)
{
	const json_object_t *obj;
	const json_value_t *val;
	const json_array_t *arr;
	const char *key;
	const char *tag_value;

	obj = json_value_object(root);
	CHECK_JSON_VALUE(obj)

	json_object_for_each(key, val, obj)
	{
		struct ConsulServiceTags instance;

		instance.service_name = key;
		arr = json_value_array(val);
		CHECK_JSON_VALUE(arr)

		const json_value_t *tag_val;
		json_array_for_each(tag_val, arr)
		{
			tag_value = json_value_string(tag_val);
			CHECK_JSON_VALUE(tag_value)
			instance.tags.emplace_back(tag_value);
		}

		result.emplace_back(std::move(instance));
	}

	return true;
}

static bool parse_discover_node(const json_object_t *obj,
								struct ConsulServiceInstance *instance)
{
	const json_value_t *val;
	const char *str;

	val = json_object_find("Node", obj);
	CHECK_JSON_VALUE(val)

	const json_object_t *node_obj = json_value_object(val);
	CHECK_JSON_VALUE(node_obj)

	val = json_object_find("ID", node_obj);
	CHECK_JSON_VALUE(val)

	str = json_value_string(val);
	CHECK_JSON_VALUE(str)
	instance->node_id = str;

	val = json_object_find("Node", node_obj);
	CHECK_JSON_VALUE(val)

	str = json_value_string(val);
	CHECK_JSON_VALUE(str)
	instance->node_name = str;

	val = json_object_find("Address", node_obj);
	CHECK_JSON_VALUE(val)

	str = json_value_string(val);
	CHECK_JSON_VALUE(str)
	instance->node_address = str;

	val = json_object_find("Datacenter", node_obj);
	CHECK_JSON_VALUE(val)

	str = json_value_string(val);
	CHECK_JSON_VALUE(str)
	instance->dc = str;

	val = json_object_find("Meta", node_obj);
	CHECK_JSON_VALUE(val)
	const json_object_t *meta_obj = json_value_object(val);
	CHECK_JSON_VALUE(meta_obj)

	const char *meta_k;
	const json_value_t *meta_v;

	json_object_for_each(meta_k, meta_v, meta_obj)
	{
		str = json_value_string(meta_v);
		CHECK_JSON_VALUE(str)
		instance->node_meta[meta_k] = str;
	}

	val = json_object_find("CreateIndex", node_obj);
	if (val)
		instance->create_index = json_value_number(val);

	val = json_object_find("ModifyIndex", node_obj);
	if (val)
		instance->modify_index = json_value_number(val);

	return true;
}

static bool parse_tagged_address(const char *name, 
								 const json_value_t *tagged_val,
								 ConsulAddress& tagged_address)
{
	const json_value_t *val;
	const json_object_t *obj;
	const char *str;

	obj = json_value_object(tagged_val);
	CHECK_JSON_VALUE(obj)

	val = json_object_find(name, obj);
	CHECK_JSON_VALUE(val)
	obj = json_value_object(val);
	CHECK_JSON_VALUE(obj)

	val = json_object_find("Address", obj);
	CHECK_JSON_VALUE(val)
	str = json_value_string(val);
	CHECK_JSON_VALUE(str)
	tagged_address.first = str;

	val = json_object_find("Port", obj);
	CHECK_JSON_VALUE(val)
	tagged_address.second = json_value_number(val);
	return true;
}

static bool parse_service(const json_object_t *obj,
                          struct ConsulService *service)
{
	const json_object_t *service_obj;
	const json_value_t *val;
	const char *str;

	val = json_object_find("Service", obj);
	CHECK_JSON_VALUE(val)

	service_obj = json_value_object(val);
	CHECK_JSON_VALUE(service_obj)

	val = json_object_find("ID", service_obj);
	CHECK_JSON_VALUE(val)

	str = json_value_string(val);
	CHECK_JSON_VALUE(str)
	service->service_id = str;

	val = json_object_find("Service", service_obj);
	CHECK_JSON_VALUE(val)

	str = json_value_string(val);
	CHECK_JSON_VALUE(str)
	service->service_name = str;

	val = json_object_find("Namespace", service_obj);
	if (val)
	{
		str = json_value_string(val);
		CHECK_JSON_VALUE(str)
		service->service_namespace = str;
	}

	val = json_object_find("Address", service_obj);
	CHECK_JSON_VALUE(val)

	str = json_value_string(val);
	CHECK_JSON_VALUE(str)
	service->service_address.first = str;

	val = json_object_find("Port", service_obj);
	CHECK_JSON_VALUE(val)
	service->service_address.second = json_value_number(val);

	val = json_object_find("TaggedAddresses", service_obj);
	CHECK_JSON_VALUE(val)
	parse_tagged_address("lan", val, service->lan);
	parse_tagged_address("lan_ipv4", val, service->lan_ipv4);
	parse_tagged_address("lan_ipv6", val, service->lan_ipv6);
	parse_tagged_address("virtual", val, service->virtual_address);
	parse_tagged_address("wan", val, service->wan);
	parse_tagged_address("wan_ipv4", val, service->wan_ipv4);
	parse_tagged_address("wan_ipv6", val, service->wan_ipv6);

	val = json_object_find("Tags", service_obj);
	CHECK_JSON_VALUE(val)
	const json_array_t *tags_arr = json_value_array(val);
	if (tags_arr)
	{
		const json_value_t *tags_value;
		json_array_for_each(tags_value, tags_arr)
		{
			str = json_value_string(tags_value);
			CHECK_JSON_VALUE(str)
			service->tags.emplace_back(str);
		}
	}

	val = json_object_find("Meta", service_obj);
	CHECK_JSON_VALUE(val)
	const json_object_t *meta_obj = json_value_object(val);
	CHECK_JSON_VALUE(meta_obj)

	const char *meta_k;
	const json_value_t *meta_v;
	json_object_for_each(meta_k, meta_v, meta_obj)
	{
		str = json_value_string(meta_v);
		CHECK_JSON_VALUE(str)
		service->meta[meta_k] = str; 
	}

	val = json_object_find("EnableTagOverride", service_obj);
	if (val)
		service->tag_override = (json_value_type(val) == JSON_VALUE_TRUE);

	return true;
}

static bool parse_health_check(const json_object_t *obj,
							   struct ConsulServiceInstance *instance)
{
	const json_value_t *val;
	const json_object_t *check_obj;
	const char *str;

	val = json_object_find("Checks", obj);
	CHECK_JSON_VALUE(val)

	const json_array_t *check_arr = json_value_array(val);
	CHECK_JSON_VALUE(check_arr)

	const json_value_t *arr_val;
	json_array_for_each(arr_val, check_arr)
	{
		check_obj = json_value_object(arr_val);
		CHECK_JSON_VALUE(check_obj)

		val = json_object_find("ServiceName", check_obj);
		CHECK_JSON_VALUE(val)

		str = json_value_string(val);
		CHECK_JSON_VALUE(str)
		std::string check_service_name = str;

		val = json_object_find("ServiceID", check_obj);
		CHECK_JSON_VALUE(val)

		str = json_value_string(val);
		CHECK_JSON_VALUE(str)
		std::string check_service_id = str;

		if (check_service_id.empty() || check_service_name.empty())
			continue;

		val = json_object_find("CheckID", check_obj);
		CHECK_JSON_VALUE(val)

		str = json_value_string(val);
		CHECK_JSON_VALUE(str)
		instance->check_id = str;

		val = json_object_find("Name", check_obj);
		CHECK_JSON_VALUE(val)

		str = json_value_string(val);
		CHECK_JSON_VALUE(str)
		instance->check_name = str;

		val = json_object_find("Status", check_obj);
		CHECK_JSON_VALUE(val)

		str = json_value_string(val);
		CHECK_JSON_VALUE(str)
		instance->check_status = str;

		val = json_object_find("Notes", check_obj);
		if (val)
		{
			str = json_value_string(val);
			CHECK_JSON_VALUE(str)
			instance->check_notes = str;
		}

		val = json_object_find("Output", check_obj);
		if (val)
		{
			str = json_value_string(val);
			CHECK_JSON_VALUE(str)
			instance->check_output = str;
		}

		val = json_object_find("Type", check_obj);
		if (val)
		{
			str = json_value_string(val);
			CHECK_JSON_VALUE(str)
			instance->check_type = str;
		}

		break; //only one effective service health check
	}

	return true;
}

static bool parse_discover_result(const json_value_t *root,
		std::vector<struct ConsulServiceInstance>& result)
{
	const json_array_t *arr = json_value_array(root);
	const json_value_t *val;
	const json_object_t *obj;

	if (!arr)
		return false;

	json_array_for_each(val, arr)
	{
		struct ConsulServiceInstance instance;

		obj = json_value_object(val);

		if (!obj)
			return false;

		if (!parse_discover_node(obj, &instance))
			return false;

		if (!parse_service(obj, &instance.service))
			return false;

		parse_health_check(obj, &instance);

		result.emplace_back(std::move(instance));
	}

	return true;
}

static void print_json_object(const json_object_t *obj, int depth,
							  std::string& json_str)
{
	const char *name;
	const json_value_t *val;
	int n = 0;
	int i;

	json_str += "{\n";
	json_object_for_each(name, val, obj)
	{
		if (n != 0)
			json_str += ",\n";

		n++;
		for (i = 0; i < depth + 1; i++)
			json_str += "    ";

		json_str += "\"";
		json_str += name;
		json_str += "\": ";
		print_json_value(val, depth + 1, json_str);
	}

	json_str += "\n";
	for (i = 0; i < depth; i++)
		json_str += "    ";

	json_str += "}";
}

static void print_json_array(const json_array_t *arr, int depth,
							 std::string& json_str)
{
	const json_value_t *val;
	int n = 0;
	int i;

	json_str += "[\n";
	json_array_for_each(val, arr)
	{
		if (n != 0)
			json_str += ",\n";

		n++;
		for (i = 0; i < depth + 1; i++)
			json_str += "    ";

		print_json_value(val, depth + 1, json_str);
	}

	json_str += "\n";
	for (i = 0; i < depth; i++)
		json_str += "    ";

	json_str += "]";
}

static void print_json_string(const char *str, std::string& json_str)
{
	json_str += "\"";
	while (*str)
	{
		switch (*str)
		{
		case '\r':
			json_str += "\\r";
			break;
		case '\n':
			json_str += "\\n";
			break;
		case '\f':
			json_str += "\\f";
			break;
		case '\b':
			json_str += "\\b";
			break;
		case '\"':
			json_str += "\\\"";
			break;
		case '\t':
			json_str += "\\t";
			break;
		case '\\':
			json_str += "\\\\";
			break;
		default:
			json_str += *str;
			break;
		}
		str++;
	}
	json_str += "\"";
}

static void print_json_number(double number, std::string& json_str)
{
	long long integer = number;

	if (integer == number)
		json_str += std::to_string(integer);
	else
		json_str += std::to_string(number);
}

static void print_json_value(const json_value_t *val, int depth,
							 std::string& json_str)
{
	const char *val_str;
	switch (json_value_type(val))
	{
	case JSON_VALUE_STRING:
		val_str = json_value_string(val);
		if (!val_str)
			return;

		print_json_string(val_str, json_str);
		break;
	case JSON_VALUE_NUMBER:
		print_json_number(json_value_number(val), json_str);
		break;
	case JSON_VALUE_OBJECT:
		print_json_object(json_value_object(val), depth, json_str);
		break;
	case JSON_VALUE_ARRAY:
		print_json_array(json_value_array(val), depth, json_str);
		break;
	case JSON_VALUE_TRUE:
		json_str += "true";
		break;
	case JSON_VALUE_FALSE:
		json_str += "false";
		break;
	case JSON_VALUE_NULL:
		json_str += "null";
		break;
	}
}

