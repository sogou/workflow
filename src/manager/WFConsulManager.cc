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

#include <set>
#include <unordered_map>
#include <unordered_set>
#include "WFConsulManager.h"
#include "WFConsulClient.h"
#include "UpstreamManager.h"

using namespace protocol;

enum
{
    CONSUL_INIT_FAILED       = -1, 
    CONSUL_INIT_SUCCESS      = 0,
};

class ConsulPolicy
{
public:
	ConsulPolicy(const std::string& policy_name,
				 const struct ConsulWatchParams *params,
				 upstream_route_t select,
				 upstream_route_t consistent_hash)
		: policy_name(policy_name), params(*params)
	{
		this->select = select;
		this->consistent_hash = consistent_hash;
		status = -1;
		
		switch (this->params.upstream_policy)
		{
		case CONSUL_UPSTREAM_WEIGHT:
			status = UpstreamManager::upstream_create_weighted_random(
				this->policy_name, true);
			break;
		case CONSUL_UPSTREAM_HASH:
			status = UpstreamManager::upstream_create_consistent_hash(
				this->policy_name, this->consistent_hash);
			break;
		case CONSUL_UPSTREAM_MANUAL:
			status = UpstreamManager::upstream_create_manual(this->policy_name,
				this->select, true, this->consistent_hash);
			break;
		case CONSUL_UPSTREAM_NVSWRR:
			status = UpstreamManager::upstream_create_vnswrr(this->policy_name);
			break;
		}
	}

	~ConsulPolicy()
	{
		UpstreamManager::upstream_delete(this->policy_name);
	}

	int add_servers(const std::vector<std::string>& addresses)
	{
		if (status == -1)
			return -1;
	
		AddressParams address_params = ADDRESS_PARAMS_DEFAULT;
		address_params.max_fails = this->params.max_fails;
		address_params.endpoint_params.connect_timeout = this->params.connect_timeout;
		address_params.endpoint_params.response_timeout = this->params.response_timeout;

		for (const auto& address : addresses)
		{
			fprintf(stderr, "add addr:%s\n", address.c_str());
			if (UpstreamManager::upstream_add_server(this->policy_name, address,
													 &address_params) == -1)
				return -1;
		}

		return 0;
	}

	int remove_servers(const std::vector<std::string>& addresses)
	{
		if (status == -1)
			return -1;
		
		for (const auto& address : addresses)
		{
			fprintf(stderr, "remove addr:%s\n", address.c_str());
			if (UpstreamManager::upstream_remove_server(this->policy_name,
														address) == -1)
				return -1;
		}

		return 0;
	}
	
private:
	std::string         policy_name;
	struct ConsulWatchParams params;
	upstream_route_t	select;
	upstream_route_t	consistent_hash;
	int status;	
};

class __WFConsulManager
{
public:
	__WFConsulManager(const std::string& consul_url, ConsulConfig config) :
		ref(1), consul_url(consul_url), config(std::move(config)),
		retry_max(2), select(nullptr), consistent_hash(nullptr)
	{
		if (this->client.init(consul_url, this->config) == 0)
			this->status = CONSUL_INIT_SUCCESS;
		else
			this->status = CONSUL_INIT_FAILED;

		this->discover_cb = std::bind(&__WFConsulManager::discover_callback, this,
									  std::placeholders::_1);
		this->register_cb = std::bind(&__WFConsulManager::register_callback, this,
									  std::placeholders::_1);
		this->deregister_cb = std::bind(&__WFConsulManager::register_callback, this,
										std::placeholders::_1);
	}

	~__WFConsulManager()
	{
		if (this->status != CONSUL_INIT_FAILED)
			this->client.deinit();
	}
	
	int watch_service(const std::string& service_namespace,
					  const std::string& service_name,
					  const struct ConsulWatchParams *params);

	int unwatch_service(const std::string& service_namespace,
						const std::string& service_name);

	int register_service(const std::string& service_namespace,
						 const std::string& service_name,
						 const std::string& service_id,
						 const struct ConsulRegisterParams *params);

	int deregister_service(const std::string& service_namespace,
						   const std::string& service_id);

	void get_watching_services(std::vector<std::string>& services);

	void set_select(upstream_route_t select)
	{
		this->select = select;
	}

	void set_consistent_hash(upstream_route_t consistent_hash)
	{
		this->consistent_hash = consistent_hash;
	}

public:
	void exit()
	{
		assert(--this->ref == 0);
		delete this;
	}

	using ConsulInstances = std::vector<struct ConsulServiceInstance>;
	using ConsulAddressSet = std::unordered_set<std::string>;
private:
	std::atomic<int> ref;
	std::string consul_url;
	ConsulConfig config;
	WFConsulClient client;
	int retry_max;

	struct WatchInfo
	{
		bool watching;
		long long consul_index;
		std::condition_variable cond;
		ConsulAddressSet cached_addresses;
		ConsulPolicy *policy;
	};

	struct ConsulCallBackResult
	{
		WFFacilities::WaitGroup *wait_group;
		int error;
	};

	std::mutex mutex;
	std::unordered_map<std::string, struct WatchInfo *> watch_status;
	int status;
	struct ConsulWatchParams params;
	upstream_route_t select;
	upstream_route_t consistent_hash;

	std::function<void (WFConsulTask *task)> discover_cb;
	std::function<void (WFConsulTask *task)> register_cb;
	std::function<void (WFConsulTask *task)> deregister_cb;

private:
	void discover_callback(WFConsulTask *task);
	void register_callback(WFConsulTask *task);
	void deregister_callback(WFConsulTask *task);
	void timer_callback(WFTimerTask *task, long long consul_index);
	int update_upstream_and_instances(
                                const std::string& policy_name,
                                const ConsulInstances& instances,
                                ConsulPolicy& policy,
                                ConsulAddressSet& address_cached);
	std::string get_policy_name(const std::string& service_namespace,
								const std::string& service_name);
	std::string get_address(const std::string& ip, unsigned short port);
};

struct WFConsulTaskContext
{
	std::string service_namespace;
	std::string service_name;
};

WFConsulManager::WFConsulManager(const std::string& consul_url,
							 ConsulConfig config)
{
	ptr = new __WFConsulManager(consul_url, std::move(config));
}

WFConsulManager::~WFConsulManager()
{
	ptr->exit();
}

int WFConsulManager::watch_service(const std::string& service_namespace,
								 const std::string& service_name)
{
	struct ConsulWatchParams params = CONSUL_DISCOVER_PARAMS_DEFAULT;
	return watch_service(service_namespace, service_name, &params);
}

int WFConsulManager::watch_service(const std::string& service_namespace,
								 const std::string& service_name,
								 const struct ConsulWatchParams *params)
{
	return this->ptr->watch_service(service_namespace, service_name, params);
}

int WFConsulManager::unwatch_service(const std::string& service_namespace,
								   const std::string& service_name)
{
	return this->ptr->unwatch_service(service_namespace, service_name);
}

int WFConsulManager::register_service(const std::string& service_namespace,
									const std::string& service_name,
									const std::string& service_id,
									const struct ConsulRegisterParams *params)
{
	return ptr->register_service(service_namespace, service_name, service_id,
								 params);
}

int WFConsulManager::deregister_service(const std::string& service_namespace,
									  const std::string& service_id)
{
	return ptr->deregister_service(service_namespace, service_id);
}

void WFConsulManager::get_watching_services(std::vector<std::string>& services)
{
	ptr->get_watching_services(services);
}

void WFConsulManager::set_select(upstream_route_t select)
{
	ptr->set_select(select);
}

void WFConsulManager::set_consistent_hash(upstream_route_t consistent_hash)
{
	ptr->set_consistent_hash(consistent_hash);
}

int __WFConsulManager::watch_service(const std::string& service_namespace,
								   const std::string& service_name,
								   const struct ConsulWatchParams *params)
{
	if (this->status == CONSUL_INIT_FAILED || !params)
		return CONSUL_INIT_FAILED;
	
	this->params = *params;
		
	WFFacilities::WaitGroup wait_group(1);
	WFConsulTask *task = this->client.create_discover_task(service_namespace,
														   service_name,
														   this->retry_max,
														   this->discover_cb);
	task->set_consul_index(0);

	struct ConsulCallBackResult result;
	result.wait_group = &wait_group;
	task->user_data = &result;

	struct WFConsulTaskContext *ctx = new struct WFConsulTaskContext;
	ctx->service_namespace = service_namespace;
	ctx->service_name = service_name;

	SeriesWork *series = Workflow::create_series_work(task,
												[](const SeriesWork *series) {
		delete (struct WFConsulTaskContext *)series->get_context();
	});

	series->set_context(ctx);
	series->start();

	wait_group.wait();

	if (result.error == 0)
		++this->ref;

	return result.error;
}

int __WFConsulManager::unwatch_service(const std::string& service_namespace,
									 const std::string& service_name)
{
	if (this->status == CONSUL_INIT_FAILED)
		return CONSUL_INIT_FAILED;

	std::string policy_name = get_policy_name(service_namespace, service_name);
	std::unique_lock<std::mutex> lock(this->mutex);
	auto iter = this->watch_status.find(policy_name);
	if (iter == this->watch_status.end())
		return WFT_ERR_CONSUL_NO_WATCHING_SERVICE;	
		
	if (iter->second->watching)
	{
		iter->second->watching = false;
		iter->second->cond.wait(lock);
		--this->ref;
	}

	if (!iter->second->policy)
	{
		delete iter->second->policy;
		iter->second->policy = NULL;
	}

	delete iter->second;
	this->watch_status.erase(iter);

	return 0;
}

int __WFConsulManager::register_service(const std::string& service_namespace,
									  const std::string& service_name,
									  const std::string& service_id,
									  const struct ConsulRegisterParams *params)
{
	if (this->status == CONSUL_INIT_FAILED || !params)
		return CONSUL_INIT_FAILED;

	WFFacilities::WaitGroup wait_group(1);
	WFConsulTask *task = this->client.create_register_task(service_namespace,
														   service_name,
														   service_id,
														   this->retry_max,
														   this->register_cb);
	struct ConsulService consul_service;	
	consul_service.tags = params->tags;
	consul_service.meta = params->meta;
	consul_service.service_address.first = params->address;
	consul_service.service_address.second = params->port;
	consul_service.tag_override = true;
	task->set_service(&consul_service);

	struct ConsulCallBackResult result;
	result.wait_group = &wait_group;
	task->user_data = &result;
	task->start();

	wait_group.wait();

	return result.error;
}

int __WFConsulManager::deregister_service(const std::string& service_namespace,
										const std::string& service_id)
{
	if (this->status == CONSUL_INIT_FAILED)
		return CONSUL_INIT_FAILED;

	WFFacilities::WaitGroup wait_group(1);
	WFConsulTask *task = this->client.create_deregister_task(service_namespace,
															 service_id,
															 this->retry_max,
															 this->register_cb);

	struct ConsulCallBackResult result;
	result.wait_group = &wait_group;
	task->user_data = &result;
	task->start();

	wait_group.wait();

	return result.error;
}

void __WFConsulManager::get_watching_services(std::vector<std::string>& services)
{
	std::unique_lock<std::mutex> lk(this->mutex);
	for (const auto& kv : this->watch_status)
	{
		services.emplace_back(kv.first);
	}
}

void __WFConsulManager::discover_callback(WFConsulTask *task)
{
	int error = task->get_error();
	int state = task->get_state();

	struct ConsulCallBackResult *result = NULL;
	if (task->user_data)
	{
		result = (struct ConsulCallBackResult*)task->user_data;
		result->error = error;
	}

	bool ret = false;
	ConsulInstances instances;
	if (state == WFT_STATE_SUCCESS)
	{
		ret = task->get_discover_result(instances);
	}

	if (state != WFT_STATE_SUCCESS || !ret)
	{
		if (result)
		{
			result->wait_group->done();
			return;
		}
	}
	
	long long consul_index;
	struct WFConsulTaskContext *ctx =
			(struct WFConsulTaskContext *)series_of(task)->get_context();
	std::string policy_name = get_policy_name(ctx->service_namespace,
											  ctx->service_name);
	{
		std::unique_lock<std::mutex> lk(this->mutex);
		auto iter = this->watch_status.find(policy_name);
		if (iter != this->watch_status.end())
		{
			if (result)
			{
				result->error = WFT_ERR_CONSUL_DOUBLE_WATCH;
				result->wait_group->done();
				return; 
			}

			if (!iter->second->watching)
			{
				iter->second->cond.notify_one();
				return;
			}
			
			ret = ret && (iter->second->consul_index < task->get_consul_index());
		}
		else
		{
			struct WatchInfo *watch_info = new struct WatchInfo;
			watch_info->policy = new ConsulPolicy(policy_name, &this->params,
											 this->select, this->consistent_hash);
			this->watch_status[policy_name] = watch_info;
		}

		auto& watch_info = this->watch_status[policy_name];
		watch_info->consul_index = task->get_consul_index();
		consul_index = watch_info->consul_index;
	
		if (result)
			watch_info->watching = true;

		if (ret)
		{
			update_upstream_and_instances(policy_name,
										  instances,
										  *watch_info->policy,
										  watch_info->cached_addresses);
		}
	}

	auto timer_cb = std::bind(&__WFConsulManager::timer_callback, this,
							  std::placeholders::_1, consul_index);
	WFTimerTask *timer_task;
	if (this->config.blocking_query())
		timer_task = WFTaskFactory::create_timer_task(0, timer_cb);
	else
		timer_task = WFTaskFactory::create_timer_task(
					this->config.get_wait_ttl() * 1000, timer_cb);

	series_of(task)->push_back(timer_task);

	if (result)
		result->wait_group->done();

}

void __WFConsulManager::timer_callback(WFTimerTask *task, long long consul_index)
{
	auto *series_task = series_of(task);
	struct WFConsulTaskContext *ctx =
			(struct WFConsulTaskContext *)series_task->get_context();

	WFConsulTask *discover_task;
	discover_task = this->client.create_discover_task(ctx->service_namespace,
													  ctx->service_name,
													  this->retry_max,
													  this->discover_cb);
	discover_task->set_consul_index(consul_index);
	series_of(task)->push_back(discover_task);
}

void __WFConsulManager::register_callback(WFConsulTask *task)
{
	int error = task->get_error();

	struct ConsulCallBackResult *result;
	result = (struct ConsulCallBackResult *)task->user_data;
	result->error = error;
	result->wait_group->done();
	return;
}

int __WFConsulManager::update_upstream_and_instances(
								const std::string& policy_name,
								const ConsulInstances& instances,
								ConsulPolicy& policy,
								ConsulAddressSet& cached_addresses)
{
	std::vector<std::string> add_addresses, remove_addresses;
	ConsulAddressSet cur_address_set;
	std::string	address;
	for (const auto& instance : instances)
	{
		address = get_address(instance.service.service_address.first,
						   instance.service.service_address.second);
		if (cached_addresses.find(address) == cached_addresses.end())
			add_addresses.emplace_back(address);

		cur_address_set.insert(address);
	}

	for (const auto& address : cached_addresses)
	{
		if (cur_address_set.find(address) == cur_address_set.end())
			remove_addresses.emplace_back(address);	
	}

	cached_addresses.swap(cur_address_set);

	int ret = 0;
	ret += policy.add_servers(add_addresses);
	ret += policy.remove_servers(remove_addresses);
	return ret;
}

std::string __WFConsulManager::get_policy_name(const std::string& service_namespace,
											 const std::string& service_name)
{
	return service_namespace + "." + service_name;
}

std::string __WFConsulManager::get_address(const std::string& host,
										 unsigned short port)
{
	return host + ":" + std::to_string(port);
}
