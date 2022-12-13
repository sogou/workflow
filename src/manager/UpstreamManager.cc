/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <pthread.h>
#include <functional>
#include "UpstreamManager.h"
#include "WFNameService.h"
#include "WFGlobal.h"
#include "UpstreamPolicies.h"

class __UpstreamManager
{
public:
	static __UpstreamManager *get_instance()
	{
		static __UpstreamManager kInstance;
		return &kInstance;
	}

	void add_upstream_policy(UPSGroupPolicy *policy)
	{
		pthread_mutex_lock(&this->mutex);
		this->upstream_policies.push_back(policy);
		pthread_mutex_unlock(&this->mutex);
	}

private:
	__UpstreamManager() :
		mutex(PTHREAD_MUTEX_INITIALIZER)
	{
	}

	~__UpstreamManager()
	{
		for (UPSGroupPolicy *policy : this->upstream_policies)
			delete policy;
	}

	pthread_mutex_t mutex;
	std::vector<UPSGroupPolicy *> upstream_policies;
};

int UpstreamManager::upstream_create_round_robin(const std::string& name,
												 bool try_another)
{
	WFNameService *ns = WFGlobal::get_name_service();
	auto *policy = new UPSRoundRobinPolicy(try_another);

	if (ns->add_policy(name.c_str(), policy) >= 0)
	{
		__UpstreamManager::get_instance()->add_upstream_policy(policy);
		return 0;
	}

	delete policy;
	return -1;
}

static unsigned int __default_consistent_hash(const char *path,
											  const char *query,
											  const char *fragment)
{
	static std::hash<std::string> std_hash;
	std::string str(path);

	str += query;
	str += fragment;
	return std_hash(str);
}

int UpstreamManager::upstream_create_consistent_hash(const std::string& name,
													 upstream_route_t consistent_hash)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSConsistentHashPolicy *policy;

	policy = new UPSConsistentHashPolicy(
						consistent_hash ? std::move(consistent_hash) :
										  __default_consistent_hash);
	if (ns->add_policy(name.c_str(), policy) >= 0)
	{
		__UpstreamManager::get_instance()->add_upstream_policy(policy);
		return 0;
	}

	delete policy;
	return -1;
}

int UpstreamManager::upstream_create_weighted_random(const std::string& name,
													 bool try_another)
{
	WFNameService *ns = WFGlobal::get_name_service();
	auto *policy = new UPSWeightedRandomPolicy(try_another);

	if (ns->add_policy(name.c_str(), policy) >= 0)
	{
		__UpstreamManager::get_instance()->add_upstream_policy(policy);
		return 0;
	}

	delete policy;
	return -1;
}

int UpstreamManager::upstream_create_vnswrr(const std::string& name)
{
	WFNameService *ns = WFGlobal::get_name_service();
	auto *policy = new UPSVNSWRRPolicy();

	if (ns->add_policy(name.c_str(), policy) >= 0)
	{
		__UpstreamManager::get_instance()->add_upstream_policy(policy);
		return 0;
	}

	delete policy;
	return -1;
}

int UpstreamManager::upstream_create_manual(const std::string& name,
											upstream_route_t select,
											bool try_another,
											upstream_route_t consistent_hash)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSManualPolicy *policy;

	policy = new UPSManualPolicy(try_another, std::move(select),
						consistent_hash ? std::move(consistent_hash) :
										  __default_consistent_hash);
	if (ns->add_policy(name.c_str(), policy) >= 0)
	{
		__UpstreamManager::get_instance()->add_upstream_policy(policy);
		return 0;
	}

	delete policy;
	return -1;
}

int UpstreamManager::upstream_add_server(const std::string& name,
										 const std::string& address)
{
	return UpstreamManager::upstream_add_server(name, address,
												&ADDRESS_PARAMS_DEFAULT);
}

int UpstreamManager::upstream_add_server(const std::string& name,
										 const std::string& address,
										 const AddressParams *address_params)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSGroupPolicy *policy = dynamic_cast<UPSGroupPolicy *>(ns->get_policy(name.c_str()));

	if (policy)
	{
		policy->add_server(address, address_params);
		return 0;
	}

	errno = ENOENT;
	return -1;
}

int UpstreamManager::upstream_remove_server(const std::string& name,
											const std::string& address)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSGroupPolicy *policy = dynamic_cast<UPSGroupPolicy *>(ns->get_policy(name.c_str()));

	if (policy)
		return policy->remove_server(address);

	errno = ENOENT;
	return -1;
}

int UpstreamManager::upstream_delete(const std::string& name)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSGroupPolicy *policy = dynamic_cast<UPSGroupPolicy *>(ns->del_policy(name.c_str()));

	if (policy)
		return 0;

	errno = ENOENT;
	return -1;
}

std::vector<std::string>
UpstreamManager::upstream_main_address_list(const std::string& name)
{
	std::vector<std::string> address;
	WFNameService *ns = WFGlobal::get_name_service();
	UPSGroupPolicy *policy = dynamic_cast<UPSGroupPolicy *>(ns->get_policy(name.c_str()));

	if (policy)
		policy->get_main_address(address);

	return address;
}

int UpstreamManager::upstream_disable_server(const std::string& name,
											 const std::string& address)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSGroupPolicy *policy = dynamic_cast<UPSGroupPolicy *>(ns->get_policy(name.c_str()));

	if (policy)
	{
		policy->disable_server(address);
		return 0;
	}

	errno = ENOENT;
	return -1;
}

int UpstreamManager::upstream_enable_server(const std::string& name,
											const std::string& address)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSGroupPolicy *policy = dynamic_cast<UPSGroupPolicy *>(ns->get_policy(name.c_str()));

	if (policy)
	{
		policy->enable_server(address);
		return 0;
	}

	errno = ENOENT;
	return -1;
}

int UpstreamManager::upstream_replace_server(const std::string& name,
											 const std::string& address,
											 const struct AddressParams *address_params)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSGroupPolicy *policy = dynamic_cast<UPSGroupPolicy *>(ns->get_policy(name.c_str()));

	if (policy)
	{
		policy->replace_server(address, address_params);
		return 0;
	}

	errno = ENOENT;
	return -1;
}

