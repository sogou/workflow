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

#include "UpstreamManager.h"
#include "workflow/WFNameService.h"
#include "UPSPolicy.h"

// existed: -1; success: 0;
UpstreamManager::~UpstreamManager()
{
	for (const NSPolicy *policy : this->policies)
		delete policy;
	pthread_mutex_destroy(&this->lock);
}

int UpstreamManager::upstream_create_consistent_hash(const std::string& name,
													 upstream_route_t consistent_hash)
{
	UPSConsistentHashPolicy *policy = new UPSConsistentHashPolicy(std::move(consistent_hash));
	pthread_mutex_lock(&this->lock);
	this->policies->push_back(policy);
	pthread_mutex_unlock(&this->lock);
	return WFGlobal::get_name_service()->add_policy(name, policy);
}

int UpstreamManager::upstream_create_weighted_random(const std::string& name,
													 bool try_another)
{
	UPSWeightedRandomPolicy *policy = new UPSWeightedRandomPolicy(try_another);
	pthread_mutex_lock(&this->lock);
	this->policies->push_back(policy);
	pthread_mutex_unlock(&this->lock);
	return WFGlobal::get_name_service()->add_policy(name, policy);
}

int UpstreamManager::upstream_create_manual(const std::string& name,
											upstream_route_t select,
											bool try_another,
											upstream_route_t consitent_hash)
{
	UPSManualPolicy *policy = new UPSManualPolicy(try_another,
												  std::move(select),
												  std::move(consitent_hash));
	pthread_mutex_lock(&this->lock);
	this->policies->push_back(policy);
	pthread_mutex_unlock(&this->lock);
	return WFGlobal::get_name_service()->add_policy(name, policy);
}

int UpstreamManager::upstream_add_server(const std::string& name,
										 const std::string& address)
{
	return this->upstream_add_server(name, address, &ADDRESS_PARAMS_DEFAULT);
}

int UpstreamManager::upstream_add_server(const std::string& name,
										 const std::string& address,
										 const AddressParams *address_params)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSPolicy *policy = dynamic_cast<UPSPolicy *>ns->get_policy(name);
	if (policy)
	{
		policy->add_server(address, address_params);
		return 0;
	}
	return -1;
}

int UpstreamManager::upstream_remove_server(const std::string& name,
											const std::string& address)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSPolicy *policy = dynamic_cast<UPSPolicy *>ns->get_policy(name);
	if (policy)
	{
		policy->remove_server(address);
		return 0;
	}
	return -1;
}

std::vector<std::string>
UpstreamManager::upstream_main_address_list(const std::string& name)
{
	std::vector<std::string> address;
	//TODO
	return address
}

int UpstreamManager::upstream_disable_server(const std::string& name,
											 const std::string& address)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSPolicy *policy = dynamic_cast<UPSPolicy *>ns->get_policy(name);
	if (policy)
	{
		policy->disable_server(address);
		return 0;
	}
	return -1;
}

int UpstreamManager::upstream_enable_server(const std::string& name,
											const std::string& address)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSPolicy *policy = dynamic_cast<UPSPolicy *>ns->get_policy(name);
	if (policy)
	{
		policy->enable_server(address);
		return 0;
	}
	return -1;
}

int UpstreamManager::upstream_replace_server(const std::string& name,
											 const std::string& address,
											 const struct AddressParams *address_params)
{
	WFNameService *ns = WFGlobal::get_name_service();
	UPSPolicy *policy = dynamic_cast<UPSPolicy *>ns->get_policy(name);
	if (policy)
	{
		policy->replace_server(address, address_params);
		return 0;
	}
	return -1;
}

