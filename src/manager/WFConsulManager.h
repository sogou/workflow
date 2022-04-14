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

#ifndef _WFConsulManager_H_
#define _WFConsulManager_H_

#include <mutex>
#include <string>
#include <vector>
#include <functional>
#include <condition_variable>
#include <unordered_map>
#include <unordered_set>
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFFacilities.h"
#include "UpstreamPolicies.h"
#include "UpstreamManager.h"
#include "WFConsulClient.h"
#include "ConsulDataTypes.h"

class WFConsulManager
{
public:
	int init(const std::string& proxy_url);
	int init(const std::string& proxy_url, protocol::ConsulConfig config);
	void deinit();

	/**
     * @brief      watch service
     * @param[in]  service_namespace  consul service namespace
     * @param[in]  service_name       consul service name
     * @retval     success/fail
     * @retval     0                  success
     * @retval     -1                 fail, more info see errno
     * @note       
     * service_namespace: if consul not enterprise, you must set it empty string
     */
	int watch_service(const std::string& service_namespace,
					  const std::string& service_name);
	int watch_service(const std::string& service_namespace,
					  const std::string& service_name,
					  const struct AddressParams *address_params);

	/**
     * @brief      unwatch service
     * @param[in]  service_namespace  consul service namespace
     * @param[in]  service_name       consul service name
     * @retval     success/fail
     * @retval     0                  success
     * @retval     -1                 fail, more info see errno
     * @note       
     * service_namespace: if consul not enterprise, you must set it empty string
     */
	int unwatch_service(const std::string& service_namespace,
						const std::string& service_name);

	/**
     * @brief      register service
     * @param[in]  service            consul service
     * @retval     success/fail
     * @retval     0                  success
     * @retval     -1                 fail, more info see errno
     * @note       
     * service_namespace: if consul not enterprise, you must set it empty string
     * service_id: it must be globally unique
     */
	int register_service(const struct protocol::ConsulService *service);

	/**
     * @brief      deregister service
     * @param[in]  service_namespace  consul service namespace
     * @param[in]  service_id         consul service id
     * @retval     success/fail
     * @retval     0                  success
     * @retval     -1                 fail, more info see errno
     * @note       
     * service_namespace: if consul not enterprise, you must set it empty string
     * service_id: it must be globally unique
     */
	int deregister_service(const std::string& service_namespace,
						   const std::string& service_id);

	/**
     * @brief      get all watch services
     * @param[out] service names
     */
	void get_watching_services(std::vector<std::string>& services);

public:
	virtual ~WFConsulManager() { }

private:
	using ConsulInstances = std::vector<struct protocol::ConsulServiceInstance>;
    void discover_callback(WFConsulTask *task);
    void register_callback(WFConsulTask *task);
    void deregister_callback(WFConsulTask *task);
    void timer_callback(WFTimerTask *task, long long consul_index);
    int update_upstream_and_instances(
							const std::string& policy_name,
							const ConsulInstances& instances,
							const struct AddressParams *address_params,
							std::unordered_set<std::string>& cached_addresses);
    std::string get_policy_name(const std::string& service_namespace,
								const std::string& service_name);
    std::string get_address(const std::string& ip, unsigned short port);
	int add_servers(const std::string& policy_name,
					const std::vector<std::string>& addresses,
					const struct AddressParams *address_params);
	int remove_servers(const std::string& policy_name,
					   const std::vector<std::string>& addresses);
private:
	std::string proxy_url;
	protocol::ConsulConfig config;
	WFConsulClient client;
	std::mutex mutex;

	struct WatchInfo
	{
		bool watching;
		long long consul_index;
		std::condition_variable cond;
		std::unordered_set<std::string> cached_addresses;
    };

	struct ConsulCallBackResult
	{
		WFFacilities::WaitGroup *wait_group;
		int error;
	};

	struct WatchContext
	{
		std::string service_namespace;
		std::string service_name;
		struct AddressParams address_params;
	};
	std::unordered_map<std::string, struct WatchInfo *> watch_status;
};

#endif

