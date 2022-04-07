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

#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <functional>
#include <condition_variable>
#include "WFTask.h"
#include "WFTaskFactory.h"
#include "WFFacilities.h"
#include "ConsulDataTypes.h"
#include "UpstreamPolicies.h"

enum
{
	CONSUL_UPSTREAM_WEIGHT           = 0,
	CONSUL_UPSTREAM_HASH             = 1,
	CONSUL_UPSTREAM_MANUAL           = 2,
	CONSUL_UPSTREAM_NVSWRR           = 3,
};

struct ConsulWatchParams
{
	//CONSUL_UPSTREAM_WEIGHT or CONSUL_UPSTREAM_HASH or CONSUL_UPSTREAM_MANUAL or CONSUL_UPSTREAM_NVSWRR
	int upstream_policy;
	int connect_timeout;
	int response_timeout;
	int max_fails;
};

static constexpr struct ConsulWatchParams CONSUL_DISCOVER_PARAMS_DEFAULT =
{
	.upstream_policy    =    CONSUL_UPSTREAM_WEIGHT,
	.connect_timeout    =    10 * 1000,   //10s
	.response_timeout   =    10 * 1000,   //10s
	.max_fails          =    200,
};

struct ConsulRegisterParams
{
	std::vector<std::string> tags;	
	std::map<std::string, std::string> meta;
	std::string address;
	uint16_t port;
};

class __WFConsulManager;
class WFConsulManager
{
public:
	WFConsulManager(const std::string& consul_url, protocol::ConsulConfig config);
	~WFConsulManager();

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
					  const struct ConsulWatchParams *params);

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
     * @param[in]  service_namespace  consul service namespace
     * @param[in]  service_name       consul service name
     * @param[in]  service_id         consul service id
     * @param[in]  params             consul register params
     * @retval     success/fail
     * @retval     0                  success
     * @retval     -1                 fail, more info see errno
     * @note       
     * service_namespace: if consul not enterprise, you must set it empty string
     * service_id: it must be globally unique
     */
	int register_service(const std::string& service_namespace,
						 const std::string& service_name,
						 const std::string& service_id,
                         const struct ConsulRegisterParams *params);

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

	void set_select(upstream_route_t select);

	void set_consistent_hash(upstream_route_t consistent_hash);
private:

	__WFConsulManager *ptr;
};

#endif

