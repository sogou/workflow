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

#ifndef _UPSTREAM_MANAGER_H_
#define _UPSTREAM_MANAGER_H_

#include <string>
#include <vector>
#include "WFServiceGovernance.h"
#include "UpstreamPolicies.h"
#include "WFGlobal.h"

/**
 * @file    UpstreamManager.h
 * @brief   Local Reverse Proxy & Load Balance & Service Discovery
 * @details
 * - This is very similar with Nginx-Upstream.
 * - Do not cost any other network resource, We just simulate in local to choose one target properly.
 * - This is working only for the current process.
 */

/**
 * @brief   Upstream Management Class
 * @details
 * - We support three modes:
 *   1. Weighted-Random
 *   2. Consistent-Hash
 *   3. Manual-Select
 * - Additional, we support Main-backup & Group for server and working well in any mode.
 *
 * @code{.cc}
	upstream_create_weighted_random("abc.sogou", true);           //UPSTREAM_WEIGHTED_RANDOM
	upstream_add_server("abc.sogou", "192.168.2.100:8081");       //weight=1, max_fails=200
	upstream_add_server("abc.sogou", "192.168.2.100:9090");       //weight=1, max_fails=200
	AddressParams params = ADDRESS_PARAMS_DEFAULT;
	params.weight = 2;
	params.max_fails = 6;
	upstream_add_server("abc.sogou", "www.sogou.com", &params);   //weight=2, max_fails=6

	//send request with url like http://abc.sogou/somepath/somerequest

	upstream_create_consistent_hash("def.sogou",
								    [](const char *path,
									   const char *query,
									   const char *fragment) -> int {
											return somehash(...));
									});                           //UPSTREAM_CONSISTENT_HASH
	upstream_create_manual("xyz.sogou",
						   [](const char *path,
							  const char *query,
							  const char *fragment) -> int {
									return select_xxx(...));
						   },
						   true,
						   [](const char *path,
							  const char *query,
							  const char *fragment) -> int {
									return rehash(...));
						   },);                                   //UPSTREAM_MANUAL
 * @endcode
 */
class UpstreamManager
{
public:
	/**
	 * @brief      MODE 0: round-robin select
	 * @param[in]  name             upstream name
	 * @param[in]  try_another      when first choice is failed, try another one or not
	 * @return     success/fail
	 * @retval     0                success
	 * @retval     -1               fail, more info see errno
	 * @note
	 * when first choose server is already down:
	 * - if try_another==false, request will be failed
	 * - if try_another==true, upstream will choose the next
	 */
	static int upstream_create_round_robin(const std::string& name,
										   bool try_another);

	/**
	 * @brief      MODE 1: consistent-hashing select
	 * @param[in]  name             upstream name
	 * @param[in]  consitent_hash   consistent-hash functional
	 * @return     success/fail
	 * @retval     0                success
	 * @retval     -1               fail, more info see errno
	 * @note       consitent_hash need to return value in 0~(2^31-1) Balance/Monotonicity/Spread/Smoothness
	 * @note       if consitent_hash==nullptr, upstream will use std::hash with request uri
	 */
	static int upstream_create_consistent_hash(const std::string& name,
											   upstream_route_t consitent_hash);

	/**
	 * @brief      MODE 2: weighted-random select
	 * @param[in]  name             upstream name
	 * @param[in]  try_another      when first choice is failed, try another one or not
	 * @return     success/fail
	 * @retval     0                success
	 * @retval     -1               fail, more info see errno
	 * @note
	 * when first choose server is already down:
	 * - if try_another==false, request will be failed
	 * - if try_another==true, upstream will choose from alive-servers by weight-random strategy
	 */
	static int upstream_create_weighted_random(const std::string& name,
											   bool try_another);

	/**
	 * @brief      MODE 3: manual select
	 * @param[in]  name             upstream name
	 * @param[in]  select           manual select functional, just tell us main-index.
	 * @param[in]  try_another      when first choice is failed, try another one or not
	 * @param[in]  consitent_hash   consistent-hash functional
	 * @return     success/fail
	 * @retval     0                success
	 * @retval     -1               fail, more info see errno
	 * @note
	 * when first choose server is already down:
	 * - if try_another==false, request will be failed, consistent_hash value will be ignored
	 * - if try_another==true, upstream will work with consistent hash mode，if consitent_hash==NULL, upstream will use std::hash with request uri
	 * @warning    select functional cannot be nullptr!
	 */
	static int upstream_create_manual(const std::string& name,
									  upstream_route_t select,
									  bool try_another,
									  upstream_route_t consitent_hash);

	/**
	 * @brief      MODE 4: VNSWRR select
	 * @param[in]  name             upstream name
	 * @return     success/fail
	 * @retval     0                success
	 * @retval     -1               fail, more info see errno
	 * @note
	 */
	static int upstream_create_vnswrr(const std::string& name);

	/**
	 * @brief      Delete one upstream
	 * @param[in]  name             upstream name
	 * @return     success/fail
	 * @retval     0                success
	 * @retval     -1               fail, not found
	 */
	static int upstream_delete(const std::string& name);

public:
	/**
	 * @brief      Add server into one upstream, with default config
	 * @param[in]  name             upstream name
	 * @param[in]  address          ip OR host OR ip:port OR host:port OR /unix-domain-socket
	 * @return     success/fail
	 * @retval     0                success
	 * @retval     -1               fail, more info see errno
	 * @warning    Same address add twice, means two different server
	 */
	static int upstream_add_server(const std::string& name,
								   const std::string& address);

	/**
	 * @brief      Add server into one upstream, with custom config
	 * @param[in]  name             upstream name
	 * @param[in]  address          ip OR host OR ip:port OR host:port OR /unix-domain-socket
	 * @param[in]  address_params   custom config for this target server
	 * @return     success/fail
	 * @retval     0                success
	 * @retval     -1               fail, more info see errno
	 * @warning    Same address with different params, means two different server
	 * @warning    Same address with exactly same params, still means two different server
	 */
	static int upstream_add_server(const std::string& name,
								   const std::string& address,
								   const struct AddressParams *address_params);

	/**
	 * @brief      Remove server from one upstream
	 * @param[in]  name             upstream name
	 * @param[in]  address          same as address when add by upstream_add_server
	 * @return     success/fail
	 * @retval     >=0              success, the amount of being removed server
	 * @retval     -1               fail, upstream name not found
	 * @warning    If server servers has the same address in this upstream, we will remove them all
	 */
	static int upstream_remove_server(const std::string& name,
									  const std::string& address);

	/**
	 * @brief      get all main servers address list from one upstream
	 * @param[in]  name             upstream name
	 * @return     all main servers' address list
	 * @warning    If server servers has the same address in this upstream, then will appear in the vector multiply times
	 */
	static std::vector<std::string> upstream_main_address_list(const std::string& name);

public:
	/// @breif for plugin
	static int upstream_disable_server(const std::string& name, const std::string& address);
	static int upstream_enable_server(const std::string& name, const std::string& address);

	static int upstream_replace_server(const std::string& name,
									   const std::string& address,
									   const struct AddressParams *address_params);

};

#endif

