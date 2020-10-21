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
#include <functional>
#include "URIParser.h"
#include "EndpointParams.h"

/**
 * @file    UpstreamManager.h
 * @brief   Local Reverse Proxy & Load Balance & Service Discovery
 * @details
 * - This is very similar with Nginx-Upstream.
 * - Do not cost any other network resource, We just simulate in local to choose one target properly.
 * - This is working only for the current process.
 */

/**
 * @brief   Functional for consistent-hash OR manual-select
 * @details
 * - path/query/fragment is empty string when uri not contain that region
 * - path/query/fragment would never be NULL
 */
using upstream_route_t = std::function<unsigned int (const char *, const char *, const char *)>;

/**
 * @brief   Server config for upstream
 * @details
 * When call UpstreamManager::upstream_add_server, you can set custom config for each target
*/
struct AddressParams
{
	struct EndpointParams endpoint_params; ///< Connection config
	unsigned int dns_ttl_default;          ///< in seconds, DNS TTL when network request success
	unsigned int dns_ttl_min;              ///< in seconds, DNS TTL when network request fail
/**
 * - The max_fails directive sets the number of consecutive unsuccessful attempts to communicate with the server.
 * - After 30s following the server failure, upstream probe the server with some live client’s requests.
 * - If the probes have been successful, the server is marked as a live one.
 * - If max_fails is set to 1, it means server would out of upstream selection in 30 seconds when failed only once
 */
	unsigned int max_fails;                ///< [1, INT32_MAX] max_fails = 0 means max_fails = 1
	unsigned short weight;                 ///< [1, 65535] weight = 0 means weight = 1. only for main server
	int server_type;                       ///< 0 for main and 1 for backup
	int group_id;                          ///< -1 means no group. Backup without group will be backup for any main
};

/**
 * @brief   Default server config for upstream
 */
static constexpr struct AddressParams ADDRESS_PARAMS_DEFAULT =
{
	.endpoint_params	=	ENDPOINT_PARAMS_DEFAULT,
	.dns_ttl_default	=	12 * 3600,
	.dns_ttl_min		=	180,
	.max_fails			=	200,
	.weight				=	1,
	.server_type		=	0,	/* 0 for main and 1 for backup. */
	.group_id			=	-1,
};

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
	upstream_create_weighted_random("abc.sogou", true);           //UPSTREAM_WIGHTED_RANDOM
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
	 * @brief      Delete one upstream
	 * @param[in]  name             upstream name
	 * @return     success/fail
	 * @retval     0                fail, not found
	 * @retval     1                success
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

public:
	/// @brief Internal use only
	class UpstreamResult
	{
public:
		void *cookie;
		const struct AddressParams *address_params;
#define UPSTREAM_SUCCESS	0
#define UPSTREAM_NOTFOUND	1
#define UPSTREAM_ALL_DOWN	2
		int state;

public:
		UpstreamResult():
			cookie(NULL),
			address_params(NULL),
			state(UPSTREAM_NOTFOUND)
		{}

		void clear()
		{
			cookie = NULL;
			address_params = NULL;
			state = UPSTREAM_NOTFOUND;
		}
	};

	/// @brief Internal use only
	static int choose(ParsedURI& uri, UpstreamResult& result);
	/// @brief Internal use only
	static void notify_unavailable(void *cookie);
	/// @brief Internal use only
	static void notify_available(void *cookie);
};

#endif

