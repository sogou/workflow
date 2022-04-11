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

#ifndef _WFTASKERROR_H_
#define _WFTASKERROR_H_

/**
 * @file    WFTaskError.h
 * @brief   Workflow Task Error Code List
 */

/**
 * @brief   Defination of task state code
 * @note    Only for WFNetworkTask and only when get_state()==WFT_STATE_TASK_ERROR
 */
enum
{
	//COMMON
	WFT_ERR_URI_PARSE_FAILED = 1001,            ///< URI, parse failed
	WFT_ERR_URI_SCHEME_INVALID = 1002,          ///< URI, invalid scheme
	WFT_ERR_URI_PORT_INVALID = 1003,            ///< URI, invalid port
	WFT_ERR_UPSTREAM_UNAVAILABLE = 1004,        ///< Upstream, all target server down

	//HTTP
	WFT_ERR_HTTP_BAD_REDIRECT_HEADER = 2001,    ///< Http, 301/302/303/307/308 Location header value is NULL
	WFT_ERR_HTTP_PROXY_CONNECT_FAILED = 2002,   ///< Http, proxy CONNECT return non 200

	//REDIS
	WFT_ERR_REDIS_ACCESS_DENIED = 3001,         ///< Redis, invalid password
	WFT_ERR_REDIS_COMMAND_DISALLOWED = 3002,    ///< Redis, command disabled, cannot be "AUTH"/"SELECT"

	//MYSQL
	WFT_ERR_MYSQL_HOST_NOT_ALLOWED = 4001,      ///< MySQL
	WFT_ERR_MYSQL_ACCESS_DENIED = 4002,         ///< MySQL, authentication failed
	WFT_ERR_MYSQL_INVALID_CHARACTER_SET = 4003, ///< MySQL, invalid charset, not found in MySQL-Documentation
	WFT_ERR_MYSQL_COMMAND_DISALLOWED = 4004,    ///< MySQL, sql command disabled, cannot be "USE"/"SET NAMES"/"SET CHARSET"/"SET CHARACTER SET"
	WFT_ERR_MYSQL_QUERY_NOT_SET = 4005,         ///< MySQL, query not set sql, maybe forget please check
	WFT_ERR_MYSQL_SSL_NOT_SUPPORTED = 4006,		///< MySQL, SSL not supported by the server

	//KAFKA
	WFT_ERR_KAFKA_PARSE_RESPONSE_FAILED = 5001, ///< Kafka parse response failed
	WFT_ERR_KAFKA_PRODUCE_FAILED = 5002,
	WFT_ERR_KAFKA_FETCH_FAILED = 5003,
	WFT_ERR_KAFKA_CGROUP_FAILED = 5004,
	WFT_ERR_KAFKA_COMMIT_FAILED = 5005,
	WFT_ERR_KAFKA_META_FAILED = 5006,
	WFT_ERR_KAFKA_LEAVEGROUP_FAILED = 5007,
	WFT_ERR_KAFKA_API_UNKNOWN = 5008,			///< api type not supported
	WFT_ERR_KAFKA_VERSION_DISALLOWED = 5009,	///< broker version not supported
	WFT_ERR_KAFKA_SASL_DISALLOWED = 5010,		///< sasl not supported
	WFT_ERR_KAFKA_ARRANGE_FAILED = 5011,		///< arrange toppar failed
	WFT_ERR_KAFKA_LIST_OFFSETS_FAILED = 5012,
	WFT_ERR_KAFKA_CGROUP_ASSIGN_FAILED = 5013,

	//CONSUL
	WFT_ERR_CONSUL_API_UNKNOWN = 6001,		///< api type not supported
	WFT_ERR_CONSUL_CHECK_RESPONSE_FAILED = 6002,	///< Consul http code failed
};

#endif
