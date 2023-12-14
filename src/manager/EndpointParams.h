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

#ifndef _ENDPOINTPARAMS_H_
#define _ENDPOINTPARAMS_H_

#include <sys/types.h>
#include <sys/socket.h>

/**
 * @file   EndpointParams.h
 * @brief  Network config for client task
 */

enum TransportType
{
	TT_TCP,
	TT_UDP,
	TT_SCTP,
	TT_TCP_SSL,
	TT_SCTP_SSL,
};

struct EndpointParams
{
	int address_family;
	size_t max_connections;
	int connect_timeout;
	int response_timeout;
	int ssl_connect_timeout;
	bool use_tls_sni;
};

static constexpr struct EndpointParams ENDPOINT_PARAMS_DEFAULT =
{
	.address_family			=	AF_UNSPEC,
	.max_connections		=	200,
	.connect_timeout		=	10 * 1000,
	.response_timeout		=	10 * 1000,
	.ssl_connect_timeout	=	10 * 1000,
	.use_tls_sni			=	false,
};

#endif

