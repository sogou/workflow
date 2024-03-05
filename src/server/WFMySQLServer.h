/*
  Copyright (c) 2020 Sogou, Inc.

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

#ifndef _WFMYSQLSERVER_H_
#define _WFMYSQLSERVER_H_

#include <utility>
#include "MySQLMessage.h"
#include "WFServer.h"
#include "WFTaskFactory.h"
#include "WFConnection.h"

using mysql_process_t = std::function<void (WFMySQLTask *)>;
class MySQLServer;

static constexpr struct WFServerParams MYSQL_SERVER_PARAMS_DEFAULT =
{
	.transport_type			=	TT_TCP,
	.max_connections		=	2000,
	.peer_response_timeout	=	10 * 1000,
	.receive_timeout		=	-1,
	.keep_alive_timeout		=	28800 * 1000,
	.request_size_limit		=	(size_t)-1,
	.ssl_accept_timeout		=	10 * 1000,
};

class WFMySQLServer : public WFServer<protocol::MySQLRequest,
									  protocol::MySQLResponse>
{
public:
	WFMySQLServer(mysql_process_t proc):
		WFServer(&MYSQL_SERVER_PARAMS_DEFAULT, std::move(proc))
	{
	}

protected:
	virtual WFConnection *new_connection(int accept_fd);
	virtual CommSession *new_session(long long seq, CommConnection *conn);
};

#endif

