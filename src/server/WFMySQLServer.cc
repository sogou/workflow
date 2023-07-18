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

#include <sys/uio.h>
#include "WFMySQLServer.h"

WFConnection *WFMySQLServer::new_connection(int accept_fd)
{
	WFConnection *conn = this->WFServer::new_connection(accept_fd);

	if (conn)
	{
		protocol::MySQLHandshakeResponse resp;
		struct iovec vec[8];
		int count;

		resp.server_set(0x0a, "5.5", 1, (const uint8_t *)"12345678901234567890",
						0, 33, 0);
		count = resp.encode(vec, 8);
		if (count >= 0)
		{
			if (writev(accept_fd, vec, count) >= 0)
				return conn;
		}

		this->delete_connection(conn);
	}

	return NULL;
}

CommSession *WFMySQLServer::new_session(long long seq, CommConnection *conn)
{
	static mysql_process_t empty = [](WFMySQLTask *){ };
	WFMySQLTask *task;

	task = WFServerTaskFactory::create_mysql_task(this, seq ? this->process :
															  empty);
	task->set_keep_alive(this->params.keep_alive_timeout);
	task->set_receive_timeout(this->params.receive_timeout);
	task->get_req()->set_size_limit(this->params.request_size_limit);

	return task;
}

