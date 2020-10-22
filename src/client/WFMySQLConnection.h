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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#include <string>
#include <utility>
#include <functional>
#include "URIParser.h"
#include "WFTaskFactory.h"

class WFMySQLConnection
{
public:
	/* example: mysql://username:passwd@127.0.0.1/dbname?character_set=utf8
	 * IP string is recommmended in url. When using a domain name, the first
	 * address resovled will be used. Don't use upstream name as a host. */
	int init(const std::string& url);

	void deinit() { }

public:
	WFMySQLTask *create_query_task(const std::string& query,
								   mysql_callback_t callback);

public:
	/* If you don't disconnect manually, the TCP connection will be
	 * kept alive after this object is deleted, and maybe reused by
	 * another WFMySQLConnection object with same id and url. */
	WFMySQLTask *create_disconnect_task(mysql_callback_t callback);

protected:
	ParsedURI uri;
	int id;

public:
	/* Make sure that cocurrent connections have different id.
	 * When a connection object is deleted, id can be reused. */
	WFMySQLConnection(int id) { this->id = id; }
	virtual ~WFMySQLConnection() { }
};

inline WFMySQLTask *
WFMySQLConnection::create_query_task(const std::string& query,
									 mysql_callback_t callback)
{
	WFMySQLTask *task = WFTaskFactory::create_mysql_task(this->uri, 0,
												std::move(callback));
	task->get_req()->set_query(query);
	return task;
}

inline WFMySQLTask *
WFMySQLConnection::create_disconnect_task(mysql_callback_t callback)
{
	WFMySQLTask *task = WFTaskFactory::create_mysql_task(this->uri, 0,
												std::move(callback));
	task->get_req()->set_query("");
	task->set_keep_alive(0);
	return task;
}

