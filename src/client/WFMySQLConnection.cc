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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <utility>
#include "URIParser.h"
#include "WFMySQLConnection.h"

int WFMySQLConnection::init(const std::string& url, SSL_CTX *ssl_ctx)
{
	std::string query;
	ParsedURI uri;

	if (URIParser::parse(url, uri) >= 0)
	{
		if (uri.query)
		{
			query = uri.query;
			query += '&';
		}

		query += "transaction=INTERNAL_CONN_ID_" + std::to_string(this->id);
		free(uri.query);
		uri.query = strdup(query.c_str());
		if (uri.query)
		{
			this->uri = std::move(uri);
			this->ssl_ctx = ssl_ctx;
			return 0;
		}
	}
	else if (uri.state == URI_STATE_INVALID)
		errno = EINVAL;

	return -1;
}

