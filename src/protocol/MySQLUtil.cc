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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#include <string>
#include "MySQLUtil.h"

namespace protocol
{

std::string MySQLUtil::escape_string(const std::string& str)
{
	std::string res;
	char escape;
	size_t i;

	for (i = 0; i < str.size(); i++)
	{
		switch (str[i])
		{
		case '\0':
			escape = '0';
			break;
		case '\n':
			escape = 'n';
			break;
		case '\r':
			escape = 'r';
			break;
		case '\\':
			escape = '\\';
			break;
		case '\'':
			escape = '\'';
			break;
		case '\"':
			escape = '\"';
			break;
		case '\032':
			escape = 'Z';
			break;
		default:
			res.push_back(str[i]);
			continue;
		}

		res.push_back('\\');
		res.push_back(escape);
	}

	return res;
}

std::string MySQLUtil::escape_string_quote(const std::string& str, char quote)
{
	std::string res;
	size_t i;

	for (i = 0; i < str.size(); i++)
	{
		if (str[i] == quote)
			res.push_back(quote);

		res.push_back(str[i]);
	}

	return res;
}

}

