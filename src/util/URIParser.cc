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
           Wang Zhulei (wangzhulei@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
*/

#include <string.h>
#include <errno.h>
#include <utility>
#include <vector>
#include <map>
#include "StringUtil.h"
#include "URIParser.h"

enum
{
	URI_SCHEME,
	URI_USERINFO,
	URI_HOST,
	URI_PORT,
	URI_QUERY,
	URI_FRAGMENT,
	URI_PATH,
	URI_PART_ELEMENTS,
};

//scheme://[userinfo@]host[:port][/path][?query][#fragment]
//0-6 (scheme, userinfo, host, port, path, query, fragment)
static constexpr unsigned char valid_char[4][256] = {
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	},
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0,
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	},
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0,
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	},
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	},
};

static unsigned char authority_map[256] = {
	URI_PART_ELEMENTS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, URI_FRAGMENT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, URI_PATH,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, URI_HOST, 0, 0, 0, 0, URI_QUERY,
	URI_USERINFO, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

ParsedURI::ParsedURI(ParsedURI&& uri)
{
	scheme = uri.scheme;
	userinfo = uri.userinfo;
	host = uri.host;
	port = uri.port;
	path = uri.path;
	query = uri.query;
	fragment = uri.fragment;
	state = uri.state;
	error = uri.error;
	uri.init();
}

ParsedURI& ParsedURI::operator= (ParsedURI&& uri)
{
	if (this != &uri)
	{
		deinit();
		scheme = uri.scheme;
		userinfo = uri.userinfo;
		host = uri.host;
		port = uri.port;
		path = uri.path;
		query = uri.query;
		fragment = uri.fragment;
		state = uri.state;
		error = uri.error;
		uri.init();
	}

	return *this;
}

void ParsedURI::copy(const ParsedURI& uri)
{
	init();
	state = uri.state;
	error = uri.error;
	if (state == URI_STATE_SUCCESS)
	{
		bool succ = false;

		do
		{
			if (uri.scheme)
			{
				scheme = strdup(uri.scheme);
				if (!scheme)
					break;
			}

			if (uri.userinfo)
			{
				userinfo = strdup(uri.userinfo);
				if (!userinfo)
					break;
			}

			if (uri.host)
			{
				host = strdup(uri.host);
				if (!host)
					break;
			}

			if (uri.port)
			{
				port = strdup(uri.port);
				if (!port)
					break;
			}

			if (uri.path)
			{
				path = strdup(uri.path);
				if (!path)
					break;
			}

			if (uri.query)
			{
				query = strdup(uri.query);
				if (!query)
					break;
			}

			if (uri.fragment)
			{
				fragment = strdup(uri.fragment);
				if (!fragment)
					break;
			}

			succ = true;
		} while (0);

		if (!succ)
		{
			deinit();
			init();
			state = URI_STATE_ERROR;
			error = errno;
		}
	}
}

int URIParser::parse(const char *str, ParsedURI& uri)
{
	uri.state = URI_STATE_INVALID;

	int start_idx[URI_PART_ELEMENTS] = {0};
	int end_idx[URI_PART_ELEMENTS] = {0};
	int pre_state = URI_SCHEME;
	bool in_ipv6 = false;
	int i;

	for (i = 0; str[i]; i++)
	{
		if (str[i] == ':')
		{
			end_idx[URI_SCHEME] = i++;
			break;
		}
	}

	if (end_idx[URI_SCHEME] == 0)
		return -1;

	if (str[i] == '/' && str[i + 1] == '/')
	{
		pre_state = URI_HOST;
		i += 2;
		if (str[i] == '[')
			in_ipv6 = true;
		else
			start_idx[URI_USERINFO] = i;

		start_idx[URI_HOST] = i;
	}
	else
	{
		pre_state = URI_PATH;
		start_idx[URI_PATH] = i;
	}

	bool skip_path = false;
	if (start_idx[URI_PATH] == 0)
	{
		for (; ; i++)
		{
			switch (authority_map[(unsigned char)str[i]])
			{
				case 0:
					continue;

				case URI_USERINFO:
					if (str[i + 1] == '[')
						in_ipv6 = true;

					end_idx[URI_USERINFO] = i;
					start_idx[URI_HOST] = i + 1;
					pre_state = URI_HOST;
					continue;

				case URI_HOST:
					if (str[i - 1] == ']')
						in_ipv6 = false;

					if (!in_ipv6)
					{
						end_idx[URI_HOST] = i;
						start_idx[URI_PORT] = i + 1;
						pre_state = URI_PORT;
					}
					continue;

				case URI_QUERY:
					end_idx[pre_state] = i;
					start_idx[URI_QUERY] = i + 1;
					pre_state = URI_QUERY;
					skip_path = true;
					continue;

				case URI_FRAGMENT:
					end_idx[pre_state] = i;
					start_idx[URI_FRAGMENT] = i + 1;
					end_idx[URI_FRAGMENT] = i + strlen(str + i);
					pre_state = URI_PART_ELEMENTS;
					skip_path = true;
					break;

				case URI_PATH:
					if (skip_path)
						continue;

					start_idx[URI_PATH] = i;
					break;

				case URI_PART_ELEMENTS:
					skip_path = true;
					break;
			}

			break;
		}
	}

	if (pre_state != URI_PART_ELEMENTS)
		end_idx[pre_state] = i;

	if (!skip_path)
	{
		pre_state = URI_PATH;
		for (; str[i]; i++)
		{
			if (str[i] == '?')
			{
				end_idx[URI_PATH] = i;
				start_idx[URI_QUERY] = i + 1;
				pre_state = URI_QUERY;
				while (str[i + 1])
				{
					if (str[++i] == '#')
						break;
				}
			}

			if (str[i] == '#')
			{
				end_idx[pre_state] = i;
				start_idx[URI_FRAGMENT] = i + 1;
				pre_state = URI_FRAGMENT;
				break;
			}
		}

		end_idx[pre_state] = i + strlen(str + i);
	}

	for (int i = 0; i < URI_QUERY; i++)
	{
		for (int j = start_idx[i]; j < end_idx[i]; j++)
		{
			if (!valid_char[i][(unsigned char)str[j]])
				return -1;//invalid char
		}
	}

	char **dst[URI_PART_ELEMENTS] = {&uri.scheme, &uri.userinfo, &uri.host, &uri.port,
					 &uri.query, &uri.fragment, &uri.path};

	for (int i = 0; i < URI_PART_ELEMENTS; i++)
	{
		if (end_idx[i] > start_idx[i])
		{
			size_t len = end_idx[i] - start_idx[i];

			*dst[i] = (char *)realloc(*dst[i], len + 1);
			if (*dst[i] == NULL)
			{
				uri.state = URI_STATE_ERROR;
				uri.error = errno;
				return -1;
			}

			if (i == URI_HOST && str[start_idx[i]] == '[' &&
				str[end_idx[i] - 1] == ']')
			{
				len -= 2;
				memcpy(*dst[i], str + start_idx[i] + 1, len);
			}
			else
				memcpy(*dst[i], str + start_idx[i], len);

			(*dst[i])[len] = '\0';
		}
		else
		{
			free(*dst[i]);
			*dst[i] = NULL;
		}
	}

	uri.state = URI_STATE_SUCCESS;
	return 0;
}

std::map<std::string, std::vector<std::string>>
URIParser::split_query_strict(const std::string &query)
{
	std::map<std::string, std::vector<std::string>> res;

	if (query.empty())
		return res;

	std::vector<std::string> arr = StringUtil::split(query, '&');

	if (arr.empty())
		return res;

	for (const auto& ele : arr)
	{
		if (ele.empty())
			continue;

		std::vector<std::string> kv = StringUtil::split(ele, '=');
		size_t kv_size = kv.size();
		std::string& key = kv[0];

		if (key.empty())
			continue;

		if (kv_size == 1)
		{
			res[key].emplace_back();
			continue;
		}

		std::string& val = kv[1];

		if (val.empty())
			res[key].emplace_back();
		else
			res[key].emplace_back(std::move(val));
	}

	return res;
}

std::map<std::string, std::string> URIParser::split_query(const std::string &query)
{
	std::map<std::string, std::string> res;

	if (query.empty())
		return res;

	std::vector<std::string> arr = StringUtil::split(query, '&');

	if (arr.empty())
		return res;

	for (const auto& ele : arr)
	{
		if (ele.empty())
			continue;

		std::vector<std::string> kv = StringUtil::split(ele, '=');
		size_t kv_size = kv.size();
		std::string& key = kv[0];

		if (key.empty() || res.count(key) > 0)
			continue;

		if (kv_size == 1)
		{
			res.emplace(std::move(key), "");
			continue;
		}

		std::string& val = kv[1];

		if (val.empty())
			res.emplace(std::move(key), "");
		else
			res.emplace(std::move(key), std::move(val));
	}

	return res;
}

std::vector<std::string> URIParser::split_path(const std::string &path)
{
	return StringUtil::split_filter_empty(path, '/');
}

