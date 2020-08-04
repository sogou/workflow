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

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <utility>
#include "StringUtil.h"
#include "URIParser.h"
/*
static bool is_unreserved[256];
static bool is_sub_delims[256];
static bool is_pchar[256];
static constexpr char sep[4] = {':', '/', '?', '#'};
static bool valid_char[7][256];

class __Init
{
public:
	__Init()
	{
		is_unreserved[(unsigned char)'-'] =
		is_unreserved[(unsigned char)'.'] =
		is_unreserved[(unsigned char)'_'] =
		is_unreserved[(unsigned char)'~'] = true;
		for (int i = 0; i < 256; i++)
		{
			if (isalnum(i))
				is_unreserved[i] = true;
		}

		is_sub_delims[(unsigned char)'!'] =
		is_sub_delims[(unsigned char)'$'] =
		is_sub_delims[(unsigned char)'&'] =
		is_sub_delims[(unsigned char)'\''] =
		is_sub_delims[(unsigned char)'('] =
		is_sub_delims[(unsigned char)')'] =
		is_sub_delims[(unsigned char)'*'] =
		is_sub_delims[(unsigned char)'+'] =
		is_sub_delims[(unsigned char)','] =
		is_sub_delims[(unsigned char)';'] =
		is_sub_delims[(unsigned char)'='] = true;

		is_pchar[(unsigned char)'%'] =
		is_pchar[(unsigned char)':'] =
		is_pchar[(unsigned char)'@'] = true;
		for (int i = 0; i < 256; i++)
		{
			if (is_unreserved[i] || is_sub_delims[i])
				is_pchar[i] = true;
		}

		for (int i = 0; i < 7; i++)
		{
			bool *arr = valid_char[i];
			switch (i)
			{
			case 0://scheme
				arr[(unsigned char)'+'] =
				arr[(unsigned char)'-'] =
				arr[(unsigned char)'.'] = true;
				for (int i = 0; i < 256; i++)
				{
					if (isalnum(i))
						arr[i] = true;
				}

				break;

			case 1://userinfo
				arr[(unsigned char)':'] =
				arr[(unsigned char)'%'] = true;
				for (int i = 0; i < 256; i++)
				{
					if (is_unreserved[i] || is_sub_delims[i])
						arr[i] = true;
				}

				break;

			case 2://host
				arr[(unsigned char)'%'] = true;
				for (int i = 0; i < 256; i++)
				{
					if (is_unreserved[i] || is_sub_delims[i])
						arr[i] = true;
				}

				break;

			case 3://port
				for (int i = 0; i < 256; i++)
				{
					if (isdigit(i))
						arr[i] = true;
				}

				break;

			case 4://path
				arr[(unsigned char)'/'] = true;
				for (int i = 0; i < 256; i++)
				{
					if (is_pchar[i])
						arr[i] = true;
				}

				break;

			case 5://query
			case 6://fragment
				arr[(unsigned char)'/'] =
				arr[(unsigned char)'?'] = true;
				for (int i = 0; i < 256; i++)
				{
					if (is_pchar[i])
						arr[i] = true;
				}
				break;

			default:
				break;
			}
		}
	}
};

static __Init g_init;
*/
static constexpr char sep[4] = {':', '/', '?', '#'};
//scheme://[userinfo@]host[:port][/path][?query][#fragment]
//0-6 (scheme, userinfo, host, port, path, query, fragment)

static constexpr bool valid_char[7][256] = {
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

	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
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
		0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
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
		0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
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
	}
};

void ParsedURI::deinit()
{
	if (scheme)
	{
		free(scheme);
		scheme = NULL;
	}

	if (host)
	{
		free(host);
		host = NULL;
	}

	if (path)
	{
		free(path);
		path = NULL;
	}

	if (userinfo)
	{
		free(userinfo);
		userinfo = NULL;
	}

	if (port)
	{
		free(port);
		port = NULL;
	}

	if (query)
	{
		free(query);
		query = NULL;
	}

	if (fragment)
	{
		free(fragment);
		fragment = NULL;
	}
}

void ParsedURI::__copy(const ParsedURI& copy)
{
	init();
	state = copy.state;
	error = copy.error;
	if (state == URI_STATE_SUCCESS)
	{
		bool succ = false;

		do
		{
			if (copy.scheme)
			{
				scheme = strdup(copy.scheme);
				if (!scheme)
					break;
			}

			if (copy.userinfo)
			{
				userinfo = strdup(copy.userinfo);
				if (!userinfo)
					break;
			}

			if (copy.host)
			{
				host = strdup(copy.host);
				if (!host)
					break;
			}

			if (copy.port)
			{
				port = strdup(copy.port);
				if (!port)
					break;
			}

			if (copy.path)
			{
				path = strdup(copy.path);
				if (!path)
					break;
			}

			if (copy.query)
			{
				query = strdup(copy.query);
				if (!query)
					break;
			}

			if (copy.fragment)
			{
				fragment = strdup(copy.fragment);
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

void ParsedURI::__move(ParsedURI&& move)
{
	scheme = move.scheme;
	userinfo = move.userinfo;
	host = move.host;
	port = move.port;
	path = move.path;
	query = move.query;
	fragment = move.fragment;
	state = move.state;
	error = move.error;

	move.init();
}

int URIParser::parse(const char *str, ParsedURI& uri)
{
	uri.state = URI_STATE_INVALID;
	if (!str[0])
		return -1;//uri empty

	if (!isalpha((unsigned char)str[0]))
		return -1;//uri first char must be alpha

	int st[7] = {0};
	int ed[7] = {0};
	int cur = 1;
	while (valid_char[0][(unsigned char)str[cur]])
		cur++;

	ed[0] = cur;
	if (str[cur] && str[cur + 1] && str[cur + 2]
		&& str[cur] == ':' && str[cur + 1] =='/' && str[cur + 2] =='/')
		cur += 3;
	else
		return -1;//not match with ://

	int last = cur;
	int idx = 0;
	bool is_ipv6 = false;

	for (int i = cur; str[i]; i++)
	{
		if (str[i] == '@')
		{
			st[1] = cur;
			ed[1] = i;
			cur = i + 1;
			break;
		}
	}

	if (str[cur] == '[')
	{
		st[2] = ++cur;
		while (str[cur] && str[cur] != ']')
			cur++;

		if (str[cur] != ']')
			return -1;

		is_ipv6 = true;
		ed[2] = cur++;
		if (str[cur])
		{
			bool is_sep = false;

			for (int i = 0; i < 4; i++)
			{
				if (str[cur] == sep[i])
				{
					is_sep = true;
					break;
				}
			}

			if (!is_sep)
				return -1;
		}
	}
	else
		last = cur;

	//userinfo@host:port/path?query#fragment
	//host[:port][/path][?query][#fragment]
	for (; str[cur]; cur++)
	{
		if (idx < 4)
		{
			for (int i = idx; i < 4; i++)
			{
				if (str[cur] == sep[i])
				{
					if (is_ipv6)
						is_ipv6 = false;
					else
					{
						st[idx + 2] = last;
						ed[idx + 2] = cur;
					}

					idx = i + 1;
					if (sep[i] == '/')
						last = cur;
					else
						last = cur + 1;

					break;
				}
			}
		}
	}

	if (cur > last && !is_ipv6)
	{
		st[idx + 2] = last;
		ed[idx + 2] = cur;
	}

	//check valid, skip scheme because of already checked
	for (int i = 1; i < 7; i++)
	{
		for (int j = st[i]; j < ed[i]; j++)
			if (!valid_char[i][(unsigned char)str[j]])
				return -1;//invalid char
	}

	char **dst[7] = {&uri.scheme, &uri.userinfo, &uri.host, &uri.port,
					 &uri.path, &uri.query, &uri.fragment};

	for (int i = 0; i < 7; i++)
	{
		if (ed[i] > st[i])
		{
			size_t len = ed[i] - st[i];

			*dst[i] = (char *)realloc(*dst[i], len + 1);
			if (*dst[i] == NULL)
			{
				uri.state = URI_STATE_ERROR;
				uri.error = errno;
				return -1;
			}

			memcpy(*dst[i], str + st[i], len);
			(*dst[i])[len] = '\0';

			if (i == 2 && len >= 3 && (*dst[2])[0] == '%' && (*dst[2])[1] == '2' && ((*dst[2])[2] == 'F' || (*dst[2])[2] == 'f'))
			{
				len = StringUtil::url_decode(*dst[2], len);
				(*dst[i])[len] = '\0';
			}
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

