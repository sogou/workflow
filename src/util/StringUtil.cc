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

#include <ctype.h>
#include <string>
#include <vector>
#include <algorithm>
#include "StringUtil.h"

static int __htoi(unsigned char *s)
{
	int value;
	int c;

	c = s[0];
	if (isupper(c))
		c = tolower(c);

	value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

	c = s[1];
	if (isupper(c))
		c = tolower(c);

	value += (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10);
	return value;
}

static inline char __itoh(int n)
{
	if (n > 9)
		return n - 10 + 'A';

	return n + '0';
}

size_t StringUtil::url_decode(char *str, size_t len)
{
	char *dest = str;
	char *data = str;

	while (len--)
	{
		if (*data == '%' && len >= 2
			&& isxdigit(*(data + 1))
			&& isxdigit(*(data + 2)))
		{
			*dest = __htoi((unsigned char *)data + 1);
			data += 2;
			len -= 2;
		}
		else if (*data == '+')
			*dest = ' ';
		else
			*dest = *data;

		data++;
		dest++;
	}

	*dest = '\0';
	return dest - str;
}

void StringUtil::url_decode(std::string& str)
{
	if (str.empty())
		return;

	size_t sz = url_decode(const_cast<char *>(str.c_str()), str.size());

	str.resize(sz);
}

std::string StringUtil::url_encode(const std::string& str)
{
	std::string res;
	const char *cur = str.c_str();
	const char *ed = cur + str.size();

	while (cur < ed)
	{
		if (*cur == ' ')
			res += '+';
		else if (isalnum(*cur) || *cur == '-' || *cur == '_' || *cur == '.'
				|| *cur == '!' || *cur == '~' || *cur == '*' || *cur == '\''
				|| *cur == '(' || *cur == ')' || *cur == ':' || *cur == '/'
				|| *cur == '@' || *cur == '?' || *cur == '#' || *cur == '&')
			res += *cur;
		else
		{
			res += '%';
			res += __itoh(((const unsigned char)(*cur)) >> 4);
			res += __itoh(((const unsigned char)(*cur)) % 16);
		}

		cur++;
	}

	return res;
}

std::string StringUtil::url_encode_component(const std::string& str)
{
	std::string res;
	const char *cur = str.c_str();
	const char *ed = cur + str.size();

	while (cur < ed)
	{
		if (*cur == ' ')
			res += '+';
		else if (isalnum(*cur) || *cur == '-' || *cur == '_' || *cur == '.'
				|| *cur == '!' || *cur == '~' || *cur == '*' || *cur == '\''
				|| *cur == '(' || *cur == ')')
			res += *cur;
		else
		{
			res += '%';
			res += __itoh(((const unsigned char)(*cur)) >> 4);
			res += __itoh(((const unsigned char)(*cur)) % 16);
		}

		cur++;
	}

	return res;
}

std::vector<std::string> StringUtil::split(const std::string& str, char sep)
{
	std::vector<std::string> res;
	std::string::const_iterator start = str.begin();
	std::string::const_iterator end = str.end();
	std::string::const_iterator next = find(start, end, sep);

	while (next != end)
	{
		res.emplace_back(start, next);
		start = next + 1;
		next = std::find(start, end, sep);
	}

	res.emplace_back(start, next);
	return res;
}

std::vector<std::string> StringUtil::split_filter_empty(const std::string& str,
														char sep)
{
	std::vector<std::string> res;
	std::string::const_iterator start = str.begin();
	std::string::const_iterator end = str.end();
	std::string::const_iterator next = find(start, end, sep);

	while (next != end)
	{
		if (start < next)
			res.emplace_back(start, next);

		start = next + 1;
		next = find(start, end, sep);
	}

	if (start < next)
		res.emplace_back(start, next);

	return res;
}

std::string StringUtil::strip(const std::string& str)
{
	std::string res;

	if (!str.empty())
	{
		const char *st = str.c_str();
		const char *ed = st + str.size() - 1;

		while (st <= ed)
		{
			if (!isspace(*st))
				break;

			st++;
		}

		while (ed >= st)
		{
			if (!isspace(*ed))
				break;

			ed--;
		}

		if (ed >= st)
			res.assign(st, ed - st + 1);
	}

	return res;
}

bool StringUtil::start_with(const std::string& str, const std::string& prefix)
{
	size_t prefix_len = prefix.size();

	if (str.size() < prefix_len)
		return false;

	for (size_t i = 0; i < prefix_len; i++)
	{
		if (str[i] != prefix[i])
			return false;
	}

	return true;
}

