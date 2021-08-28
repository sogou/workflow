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
//scheme://[userinfo@]host[:port][/path][?query][#fragment]
//0-6 (scheme, userinfo, host, port, path, query, fragment)

static constexpr bool valid_char[11][256] = {
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
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	},
	{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
	},
	{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
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
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	},
	{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
		0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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

enum
{
	URI_SCHEME,
	URI_USERINFO,
	URI_HOST,
	URI_PORT,
	URI_PATH,
	URI_QUERY,
	URI_FRAGMENT,
	URI_NUM,
	URI_AUTH,
	URI_AUTH_PATH,
	URI_IPV6,
};

int URIParser::parse(const char *str, ParsedURI& uri)
{
	uri.state = URI_STATE_INVALID;

	int st[URI_NUM] = {0};
	int ed[URI_NUM] = {0};
	int state = URI_SCHEME;
	int pre_state = URI_SCHEME;
	int i;

	for (i = 0; str[i]; i++)
	{
		switch (str[i])
		{
		case ':':
			if (state == URI_SCHEME)
			{
				state = URI_AUTH_PATH;
				ed[URI_SCHEME] = i;
			}
			else if (state == URI_AUTH)
			{
				state = URI_PORT;
				st[URI_PORT] = i + 1;
				ed[URI_HOST] = i;
			}
			else if (state == URI_HOST)
			{
				state = URI_PORT;
				st[URI_PORT] = i + 1;
				ed[URI_HOST] = i;
			}
			else if (!valid_char[state][(unsigned char)str[i]])
				return -1;

			break;

		case '/':
			if (state == URI_AUTH_PATH)
			{
				if (str[i + 1] == '/')
				{
					state = URI_AUTH;
					i++;
					st[URI_USERINFO] = i + 1;
					st[URI_HOST] = i + 1;
				}
				else
				{
					state = URI_PATH;
					st[URI_PATH] = i;
				}
			}
			else if (state == URI_HOST)
			{
				state = URI_PATH;
				if (pre_state != URI_IPV6)
					ed[URI_HOST] = i;
				st[URI_PATH] = i;
			}
			else if (state == URI_PORT)
			{
				state = URI_PATH;
				ed[URI_PORT] = i;
				st[URI_PATH] = i;
			}
			else if (!valid_char[state][(unsigned char)str[i]])
				return -1;

			break;

		case '?':
			if (state == URI_PATH)
			{
				ed[URI_PATH] = i;
				st[URI_QUERY] = i + 1;
				state = URI_QUERY;
			}
			else if (!valid_char[state][(unsigned char)str[i]])
				return -1;

			break;

		case '#':
			if (state == URI_QUERY)
			{
				ed[URI_QUERY] = i;
				st[URI_FRAGMENT] = i + 1;
				state = URI_FRAGMENT;
			}
			else if (!valid_char[state][(unsigned char)str[i]])
				return -1;

			break;

		case '@':
			if (state == URI_AUTH)
			{
				state = URI_HOST;
				ed[URI_USERINFO] = i;
				st[URI_HOST] = i + 1;
			}
			else if (!valid_char[state][(unsigned char)str[i]])
				return -1;

			break;

		case '[':
			if (state == URI_AUTH)
			{
				state = URI_IPV6;
				st[URI_HOST] = i + 1;
			}
			else if (state == URI_IPV6)
				return -1;
			else if (!valid_char[state][(unsigned char)str[i]])
				return -1;

			break;

		case ']':
			if (state == URI_IPV6)
			{
				ed[URI_HOST] = i;
				state = URI_HOST;
				pre_state = URI_IPV6;
			}
			else if (!valid_char[state][(unsigned char)str[i]])
				return -1;

			break;

		default:
			if (state == URI_AUTH_PATH)
			{
				st[URI_PATH] = i;
				state = URI_PATH;
			}

			if (!valid_char[state][(unsigned char)str[i]])
				return -1;

			break;
		}
	}

	ed[state] = i;

	char **dst[URI_NUM] = {&uri.scheme, &uri.userinfo, &uri.host, &uri.port,
					 &uri.path, &uri.query, &uri.fragment};

	for (int i = 0; i < URI_NUM; i++)
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

			if (i == URI_HOST && len >= 3 && 
				(*dst[URI_HOST])[0] == '%' && (*dst[URI_HOST])[1] == '2' &&
				 ((*dst[URI_HOST])[2] == 'F' || (*dst[URI_HOST])[2] == 'f'))
			{
				len = StringUtil::url_decode(*dst[URI_HOST], len);
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

