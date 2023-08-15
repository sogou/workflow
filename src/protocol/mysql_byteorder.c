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

  Authors: Li Yingxin (liyingxin@sogou-inc.com)
*/

#include "mysql_byteorder.h"

int decode_length_safe(unsigned long long *res, const unsigned char **pos,
					   const unsigned char *end)
{
	const unsigned char *p = *pos;

	if (p >= end)
		return 0;

	switch (*p)
	{
	default:
		*res = *p;
		*pos = p + 1;
		break;

	case 251:
		*res = (~0ULL);
		*pos = p + 1;
		break;

	case 252:
		if (p + 2 > end)
			return 0;

		*res = uint2korr(p + 1);
		*pos = p + 3;
		break;

	case 253:
		if (p + 3 > end)
			return 0;

		*res = uint3korr(p + 1);
		*pos = p + 4;
		break;

	case 254:
		if (p + 8 > end)
			return 0;

		*res = uint8korr(p + 1);
		*pos = p + 9;
		break;

	case 255:
		return -1;
	}

	return 1;
}

int decode_string(const unsigned char **str, unsigned long long *len,
				  const unsigned char **pos, const unsigned char *end)
{
	unsigned long long length;

	if (decode_length_safe(&length, pos, end) <= 0)
		return 0;

	if (length == (~0ULL))
		length = 0;

	if (*pos + length > end)
		return 0;

	*len = length;
	*str = *pos;
	*pos = *pos + length;
	return 1;
}

