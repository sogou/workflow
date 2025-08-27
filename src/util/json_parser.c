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

#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include "list.h"
#include "json_parser.h"

#define JSON_DEPTH_LIMIT	1024

struct __json_object
{
	struct list_head head;
	size_t size;
};

struct __json_array
{
	struct list_head head;
	size_t size;
};

struct __json_value
{
	union
	{
		char *string;
		double number;
		json_object_t object;
		json_array_t array;
	} value;
	int type;
};

struct __json_member
{
	struct list_head list;
	json_value_t value;
	char name[1];
};

struct __json_element
{
	struct list_head list;
	json_value_t value;
};

typedef struct __json_member json_member_t;
typedef struct __json_element json_element_t;

static const int __whitespace_map[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1,
};

static int __json_isspace(char c)
{
	return __whitespace_map[(unsigned char)c];
}

static int __json_isdigit(char c)
{
	return (unsigned int)(c - '0') <= 9;
}

#define isspace(c)	__json_isspace(c)
#define isdigit(c)	__json_isdigit(c)

static const int __character_map[256] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
};

static int __json_string_length(const char *cursor, size_t *escape, size_t *len)
{
	size_t esc = 0;
	size_t n = 0;

	while (1)
	{
		while (__character_map[(unsigned char)cursor[n]] == 0)
			n++;

		if (cursor[n] == '\"')
			break;

		if (cursor[n] != '\\')
			return -2;

		cursor++;
		if (cursor[n] == '\0')
			return -2;

		esc++;
		n++;
	}

	*escape = esc;
	*len = n;
	return 0;
}

static int __parse_json_hex4(const char *cursor, const char **end,
							 unsigned int *code)
{
	int hex;
	int i;

	*code = 0;
	for (i = 0; i < 4; i++)
	{
		hex = *cursor;
		if (hex >= '0' && hex <= '9')
			hex = hex - '0';
		else
		{
			hex |= 0x20;
			if (hex >= 'a' && hex <= 'f')
				hex = hex - 'a' + 10;
			else
				return -2;
		}

		*code = (*code << 4) + hex;
		cursor++;
	}

	*end = cursor;
	return 0;
}

static int __parse_json_unicode(const char *cursor, const char **end,
								char *utf8)
{
	unsigned int code;
	unsigned int next;
	int ret;

	ret = __parse_json_hex4(cursor, end, &code);
	if (ret < 0)
		return ret;

	if (code >= 0xdc00 && code <= 0xdfff)
		return -2;

	if (code >= 0xd800 && code <= 0xdbff)
	{
		cursor = *end;
		if (*cursor != '\\')
			return -2;

		cursor++;
		if (*cursor != 'u')
			return -2;

		cursor++;
		ret = __parse_json_hex4(cursor, end, &next);
		if (ret < 0)
			return ret;

		if (next < 0xdc00 || next > 0xdfff)
			return -2;

		code = (((code & 0x3ff) << 10) | (next & 0x3ff)) + 0x10000;
	}

	if (code <= 0x7f)
	{
		utf8[0] = code;
		return 1;
	}
	else if (code <= 0x7ff)
	{
		utf8[0] = 0xc0 | (code >> 6);
		utf8[1] = 0x80 | (code & 0x3f);
		return 2;
	}
	else if (code <= 0xffff)
	{
		utf8[0] = 0xe0 | (code >> 12);
		utf8[1] = 0x80 | ((code >> 6) & 0x3f);
		utf8[2] = 0x80 | (code & 0x3f);
		return 3;
	}
	else
	{
		utf8[0] = 0xf0 | (code >> 18);
		utf8[1] = 0x80 | ((code >> 12) & 0x3f);
		utf8[2] = 0x80 | ((code >> 6) & 0x3f);
		utf8[3] = 0x80 | (code & 0x3f);
		return 4;
	}
}

static int __parse_json_string(const char *cursor, const char **end,
							   size_t escape, char *str)
{
	int ret;

	while (escape > 0)
	{
		while (*cursor != '\\')
		{
			*str = *cursor;
			cursor++;
			str++;
		}

		escape--;
		cursor++;
		switch (*cursor)
		{
		case '\"':
			*str = '\"';
			break;
		case '\\':
			*str = '\\';
			break;
		case '/':
			*str = '/';
			break;
		case 'b':
			*str = '\b';
			break;
		case 'f':
			*str = '\f';
			break;
		case 'n':
			*str = '\n';
			break;
		case 'r':
			*str = '\r';
			break;
		case 't':
			*str = '\t';
			break;
		case 'u':
			cursor++;
			ret = __parse_json_unicode(cursor, &cursor, str);
			if (ret < 0)
				return ret;

			if (ret == 4)
				escape--;

			str += ret;
			continue;

		default:
			return -2;
		}

		cursor++;
		str++;
	}

	while (cursor[0] != '\"' && cursor[1] != '\"' &&
		   cursor[2] != '\"' && cursor[3] != '\"')
	{
		memcpy(str, cursor, 4);
		cursor += 4;
		str += 4;
	}

	if (cursor[0] != '\"' && cursor[1] != '\"')
	{
		memcpy(str, cursor, 2);
		cursor += 2;
		str += 2;
	}

	if (*cursor != '\"')
	{
		*str = *cursor;
		cursor++;
		str++;
	}

	*str = '\0';
	*end = cursor + 1;
	return 0;
}

static const double __power_of_10[309] = {
	1e0,	1e1,	1e2,	1e3,	1e4,
	1e5,	1e6,	1e7,	1e8,	1e9,
	1e10,	1e11,	1e12,	1e13,	1e14,
	1e15,	1e16,	1e17,	1e18,	1e19,
	1e20,	1e21,	1e22,	1e23,	1e24,
	1e25,	1e26,	1e27,	1e28,	1e29,
	1e30,	1e31,	1e32,	1e33,	1e34,
	1e35,	1e36,	1e37,	1e38,	1e39,
	1e40,	1e41,	1e42,	1e43,	1e44,
	1e45,	1e46,	1e47,	1e48,	1e49,
	1e50,	1e51,	1e52,	1e53,	1e54,
	1e55,	1e56,	1e57,	1e58,	1e59,
	1e60,	1e61,	1e62,	1e63,	1e64,
	1e65,	1e66,	1e67,	1e68,	1e69,
	1e70,	1e71,	1e72,	1e73,	1e74,
	1e75,	1e76,	1e77,	1e78,	1e79,
	1e80,	1e81,	1e82,	1e83,	1e84,
	1e85,	1e86,	1e87,	1e88,	1e89,
	1e90,	1e91,	1e92,	1e93,	1e94,
	1e95,	1e96,	1e97,	1e98,	1e99,
	1e100,	1e101,	1e102,	1e103,	1e104,
	1e105,	1e106,	1e107,	1e108,	1e109,
	1e110,	1e111,	1e112,	1e113,	1e114,
	1e115,	1e116,	1e117,	1e118,	1e119,
	1e120,	1e121,	1e122,	1e123,	1e124,
	1e125,	1e126,	1e127,	1e128,	1e129,
	1e130,	1e131,	1e132,	1e133,	1e134,
	1e135,	1e136,	1e137,	1e138,	1e139,
	1e140,	1e141,	1e142,	1e143,	1e144,
	1e145,	1e146,	1e147,	1e148,	1e149,
	1e150,	1e151,	1e152,	1e153,	1e154,
	1e155,	1e156,	1e157,	1e158,	1e159,
	1e160,	1e161,	1e162,	1e163,	1e164,
	1e165,	1e166,	1e167,	1e168,	1e169,
	1e170,	1e171,	1e172,	1e173,	1e174,
	1e175,	1e176,	1e177,	1e178,	1e179,
	1e180,	1e181,	1e182,	1e183,	1e184,
	1e185,	1e186,	1e187,	1e188,	1e189,
	1e190,	1e191,	1e192,	1e193,	1e194,
	1e195,	1e196,	1e197,	1e198,	1e199,
	1e200,	1e201,	1e202,	1e203,	1e204,
	1e205,	1e206,	1e207,	1e208,	1e209,
	1e210,	1e211,	1e212,	1e213,	1e214,
	1e215,	1e216,	1e217,	1e218,	1e219,
	1e220,	1e221,	1e222,	1e223,	1e224,
	1e225,	1e226,	1e227,	1e228,	1e229,
	1e230,	1e231,	1e232,	1e233,	1e234,
	1e235,	1e236,	1e237,	1e238,	1e239,
	1e240,	1e241,	1e242,	1e243,	1e244,
	1e245,	1e246,	1e247,	1e248,	1e249,
	1e250,	1e251,	1e252,	1e253,	1e254,
	1e255,	1e256,	1e257,	1e258,	1e259,
	1e260,	1e261,	1e262,	1e263,	1e264,
	1e265,	1e266,	1e267,	1e268,	1e269,
	1e270,	1e271,	1e272,	1e273,	1e274,
	1e275,	1e276,	1e277,	1e278,	1e279,
	1e280,	1e281,	1e282,	1e283,	1e284,
	1e285,	1e286,	1e287,	1e288,	1e289,
	1e290,	1e291,	1e292,	1e293,	1e294,
	1e295,	1e296,	1e297,	1e298,	1e299,
	1e300,	1e301,	1e302,	1e303,	1e304,
	1e305,	1e306,	1e307,	1e308
};

static int __parse_json_number(const char *cursor, const char **end,
							   double *num)
{
	unsigned int digit;
	long long exp = 0;
	long long mant;
	int figures;
	int minus;
	double n;

	minus = (*cursor == '-');
	if (minus)
		cursor++;

	mant = *cursor - '0';
	if (mant >= 1 && mant <= 9)
	{
		figures = 1;
		cursor++;
		while (1)
		{
			digit = (unsigned int)(*cursor - '0');
			if (digit <= 9 && figures < 18)
			{
				mant = 10 * mant + digit;
				figures++;
				cursor++;
			}
			else
				break;
		}

		while (isdigit(*cursor))
		{
			exp++;
			cursor++;
		}
	}
	else if (mant == 0)
	{
		figures = 0;
		cursor++;
	}
	else
		return -2;

	if (*cursor == '.')
	{
		const char *frac;

		cursor++;
		if (!isdigit(*cursor))
			return -2;

		frac = cursor;
		if (figures == 0)
		{
			while (*cursor == '0')
				cursor++;
		}

		while (1)
		{
			digit = (unsigned int)(*cursor - '0');
			if (digit <= 9 && figures < 18)
			{
				mant = 10 * mant + digit;
				figures++;
				cursor++;
			}
			else
				break;
		}

		exp -= cursor - frac;
		while (isdigit(*cursor))
			cursor++;
	}

	if (*cursor == 'E' || *cursor == 'e')
	{
		long long e;
		char sign;

		cursor++;
		sign = *cursor;
		if (sign == '+' || sign == '-')
			cursor++;

		if (!isdigit(*cursor))
			return -2;

		e = *cursor - '0';
		cursor++;
		while (1)
		{
			digit = (unsigned int)(*cursor - '0');
			if (digit <= 9 && e < 100000000000000000)
			{
				e = 10 * e + digit;
				cursor++;
			}
			else
				break;
		}

		while (isdigit(*cursor))
			cursor++;

		if (sign == '-')
			e = -e;

		exp += e;
	}

	if (exp != 0 && figures != 0)
	{
		while (exp > 0 && figures < 18)
		{
			mant *= 10;
			figures++;
			exp--;
		}

		while (exp < 0 && mant % 10 == 0)
		{
			mant /= 10;
			figures--;
			exp++;
		}
	}

	n = mant;
	if (exp != 0 && figures != 0)
	{
		if (exp > 0)
		{
			if (exp > 291)
				n = INFINITY;
			else
				n *= __power_of_10[exp];
		}
		else
		{
			if (exp > -309)
				n /= __power_of_10[-exp];
			else if (exp > -324 - figures)
			{
				n /= __power_of_10[-exp - 308];
				n /= __power_of_10[308];
			}
			else
				n = 0.0;
		}
	}

	if (minus)
		n = -n;

	*num = n;
	*end = cursor;
	return 0;
}

static int __parse_json_value(const char *cursor, const char **end,
							  int depth, json_value_t *val);

static void __destroy_json_value(json_value_t *val);

static int __parse_json_member(const char *cursor, const char **end,
							   size_t escape, size_t len,
							   int depth, json_member_t *memb)
{
	int ret;

	if (escape != 0)
	{
		ret = __parse_json_string(cursor, &cursor, escape, memb->name);
		if (ret < 0)
			return ret;
	}
	else
	{
		memcpy(memb->name, cursor, len);
		memb->name[len] = '\0';
		cursor += len + 1;
	}

	while (isspace(*cursor))
		cursor++;

	if (*cursor != ':')
		return -2;

	cursor++;
	while (isspace(*cursor))
		cursor++;

	ret = __parse_json_value(cursor, &cursor, depth, &memb->value);
	if (ret < 0)
		return ret;

	*end = cursor;
	return 0;
}

static int __parse_json_members(const char *cursor, const char **end,
								int depth, json_object_t *obj)
{
	json_member_t *memb;
	size_t escape;
	size_t len;
	int ret;

	while (isspace(*cursor))
		cursor++;

	if (*cursor == '}')
	{
		*end = cursor + 1;
		return 0;
	}

	while (1)
	{
		if (*cursor != '\"')
			return -2;

		cursor++;
		ret = __json_string_length(cursor, &escape, &len);
		if (ret < 0)
			return ret;

		memb = (json_member_t *)malloc(offsetof(json_member_t, name) + len + 1);
		if (!memb)
			return -1;

		ret = __parse_json_member(cursor, &cursor, escape, len, depth, memb);
		if (ret < 0)
		{
			free(memb);
			return ret;
		}

		list_add_tail(&memb->list, &obj->head);
		obj->size++;

		while (isspace(*cursor))
			cursor++;

		if (*cursor == ',')
		{
			cursor++;
			while (isspace(*cursor))
				cursor++;
		}
		else if (*cursor == '}')
			break;
		else
			return -2;
	}

	*end = cursor + 1;
	return 0;
}

static void __destroy_json_members(json_object_t *obj)
{
	struct list_head *pos, *tmp;
	json_member_t *memb;

	list_for_each_safe(pos, tmp, &obj->head)
	{
		memb = list_entry(pos, json_member_t, list);
		__destroy_json_value(&memb->value);
		free(memb);
	}
}

static int __parse_json_object(const char *cursor, const char **end,
							   int depth, json_object_t *obj)
{
	int ret;

	if (depth == JSON_DEPTH_LIMIT)
		return -3;

	INIT_LIST_HEAD(&obj->head);
	obj->size = 0;
	ret = __parse_json_members(cursor, end, depth + 1, obj);
	if (ret < 0)
	{
		__destroy_json_members(obj);
		return ret;
	}

	return 0;
}

static int __parse_json_elements(const char *cursor, const char **end,
								 int depth, json_array_t *arr)
{
	json_element_t *elem;
	int ret;

	while (isspace(*cursor))
		cursor++;

	if (*cursor == ']')
	{
		*end = cursor + 1;
		return 0;
	}

	while (1)
	{
		elem = (json_element_t *)malloc(sizeof (json_element_t));
		if (!elem)
			return -1;

		ret = __parse_json_value(cursor, &cursor, depth, &elem->value);
		if (ret < 0)
		{
			free(elem);
			return ret;
		}

		list_add_tail(&elem->list, &arr->head);
		arr->size++;

		while (isspace(*cursor))
			cursor++;

		if (*cursor == ',')
		{
			cursor++;
			while (isspace(*cursor))
				cursor++;
		}
		else if (*cursor == ']')
			break;
		else
			return -2;
	}

	*end = cursor + 1;
	return 0;
}

static void __destroy_json_elements(json_array_t *arr)
{
	struct list_head *pos, *tmp;
	json_element_t *elem;

	list_for_each_safe(pos, tmp, &arr->head)
	{
		elem = list_entry(pos, json_element_t, list);
		__destroy_json_value(&elem->value);
		free(elem);
	}
}

static int __parse_json_array(const char *cursor, const char **end,
							  int depth, json_array_t *arr)
{
	int ret;

	if (depth == JSON_DEPTH_LIMIT)
		return -3;

	INIT_LIST_HEAD(&arr->head);
	arr->size = 0;
	ret = __parse_json_elements(cursor, end, depth + 1, arr);
	if (ret < 0)
	{
		__destroy_json_elements(arr);
		return ret;
	}

	return 0;
}

static int __parse_json_value(const char *cursor, const char **end,
							  int depth, json_value_t *val)
{
	size_t escape;
	size_t len;
	int ret;

	switch (*cursor)
	{
	case '\"':
		cursor++;
		ret = __json_string_length(cursor, &escape, &len);
		if (ret < 0)
			return ret;

		val->value.string = (char *)malloc(len + 1);
		if (!val->value.string)
			return -1;

		if (escape != 0)
		{
			ret = __parse_json_string(cursor, end, escape, val->value.string);
			if (ret < 0)
			{
				free(val->value.string);
				return ret;
			}
		}
		else
		{
			memcpy(val->value.string, cursor, len);
			val->value.string[len] = '\0';
			*end = cursor + len + 1;
		}

		val->type = JSON_VALUE_STRING;
		break;

	case '-':
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		ret = __parse_json_number(cursor, end, &val->value.number);
		if (ret < 0)
			return ret;

		val->type = JSON_VALUE_NUMBER;
		break;

	case '{':
		cursor++;
		ret = __parse_json_object(cursor, end, depth, &val->value.object);
		if (ret < 0)
			return ret;

		val->type = JSON_VALUE_OBJECT;
		break;

	case '[':
		cursor++;
		ret = __parse_json_array(cursor, end, depth, &val->value.array);
		if (ret < 0)
			return ret;

		val->type = JSON_VALUE_ARRAY;
		break;

	case 't':
		if (strncmp(cursor, "true", 4) != 0)
			return -2;

		*end = cursor + 4;
		val->type = JSON_VALUE_TRUE;
		break;

	case 'f':
		if (strncmp(cursor, "false", 5) != 0)
			return -2;

		*end = cursor + 5;
		val->type = JSON_VALUE_FALSE;
		break;

	case 'n':
		if (strncmp(cursor, "null", 4) != 0)
			return -2;

		*end = cursor + 4;
		val->type = JSON_VALUE_NULL;
		break;

	default:
		return -2;
	}

	return 0;
}

static void __destroy_json_value(json_value_t *val)
{
	switch (val->type)
	{
	case JSON_VALUE_STRING:
		free(val->value.string);
		break;

	case JSON_VALUE_OBJECT:
		__destroy_json_members(&val->value.object);
		break;

	case JSON_VALUE_ARRAY:
		__destroy_json_elements(&val->value.array);
		break;
	}
}

json_value_t *json_value_parse(const char *cursor)
{
	json_value_t *val;

	val = (json_value_t *)malloc(sizeof (json_value_t));
	if (!val)
		return NULL;

	while (isspace(*cursor))
		cursor++;

	if (__parse_json_value(cursor, &cursor, 0, val) >= 0)
	{
		while (isspace(*cursor))
			cursor++;

		if (*cursor == '\0')
			return val;

		__destroy_json_value(val);
	}

	free(val);
	return NULL;
}

static void __move_json_value(json_value_t *src, json_value_t *dest)
{
	switch (src->type)
	{
	case JSON_VALUE_STRING:
		dest->value.string = src->value.string;
		break;

	case JSON_VALUE_NUMBER:
		dest->value.number = src->value.number;
		break;

	case JSON_VALUE_OBJECT:
		INIT_LIST_HEAD(&dest->value.object.head);
		list_splice(&src->value.object.head, &dest->value.object.head);
		dest->value.object.size = src->value.object.size;
		break;

	case JSON_VALUE_ARRAY:
		INIT_LIST_HEAD(&dest->value.array.head);
		list_splice(&src->value.array.head, &dest->value.array.head);
		dest->value.array.size = src->value.array.size;
		break;
	}

	dest->type = src->type;
}

static int __set_json_value(int type, va_list ap, json_value_t *val)
{
	json_value_t *src;
	const char *str;
	size_t len;

	switch (type)
	{
	case 0:
		src = va_arg(ap, json_value_t *);
		__move_json_value(src, val);
		free(src);
		return 0;

	case JSON_VALUE_STRING:
		str = va_arg(ap, const char *);
		len = strlen(str);
		val->value.string = (char *)malloc(len + 1);
		if (!val->value.string)
			return -1;

		memcpy(val->value.string, str, len + 1);
		break;

	case JSON_VALUE_NUMBER:
		val->value.number = va_arg(ap, double);
		break;

	case JSON_VALUE_OBJECT:
		INIT_LIST_HEAD(&val->value.object.head);
		val->value.object.size = 0;
		break;

	case JSON_VALUE_ARRAY:
		INIT_LIST_HEAD(&val->value.array.head);
		val->value.array.size = 0;
		break;
	}

	val->type = type;
	return 0;
}

json_value_t *json_value_create(int type, ...)
{
	json_value_t *val;
	va_list ap;
	int ret;

	val = (json_value_t *)malloc(sizeof (json_value_t));
	if (!val)
		return NULL;

	va_start(ap, type);
	ret = __set_json_value(type, ap, val);
	va_end(ap);
	if (ret >= 0)
		return val;

	free(val);
	return NULL;
}

static int __copy_json_value(const json_value_t *src, json_value_t *dest);

static int __copy_json_members(const json_object_t *src, json_object_t *dest)
{
	struct list_head *pos;
	json_member_t *entry;
	json_member_t *memb;
	size_t len;
	int ret;

	list_for_each(pos, &src->head)
	{
		entry = list_entry(pos, json_member_t, list);
		len = strlen(entry->name);
		memb = (json_member_t *)malloc(offsetof(json_member_t, name) + len + 1);
		if (!memb)
			return -1;

		ret = __copy_json_value(&entry->value, &memb->value);
		if (ret < 0)
		{
			free(memb);
			return ret;
		}

		memcpy(memb->name, entry->name, len + 1);
		list_add_tail(&memb->list, &dest->head);
		dest->size++;
	}

	return 0;
}

static int __copy_json_elements(const json_array_t *src, json_array_t *dest)
{
	struct list_head *pos;
	json_element_t *entry;
	json_element_t *elem;
	int ret;

	list_for_each(pos, &src->head)
	{
		elem = (json_element_t *)malloc(sizeof (json_element_t));
		if (!elem)
			return -1;

		entry = list_entry(pos, json_element_t, list);
		ret = __copy_json_value(&entry->value, &elem->value);
		if (ret < 0)
		{
			free(elem);
			return ret;
		}

		list_add_tail(&elem->list, &dest->head);
		dest->size++;
	}

	return 0;
}

static int __copy_json_value(const json_value_t *src, json_value_t *dest)
{
	size_t len;
	int ret;

	switch (src->type)
	{
	case JSON_VALUE_STRING:
		len = strlen(src->value.string);
		dest->value.string = (char *)malloc(len + 1);
		if (!dest->value.string)
			return -1;

		memcpy(dest->value.string, src->value.string, len + 1);
		break;

	case JSON_VALUE_NUMBER:
		dest->value.number = src->value.number;
		break;

	case JSON_VALUE_OBJECT:
		INIT_LIST_HEAD(&dest->value.object.head);
		dest->value.object.size = 0;
		ret = __copy_json_members(&src->value.object, &dest->value.object);
		if (ret < 0)
		{
			__destroy_json_members(&dest->value.object);
			return ret;
		}

		break;

	case JSON_VALUE_ARRAY:
		INIT_LIST_HEAD(&dest->value.array.head);
		dest->value.array.size = 0;
		ret = __copy_json_elements(&src->value.array, &dest->value.array);
		if (ret < 0)
		{
			__destroy_json_elements(&dest->value.array);
			return ret;
		}

		break;
	}

	dest->type = src->type;
	return 0;
}

json_value_t *json_value_copy(const json_value_t *val)
{
	json_value_t *copy;

	copy = (json_value_t *)malloc(sizeof (json_value_t));
	if (!copy)
		return NULL;

	if (__copy_json_value(val, copy) >= 0)
		return copy;

	free(copy);
	return NULL;
}

void json_value_destroy(json_value_t *val)
{
	__destroy_json_value(val);
	free(val);
}

int json_value_type(const json_value_t *val)
{
	return val->type;
}

const char *json_value_string(const json_value_t *val)
{
	if (val->type != JSON_VALUE_STRING)
		return NULL;

	return val->value.string;
}

double json_value_number(const json_value_t *val)
{
	if (val->type != JSON_VALUE_NUMBER)
		return NAN;

	return val->value.number;
}

json_object_t *json_value_object(const json_value_t *val)
{
	if (val->type != JSON_VALUE_OBJECT)
		return NULL;

	return (json_object_t *)&val->value.object;
}

json_array_t *json_value_array(const json_value_t *val)
{
	if (val->type != JSON_VALUE_ARRAY)
		return NULL;

	return (json_array_t *)&val->value.array;
}

const json_value_t *json_object_find(const char *name,
									 const json_object_t *obj)
{
	struct list_head *pos;
	json_member_t *memb;

	list_for_each(pos, &obj->head)
	{
		memb = list_entry(pos, json_member_t, list);
		if (strcmp(name, memb->name) == 0)
			return &memb->value;
	}

	return NULL;
}

size_t json_object_size(const json_object_t *obj)
{
	return obj->size;
}

const char *json_object_next_name(const char *name,
								  const json_object_t *obj)
{
	const struct list_head *pos;

	if (name)
		pos = &list_entry(name, json_member_t, name)->list;
	else
		pos = &obj->head;

	if (pos->next == &obj->head)
		return NULL;

	return list_entry(pos->next, json_member_t, list)->name;
}

const json_value_t *json_object_next_value(const json_value_t *val,
										   const json_object_t *obj)
{
	const struct list_head *pos;

	if (val)
		pos = &list_entry(val, json_member_t, value)->list;
	else
		pos = &obj->head;

	if (pos->next == &obj->head)
		return NULL;

	return &list_entry(pos->next, json_member_t, list)->value;
}

const char *json_object_prev_name(const char *name,
								  const json_object_t *obj)
{
	const struct list_head *pos;

	if (name)
		pos = &list_entry(name, json_member_t, name)->list;
	else
		pos = &obj->head;

	if (pos->prev == &obj->head)
		return NULL;

	return list_entry(pos->prev, json_member_t, list)->name;
}

const json_value_t *json_object_prev_value(const json_value_t *val,
										   const json_object_t *obj)
{
	const struct list_head *pos;

	if (val)
		pos = &list_entry(val, json_member_t, value)->list;
	else
		pos = &obj->head;

	if (pos->prev == &obj->head)
		return NULL;

	return &list_entry(pos->prev, json_member_t, list)->value;
}

const char *json_object_value_name(const json_value_t *val,
								   const json_object_t *obj)
{
	return list_entry(val, json_member_t, value)->name;
}

static const json_value_t *__json_object_insert(const char *name,
												int type, va_list ap,
												struct list_head *pos,
												json_object_t *obj)
{
	json_member_t *memb;
	size_t len;

	len = strlen(name);
	memb = (json_member_t *)malloc(offsetof(json_member_t, name) + len + 1);
	if (!memb)
		return NULL;

	memcpy(memb->name, name, len + 1);
	if (__set_json_value(type, ap, &memb->value) < 0)
	{
		free(memb);
		return NULL;
	}

	list_add(&memb->list, pos);
	obj->size++;
	return &memb->value;
}

const json_value_t *json_object_append(json_object_t *obj,
									   const char *name,
									   int type, ...)
{
	const json_value_t *val;
	va_list ap;

	va_start(ap, type);
	val = __json_object_insert(name, type, ap, obj->head.prev, obj);
	va_end(ap);
	return val;
}

const json_value_t *json_object_insert_after(const json_value_t *val,
											 json_object_t *obj,
											 const char *name,
											 int type, ...)
{
	struct list_head *pos;
	va_list ap;

	if (val)
		pos = &list_entry(val, json_member_t, value)->list;
	else
		pos = &obj->head;

	va_start(ap, type);
	val = __json_object_insert(name, type, ap, pos, obj);
	va_end(ap);
	return val;
}

const json_value_t *json_object_insert_before(const json_value_t *val,
											  json_object_t *obj,
											  const char *name,
											  int type, ...)
{
	struct list_head *pos;
	va_list ap;

	if (val)
		pos = &list_entry(val, json_member_t, value)->list;
	else
		pos = &obj->head;

	va_start(ap, type);
	val = __json_object_insert(name, type, ap, pos->prev, obj);
	va_end(ap);
	return val;
}

json_value_t *json_object_remove(const json_value_t *val,
								 json_object_t *obj)
{
	json_member_t *memb = list_entry(val, json_member_t, value);

	val = (json_value_t *)malloc(sizeof (json_value_t));
	if (!val)
		return NULL;

	list_del(&memb->list);
	obj->size--;

	__move_json_value(&memb->value, (json_value_t *)val);
	free(memb);
	return (json_value_t *)val;
}

size_t json_array_size(const json_array_t *arr)
{
	return arr->size;
}

const json_value_t *json_array_next_value(const json_value_t *val,
										  const json_array_t *arr)
{
	const struct list_head *pos;

	if (val)
		pos = &list_entry(val, json_element_t, value)->list;
	else
		pos = &arr->head;

	if (pos->next == &arr->head)
		return NULL;

	return &list_entry(pos->next, json_element_t, list)->value;
}

const json_value_t *json_array_prev_value(const json_value_t *val,
										  const json_array_t *arr)
{
	const struct list_head *pos;

	if (val)
		pos = &list_entry(val, json_element_t, value)->list;
	else
		pos = &arr->head;

	if (pos->prev == &arr->head)
		return NULL;

	return &list_entry(pos->prev, json_element_t, list)->value;
}

static const json_value_t *__json_array_insert(int type, va_list ap,
											   struct list_head *pos,
											   json_array_t *arr)
{
	json_element_t *elem;

	elem = (json_element_t *)malloc(sizeof (json_element_t));
	if (!elem)
		return NULL;

	if (__set_json_value(type, ap, &elem->value) < 0)
	{
		free(elem);
		return NULL;
	}

	list_add(&elem->list, pos);
	arr->size++;
	return &elem->value;
}

const json_value_t *json_array_append(json_array_t *arr,
									  int type, ...)
{
	const json_value_t *val;
	va_list ap;

	va_start(ap, type);
	val = __json_array_insert(type, ap, arr->head.prev, arr);
	va_end(ap);
	return val;
}

const json_value_t *json_array_insert_after(const json_value_t *val,
											json_array_t *arr,
											int type, ...)
{
	struct list_head *pos;
	va_list ap;

	if (val)
		pos = &list_entry(val, json_element_t, value)->list;
	else
		pos = &arr->head;

	va_start(ap, type);
	val = __json_array_insert(type, ap, pos, arr);
	va_end(ap);
	return val;
}

const json_value_t *json_array_insert_before(const json_value_t *val,
											 json_array_t *arr,
											 int type, ...)
{
	struct list_head *pos;
	va_list ap;

	if (val)
		pos = &list_entry(val, json_element_t, value)->list;
	else
		pos = &arr->head;

	va_start(ap, type);
	val = __json_array_insert(type, ap, pos->prev, arr);
	va_end(ap);
	return val;
}

json_value_t *json_array_remove(const json_value_t *val,
								json_array_t *arr)
{
	json_element_t *elem = list_entry(val, json_element_t, value);

	val = (json_value_t *)malloc(sizeof (json_value_t));
	if (!val)
		return NULL;

	list_del(&elem->list);
	arr->size--;

	__move_json_value(&elem->value, (json_value_t *)val);
	free(elem);
	return (json_value_t *)val;
}

