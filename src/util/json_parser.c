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
#include <ctype.h>
#include <math.h>
#include "list.h"
#include "rbtree.h"
#include "json_parser.h"

#define JSON_DEPTH_LIMIT	1024

struct __json_object
{
	struct list_head head;
	struct rb_root root;
	int size;
};

struct __json_array
{
	struct list_head head;
	int size;
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
	struct rb_node rb;
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

static int __json_string_length(const char *cursor)
{
	int len = 0;

	while (1)
	{
		if (*cursor == '\"')
			break;

		if (*(const unsigned char *)cursor < ' ')
			return -2;

		cursor++;
		if (cursor[-1] == '\\')
		{
			if (!*cursor)
				return -2;

			cursor++;
		}

		len++;
	}

	return len;
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
		else if (hex >= 'A' && hex <= 'F')
			hex = hex - 'A' + 10;
		else if (hex >= 'a' && hex <= 'f')
			hex = hex - 'a' + 10;
		else
			return -2;

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
							   char *str)
{
	int ret;

	while (*cursor != '\"')
	{
		if (*cursor == '\\')
		{
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

				str += ret;
				continue;

			default:
				return -2;
			}
		}
		else
			*str = *cursor;

		cursor++;
		str++;
	}

	*str = '\0';
	*end = cursor + 1;
	return 0;
}

static const double __power_of_10[309] = {
	1.0e0,   1.0e1,   1.0e2,   1.0e3,   1.0e4,
	1.0e5,   1.0e6,   1.0e7,   1.0e8,   1.0e9,
	1.0e10,  1.0e11,  1.0e12,  1.0e13,  1.0e14,
	1.0e15,  1.0e16,  1.0e17,  1.0e18,  1.0e19,
	1.0e20,  1.0e21,  1.0e22,  1.0e23,  1.0e24,
	1.0e25,  1.0e26,  1.0e27,  1.0e28,  1.0e29,
	1.0e30,  1.0e31,  1.0e32,  1.0e33,  1.0e34,
	1.0e35,  1.0e36,  1.0e37,  1.0e38,  1.0e39,
	1.0e40,  1.0e41,  1.0e42,  1.0e43,  1.0e44,
	1.0e45,  1.0e46,  1.0e47,  1.0e48,  1.0e49,
	1.0e50,  1.0e51,  1.0e52,  1.0e53,  1.0e54,
	1.0e55,  1.0e56,  1.0e57,  1.0e58,  1.0e59,
	1.0e60,  1.0e61,  1.0e62,  1.0e63,  1.0e64,
	1.0e65,  1.0e66,  1.0e67,  1.0e68,  1.0e69,
	1.0e70,  1.0e71,  1.0e72,  1.0e73,  1.0e74,
	1.0e75,  1.0e76,  1.0e77,  1.0e78,  1.0e79,
	1.0e80,  1.0e81,  1.0e82,  1.0e83,  1.0e84,
	1.0e85,  1.0e86,  1.0e87,  1.0e88,  1.0e89,
	1.0e90,  1.0e91,  1.0e92,  1.0e93,  1.0e94,
	1.0e95,  1.0e96,  1.0e97,  1.0e98,  1.0e99,
	1.0e100, 1.0e101, 1.0e102, 1.0e103, 1.0e104,
	1.0e105, 1.0e106, 1.0e107, 1.0e108, 1.0e109,
	1.0e110, 1.0e111, 1.0e112, 1.0e113, 1.0e114,
	1.0e115, 1.0e116, 1.0e117, 1.0e118, 1.0e119,
	1.0e120, 1.0e121, 1.0e122, 1.0e123, 1.0e124,
	1.0e125, 1.0e126, 1.0e127, 1.0e128, 1.0e129,
	1.0e130, 1.0e131, 1.0e132, 1.0e133, 1.0e134,
	1.0e135, 1.0e136, 1.0e137, 1.0e138, 1.0e139,
	1.0e140, 1.0e141, 1.0e142, 1.0e143, 1.0e144,
	1.0e145, 1.0e146, 1.0e147, 1.0e148, 1.0e149,
	1.0e150, 1.0e151, 1.0e152, 1.0e153, 1.0e154,
	1.0e155, 1.0e156, 1.0e157, 1.0e158, 1.0e159,
	1.0e160, 1.0e161, 1.0e162, 1.0e163, 1.0e164,
	1.0e165, 1.0e166, 1.0e167, 1.0e168, 1.0e169,
	1.0e170, 1.0e171, 1.0e172, 1.0e173, 1.0e174,
	1.0e175, 1.0e176, 1.0e177, 1.0e178, 1.0e179,
	1.0e180, 1.0e181, 1.0e182, 1.0e183, 1.0e184,
	1.0e185, 1.0e186, 1.0e187, 1.0e188, 1.0e189,
	1.0e190, 1.0e191, 1.0e192, 1.0e193, 1.0e194,
	1.0e195, 1.0e196, 1.0e197, 1.0e198, 1.0e199,
	1.0e200, 1.0e201, 1.0e202, 1.0e203, 1.0e204,
	1.0e205, 1.0e206, 1.0e207, 1.0e208, 1.0e209,
	1.0e210, 1.0e211, 1.0e212, 1.0e213, 1.0e214,
	1.0e215, 1.0e216, 1.0e217, 1.0e218, 1.0e219,
	1.0e220, 1.0e221, 1.0e222, 1.0e223, 1.0e224,
	1.0e225, 1.0e226, 1.0e227, 1.0e228, 1.0e229,
	1.0e230, 1.0e231, 1.0e232, 1.0e233, 1.0e234,
	1.0e235, 1.0e236, 1.0e237, 1.0e238, 1.0e239,
	1.0e240, 1.0e241, 1.0e242, 1.0e243, 1.0e244,
	1.0e245, 1.0e246, 1.0e247, 1.0e248, 1.0e249,
	1.0e250, 1.0e251, 1.0e252, 1.0e253, 1.0e254,
	1.0e255, 1.0e256, 1.0e257, 1.0e258, 1.0e259,
	1.0e260, 1.0e261, 1.0e262, 1.0e263, 1.0e264,
	1.0e265, 1.0e266, 1.0e267, 1.0e268, 1.0e269,
	1.0e270, 1.0e271, 1.0e272, 1.0e273, 1.0e274,
	1.0e275, 1.0e276, 1.0e277, 1.0e278, 1.0e279,
	1.0e280, 1.0e281, 1.0e282, 1.0e283, 1.0e284,
	1.0e285, 1.0e286, 1.0e287, 1.0e288, 1.0e289,
	1.0e290, 1.0e291, 1.0e292, 1.0e293, 1.0e294,
	1.0e295, 1.0e296, 1.0e297, 1.0e298, 1.0e299,
	1.0e300, 1.0e301, 1.0e302, 1.0e303, 1.0e304,
	1.0e305, 1.0e306, 1.0e307, 1.0e308
};

static double __evaluate_json_number(const char *integer,
									 const char *fraction,
									 int exp)
{
	long long mant = 0;
	int figures = 0;
	double num;
	int sign;

	sign = (*integer == '-');
	if (sign)
		integer++;

	if (*integer != '0')
	{
		mant = *integer - '0';
		integer++;
		figures++;
		while (isdigit(*integer) && figures < 18)
		{
			mant *= 10;
			mant += *integer - '0';
			integer++;
			figures++;
		}

		while (isdigit(*integer))
		{
			exp++;
			integer++;
		}
	}
	else
	{
		while (*fraction == '0')
		{
			exp--;
			fraction++;
		}
	}

	while (isdigit(*fraction) && figures < 18)
	{
		mant *= 10;
		mant += *fraction - '0';
		exp--;
		fraction++;
		figures++;
	}

	if (exp != 0 && figures != 0)
	{
		while (exp > 0 && figures < 18)
		{
			mant *= 10;
			exp--;
			figures++;
		}

		while (exp < 0 && mant % 10 == 0)
		{
			mant /= 10;
			exp++;
			figures--;
		}
	}

	if (exp == 0 || figures == 0)
		num = mant;
	else if (exp > 291)
		num = INFINITY;
	else if (exp > 0)
		num = mant * __power_of_10[exp];
	else if (exp > -309)
		num = mant / __power_of_10[-exp];
	else if (exp > -324 - figures)
		num = mant / __power_of_10[-exp - 308] / __power_of_10[308];
	else
		num = 0.0;

	return sign ? -num : num;
}

static int __parse_json_number(const char *cursor, const char **end,
							   double *num)
{
	const char *integer = cursor;
	const char *fraction = "";
	int exp = 0;
	int sign;

	if (*cursor == '-')
		cursor++;

	if (!isdigit(*cursor))
		return -2;

	if (*cursor == '0' && isdigit(cursor[1]))
		return -2;

	cursor++;
	while (isdigit(*cursor))
		cursor++;

	if (*cursor == '.')
	{
		cursor++;
		fraction = cursor;
		if (!isdigit(*cursor))
			return -2;

		cursor++;
		while (isdigit(*cursor))
			cursor++;
	}

	if (*cursor == 'E' || *cursor == 'e')
	{
		cursor++;
		sign = (*cursor == '-');
		if (sign || *cursor == '+')
			cursor++;

		if (!isdigit(*cursor))
			return -2;

		exp = *cursor - '0';
		cursor++;
		while (isdigit(*cursor) && exp < 2000000)
		{
			exp *= 10;
			exp += *cursor - '0';
			cursor++;
		}

		while (isdigit(*cursor))
			cursor++;

		if (sign)
			exp = -exp;
	}

	if (cursor - integer > 1000000)
		return -2;

	*num = __evaluate_json_number(integer, fraction, exp);
	*end = cursor;
	return 0;
}

static void __insert_json_member(json_member_t *memb, struct list_head *pos,
								 json_object_t *obj)
{
	struct rb_node **p = &obj->root.rb_node;
	struct rb_node *parent = NULL;
	json_member_t *entry;

	while (*p)
	{
		parent = *p;
		entry = rb_entry(*p, json_member_t, rb);
		if (strcmp(memb->name, entry->name) < 0)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&memb->rb, parent, p);
	rb_insert_color(&memb->rb, &obj->root);
	list_add(&memb->list, pos);
}

static int __parse_json_value(const char *cursor, const char **end,
							  int depth, json_value_t *val);

static void __destroy_json_value(json_value_t *val);

static int __parse_json_member(const char *cursor, const char **end,
							   int depth, json_member_t *memb)
{
	int ret;

	ret = __parse_json_string(cursor, &cursor, memb->name);
	if (ret < 0)
		return ret;

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
	int cnt = 0;
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
		ret = __json_string_length(cursor);
		if (ret < 0)
			return ret;

		memb = (json_member_t *)malloc(offsetof(json_member_t, name) + ret + 1);
		if (!memb)
			return -1;

		ret = __parse_json_member(cursor, &cursor, depth, memb);
		if (ret < 0)
		{
			free(memb);
			return ret;
		}

		__insert_json_member(memb, obj->head.prev, obj);
		cnt++;

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
	return cnt;
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
	obj->root.rb_node = NULL;
	ret = __parse_json_members(cursor, end, depth + 1, obj);
	if (ret < 0)
	{
		__destroy_json_members(obj);
		return ret;
	}

	obj->size = ret;
	return 0;
}

static int __parse_json_elements(const char *cursor, const char **end,
								 int depth, json_array_t *arr)
{
	json_element_t *elem;
	int cnt = 0;
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
		cnt++;

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
	return cnt;
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
	ret = __parse_json_elements(cursor, end, depth + 1, arr);
	if (ret < 0)
	{
		__destroy_json_elements(arr);
		return ret;
	}

	arr->size = ret;
	return 0;
}

static int __parse_json_value(const char *cursor, const char **end,
							  int depth, json_value_t *val)
{
	int ret;

	switch (*cursor)
	{
	case '\"':
		cursor++;
		ret = __json_string_length(cursor);
		if (ret < 0)
			return ret;

		val->value.string = (char *)malloc(ret + 1);
		if (!val->value.string)
			return -1;

		ret = __parse_json_string(cursor, end, val->value.string);
		if (ret < 0)
		{
			free(val->value.string);
			return ret;
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
		dest->value.object.root.rb_node = src->value.object.root.rb_node;
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
	int len;

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
		val->value.object.root.rb_node = NULL;
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

json_value_t *json_value_parse(const char *doc)
{
	json_value_t *val;

	val = (json_value_t *)malloc(sizeof (json_value_t));
	if (!val)
		return NULL;

	while (isspace(*doc))
		doc++;

	if (__parse_json_value(doc, &doc, 0, val) >= 0)
	{
		while (isspace(*doc))
			doc++;

		if (*doc == '\0')
			return val;

		__destroy_json_value(val);
	}

	free(val);
	return NULL;
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
	if (ret < 0)
	{
		free(val);
		return NULL;
	}

	return val;
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
	struct rb_node *p = obj->root.rb_node;
	json_member_t *memb;
	int n;

	while (p)
	{
		memb = rb_entry(p, json_member_t, rb);
		n = strcmp(name, memb->name);
		if (n < 0)
			p = p->rb_left;
		else if (n > 0)
			p = p->rb_right;
		else
			return &memb->value;
	}

	return NULL;
}

int json_object_size(const json_object_t *obj)
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

static const json_value_t *__json_object_insert(const char *name,
												int type, va_list ap,
												struct list_head *pos,
												json_object_t *obj)
{
	json_member_t *memb;
	int len;

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

	__insert_json_member(memb, pos, obj);
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
	rb_erase(&memb->rb, &obj->root);
	obj->size--;

	__move_json_value(&memb->value, (json_value_t *)val);
	free(memb);
	return (json_value_t *)val;
}

int json_array_size(const json_array_t *arr)
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

