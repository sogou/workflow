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

#ifndef _JSON_PARSER_H_
#define _JSON_PARSER_H_

#include <stddef.h>

#define JSON_VALUE_STRING	1
#define JSON_VALUE_NUMBER	2
#define JSON_VALUE_OBJECT	3
#define JSON_VALUE_ARRAY	4
#define JSON_VALUE_TRUE		5
#define JSON_VALUE_FALSE	6
#define JSON_VALUE_NULL		7

typedef struct __json_value json_value_t;
typedef struct __json_object json_object_t;
typedef struct __json_array json_array_t;

#ifdef __cplusplus
extern "C"
{
#endif

json_value_t *json_value_parse(const char *doc);
json_value_t *json_value_create(int type, ...);
void json_value_destroy(json_value_t *val);

int json_value_type(const json_value_t *val);
const char *json_value_string(const json_value_t *val);
double json_value_number(const json_value_t *val);
json_object_t *json_value_object(const json_value_t *val);
json_array_t *json_value_array(const json_value_t *val);

const json_value_t *json_object_find(const char *name,
									 const json_object_t *obj);
int json_object_size(const json_object_t *obj);
const char *json_object_next_name(const char *name,
								  const json_object_t *obj);
const json_value_t *json_object_next_value(const json_value_t *val,
										   const json_object_t *obj);
const char *json_object_prev_name(const char *name,
								  const json_object_t *obj);
const json_value_t *json_object_prev_value(const json_value_t *val,
										   const json_object_t *obj);
const json_value_t *json_object_append(json_object_t *obj,
									   const char *name,
									   int type, ...);
const json_value_t *json_object_insert_after(const json_value_t *val,
											 json_object_t *obj,
											 const char *name,
											 int type, ...);
const json_value_t *json_object_insert_before(const json_value_t *val,
											  json_object_t *obj,
											  const char *name,
											  int type, ...);
json_value_t *json_object_remove(const json_value_t *val,
								 json_object_t *obj);

int json_array_size(const json_array_t *arr);
const json_value_t *json_array_next_value(const json_value_t *val,
										  const json_array_t *arr);
const json_value_t *json_array_prev_value(const json_value_t *val,
										  const json_array_t *arr);
const json_value_t *json_array_append(json_array_t *arry,
									  int type, ...);
const json_value_t *json_array_insert_after(const json_value_t *val,
											json_array_t *arr,
											int type, ...);
const json_value_t *json_array_insert_before(const json_value_t *val,
											 json_array_t *arr,
											 int type, ...);
json_value_t *json_array_remove(const json_value_t *val,
								json_array_t *arr);

#ifdef __cplusplus
}
#endif

#define json_object_for_each(name, val, obj) \
	for (name = NULL, val = NULL; \
		 name = json_object_next_name(name, obj), \
		 val = json_object_next_value(val, obj), val; )

#define json_object_for_each_prev(name, val, obj) \
	for (name = NULL, val = NULL; \
		 name = json_object_prev_name(name, obj), \
		 val = json_object_prev_value(val, obj), val; )

#define json_array_for_each(val, arr) \
	for (val = NULL; val = json_array_next_value(val, arr), val; )

#define json_array_for_each_prev(val, arr) \
	for (val = NULL; val = json_array_prev_value(val, arr), val; )

#endif

