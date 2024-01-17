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
           Liu Kai (liukaidx@sogou-inc.com)
*/

#ifndef _REDISMESSAGE_H_
#define _REDISMESSAGE_H_

#include <stdint.h>
#include <string>
#include <vector>
#include "ProtocolMessage.h"
#include "redis_parser.h"

/**
 * @file   RedisMessage.h
 * @brief  Redis Protocol Interface
 */

namespace protocol
{

class RedisValue
{
public:
	// nil
	RedisValue();
	virtual ~RedisValue();

	//copy constructor
	RedisValue(const RedisValue& copy);
	//copy operator
	RedisValue& operator= (const RedisValue& copy);
	//move constructor
	RedisValue(RedisValue&& move);
	//move operator
	RedisValue& operator= (RedisValue&& move);

	// release memory and change type to nil
	void set_nil();
	void set_int(int64_t intv);
	void set_string(const std::string& strv);
	void set_status(const std::string& strv);
	void set_error(const std::string& strv);
	void set_string(const char *str, size_t len);
	void set_status(const char *str, size_t len);
	void set_error(const char *str, size_t len);
	void set_string(const char *str);
	void set_status(const char *str);
	void set_error(const char *str);
	// array(resize)
	void set_array(size_t new_size);
	// set data by C style data struct
	void set(const redis_reply_t *reply);

	// Return true if not error
	bool is_ok() const;
	// Return true if error
	bool is_error() const;
	// Return true if nil
	bool is_nil() const;
	// Return true if integer
	bool is_int() const;
	// Return true if array
	bool is_array() const;
	// Return true if string/status
	bool is_string() const;
	// Return type of C style data struct
	int get_type() const;

	// Copy. If type isnot string/status/error, returns an empty std::string
	std::string string_value() const;
	// No copy. If type isnot string/status/error, returns NULL.
	const std::string *string_view() const;
	// If type isnot integer, returns 0
	int64_t int_value() const;
	// If type isnot array, returns 0
	size_t arr_size() const;
	// If type isnot array, do nothing
	void arr_clear();
	// If type isnot array, do nothing
	void arr_resize(size_t new_size);
	// Always return std::vector.at(pos); notice overflow exception
	RedisValue& arr_at(size_t pos) const;
	// Always return std::vector[pos]; notice overflow exception
	RedisValue& operator[] (size_t pos) const;

	// transform data into C style data struct
	bool transform(redis_reply_t *reply) const;
	// equal to set_nil();
	void clear();
	// format data to text
	std::string debug_string() const;

private:
	void free_data();
	void only_set_string_data(const std::string& strv);
	void only_set_string_data(const char *str, size_t len);
	void only_set_string_data(const char *str);

	int type_;
	void *data_;
};

class RedisMessage : public ProtocolMessage
{
public:
	RedisMessage();
	virtual ~RedisMessage();
	//move constructor
	RedisMessage(RedisMessage&& move);
	//move operator
	RedisMessage& operator= (RedisMessage&& move);

public:
	//peek after CommMessageIn append
	//not for users.
	bool parse_success() const;
	bool is_asking() const;
	void set_asking(bool asking);

protected:
	redis_parser_t *parser_;

	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);
	bool encode_reply(redis_reply_t *reply);

	class EncodeStream *stream_;

private:
	size_t cur_size_;
	bool asking_;
};

class RedisRequest : public RedisMessage
{
public:
	RedisRequest() = default;
	//move constructor
	RedisRequest(RedisRequest&& move) = default;
	//move operator
	RedisRequest& operator= (RedisRequest&& move) = default;

public:// C++ style
	// Usually, client use set_request to (prepare)send request to server
	// Usually, server use get_command/get_params to get client request

	// set_request("HSET", {"keyname", "hashkey", "somevalue"});
	void set_request(const std::string& command,
					 const std::vector<std::string>& params);

	bool get_command(std::string& command) const;
	bool get_params(std::vector<std::string>& params) const;

protected:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

private:
	std::vector<std::string> user_request_;
};

class RedisResponse : public RedisMessage
{
public:
	RedisResponse() = default;
	//move constructor
	RedisResponse(RedisResponse&& move) = default;
	//move operator
	RedisResponse& operator= (RedisResponse&& move) = default;

public:// C++ style
	// client use get_result to get result from server, copy
	void get_result(RedisValue& value) const;

	// server use set_result to (prepare)send result to client, copy
	bool set_result(const RedisValue& value);

public:// C style
	// redis_parser_t is absolutely same as hiredis-redisReply in memory
	// If you include hiredis.h, redisReply* can cast to redis_reply_t* safely
	// BUT this function return not a copy, DONOT free the pointer by yourself

	// client read  data from redis_reply_t by pointer of result_ptr
	// server write data into redis_reply_t by pointer of result_ptr
	redis_reply_t *result_ptr();

protected:
	virtual int append(const void *buf, size_t *size);

private:
	RedisValue value_;
};

////////////////////

inline RedisValue::RedisValue():
	type_(REDIS_REPLY_TYPE_NIL),
	data_(NULL)
{
}

inline RedisValue::RedisValue(const RedisValue& copy):
	type_(REDIS_REPLY_TYPE_NIL),
	data_(NULL)
{
	this->operator= (copy);
}

inline RedisValue::RedisValue(RedisValue&& move):
	type_(REDIS_REPLY_TYPE_NIL),
	data_(NULL)
{
	this->operator= (std::move(move));
}

inline bool RedisValue::is_ok() const { return type_ != REDIS_REPLY_TYPE_ERROR; }
inline bool RedisValue::is_error() const { return type_ == REDIS_REPLY_TYPE_ERROR; }
inline bool RedisValue::is_nil() const { return type_ == REDIS_REPLY_TYPE_NIL; }
inline bool RedisValue::is_int() const { return type_ == REDIS_REPLY_TYPE_INTEGER; }
inline bool RedisValue::is_array() const { return type_ == REDIS_REPLY_TYPE_ARRAY; }
inline int RedisValue::get_type() const { return type_; }

inline bool RedisValue::is_string() const
{
	return type_ == REDIS_REPLY_TYPE_STRING || type_ == REDIS_REPLY_TYPE_STATUS;
}

inline std::string RedisValue::string_value() const
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		return *((std::string *)data_);
	else
		return "";
}

inline const std::string *RedisValue::string_view() const
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
			type_ == REDIS_REPLY_TYPE_STATUS ||
			type_ == REDIS_REPLY_TYPE_ERROR)
		return ((std::string *)data_);
	else
		return NULL;
}

inline int64_t RedisValue::int_value() const
{
	if (type_ == REDIS_REPLY_TYPE_INTEGER)
		return *((int64_t *)data_);
	else
		return 0;
}

inline size_t RedisValue::arr_size() const
{
	if (type_ == REDIS_REPLY_TYPE_ARRAY)
		return ((std::vector<RedisValue> *)data_)->size();
	else
		return 0;
}

inline RedisValue& RedisValue::arr_at(size_t pos) const
{
	return ((std::vector<RedisValue> *)data_)->at(pos);
}

inline RedisValue& RedisValue::operator[] (size_t pos) const
{
	return (*((std::vector<RedisValue> *)data_))[pos];
}

inline void RedisValue::set_nil()
{
	free_data();
	type_ = REDIS_REPLY_TYPE_NIL;
}

inline void RedisValue::clear()
{
	set_nil();
}

inline bool RedisMessage::parse_success() const { return parser_->parse_succ; }

inline bool RedisMessage::is_asking() const { return asking_; }

inline void RedisMessage::set_asking(bool asking) { asking_ = asking; }

inline redis_reply_t *RedisResponse::result_ptr()
{
	return &parser_->reply;
}

inline void RedisResponse::get_result(RedisValue& value) const
{
	if (parser_->parse_succ)
		value.set(&parser_->reply);
	else
		value.set_nil();
}

}

#endif

