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

#include <errno.h>
#include <string.h>
#include <sstream>
#include <utility>
#include "RedisMessage.h"

namespace protocol
{

typedef int64_t Rint;
typedef std::string Rstr;
typedef std::vector<RedisValue> Rarr;

RedisValue& RedisValue::operator= (const RedisValue& copy)
{
	if (this != &copy)
	{
		free_data();

		switch (copy.type_)
		{
		case REDIS_REPLY_TYPE_INTEGER:
			type_ = copy.type_;
			data_ = new Rint(*((Rint*)(copy.data_)));
			break;

		case REDIS_REPLY_TYPE_ERROR:
		case REDIS_REPLY_TYPE_STATUS:
		case REDIS_REPLY_TYPE_STRING:
			type_ = copy.type_;
			data_ = new Rstr(*((Rstr*)(copy.data_)));
			break;

		case REDIS_REPLY_TYPE_ARRAY:
			type_ = copy.type_;
			data_ = new Rarr(*((Rarr*)(copy.data_)));
			break;

		default:
			type_ = REDIS_REPLY_TYPE_NIL;
			data_ = NULL;
		}
	}

	return *this;
}

RedisValue& RedisValue::operator= (RedisValue&& move)
{
	if (this != &move)
	{
		free_data();

		type_ = move.type_;
		data_ = move.data_;

		move.type_ = REDIS_REPLY_TYPE_NIL;
		move.data_ = NULL;
	}

	return *this;
}

void RedisValue::free_data()
{
	if (data_)
	{
		switch (type_)
		{
		case REDIS_REPLY_TYPE_INTEGER:
			delete (Rint *)data_;
			break;

		case REDIS_REPLY_TYPE_ERROR:
		case REDIS_REPLY_TYPE_STATUS:
		case REDIS_REPLY_TYPE_STRING:
			delete (Rstr *)data_;
			break;

		case REDIS_REPLY_TYPE_ARRAY:
			delete (Rarr *)data_;
			break;
		}

		data_ = NULL;
	}
}

void RedisValue::only_set_string_data(const std::string& strv)
{
	Rstr *p = (Rstr *)(data_);
	p->assign(strv);
}

void RedisValue::only_set_string_data(const char *str, size_t len)
{
	Rstr *p = (Rstr *)(data_);
	if (str == NULL || len == 0)
		p->clear();
	else
		p->assign(str, len);
}

void RedisValue::only_set_string_data(const char *str)
{
	Rstr *p = (Rstr *)(data_);
	if (str == NULL)
		p->clear();
	else
		p->assign(str);
}

void RedisValue::set_int(int64_t intv)
{
	if (type_ == REDIS_REPLY_TYPE_INTEGER)
		*((Rint *)data_) = intv;
	else
	{
		free_data();
		data_ = new Rint(intv);
		type_ = REDIS_REPLY_TYPE_INTEGER;
	}
}

void RedisValue::set_string(const std::string& strv)
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		only_set_string_data(strv);
	else
	{
		free_data();
		data_ = new Rstr(strv);
	}

	type_ = REDIS_REPLY_TYPE_STRING;
}

void RedisValue::set_status(const std::string& strv)
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		only_set_string_data(strv);
	else
	{
		free_data();
		data_ = new Rstr(strv);
	}

	type_ = REDIS_REPLY_TYPE_STATUS;
}

void RedisValue::set_error(const std::string& strv)
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		only_set_string_data(strv);
	else
	{
		free_data();
		data_ = new Rstr(strv);
	}

	type_ = REDIS_REPLY_TYPE_ERROR;
}

void RedisValue::set_string(const char *str, size_t len)
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		only_set_string_data(str, len);
	else
	{
		free_data();
		data_ = new Rstr(str, len);
	}

	type_ = REDIS_REPLY_TYPE_STRING;
}

void RedisValue::set_status(const char *str, size_t len)
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		only_set_string_data(str, len);
	else
	{
		free_data();
		data_ = new Rstr(str, len);
	}

	type_ = REDIS_REPLY_TYPE_STATUS;
}

void RedisValue::set_error(const char *str, size_t len)
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		only_set_string_data(str, len);
	else
	{
		free_data();
		data_ = new Rstr(str, len);
	}

	type_ = REDIS_REPLY_TYPE_ERROR;
}

void RedisValue::set_string(const char *str)
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		only_set_string_data(str);
	else
	{
		free_data();
		data_ = new Rstr(str);
	}

	type_ = REDIS_REPLY_TYPE_STRING;
}

void RedisValue::set_status(const char *str)
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		only_set_string_data(str);
	else
	{
		free_data();
		data_ = new Rstr(str);
	}

	type_ = REDIS_REPLY_TYPE_STATUS;
}

void RedisValue::set_error(const char *str)
{
	if (type_ == REDIS_REPLY_TYPE_STRING ||
		type_ == REDIS_REPLY_TYPE_STATUS ||
		type_ == REDIS_REPLY_TYPE_ERROR)
		only_set_string_data(str);
	else
	{
		free_data();
		data_ = new Rstr(str);
	}

	type_ = REDIS_REPLY_TYPE_ERROR;
}

void RedisValue::set_array(size_t new_size)
{
	if (type_ == REDIS_REPLY_TYPE_ARRAY)
		((Rarr *)data_)->resize(new_size);
	else
	{
		free_data();
		data_ = new Rarr(new_size);
		type_ = REDIS_REPLY_TYPE_ARRAY;
	}
}

void RedisValue::set(const redis_reply_t *reply)
{
	set_nil();
	switch (reply->type)
	{
	case REDIS_REPLY_TYPE_INTEGER:
		set_int(reply->integer);
		break;

	case REDIS_REPLY_TYPE_ERROR:
		set_error(reply->str, reply->len);
		break;

	case REDIS_REPLY_TYPE_STATUS:
		set_status(reply->str, reply->len);
		break;

	case REDIS_REPLY_TYPE_STRING:
		set_string(reply->str, reply->len);
		break;

	case REDIS_REPLY_TYPE_ARRAY:
		set_array(reply->elements);

		if (reply->elements > 0)
		{
			Rarr *parr = (Rarr *)data_;
			for (size_t i = 0; i < reply->elements; i++)
				(*parr)[i].set(reply->element[i]);
		}

		break;
	}
}

void RedisValue::arr_clear()
{
	if (type_ == REDIS_REPLY_TYPE_ARRAY)
		((Rarr *)data_)->clear();
}

void RedisValue::arr_resize(size_t new_size)
{
	if (type_ == REDIS_REPLY_TYPE_ARRAY)
		((Rarr *)data_)->resize(new_size);
}

bool RedisValue::transform(redis_reply_t *reply) const
{
	//todo risk of stack overflow
	Rarr *parr;
	Rstr *pstr;

	redis_reply_set_null(reply);
	switch (type_)
	{
	case REDIS_REPLY_TYPE_INTEGER:
		redis_reply_set_integer(*((Rint *)data_), reply);
		break;

	case REDIS_REPLY_TYPE_ARRAY:
		parr = (Rarr *)data_;
		if (redis_reply_set_array(parr->size(), reply) < 0)
			return false;

		for (size_t i = 0; i < reply->elements; i++)
		{
			if (!(*parr)[i].transform(reply->element[i]))
				return false;
		}

		break;

	case REDIS_REPLY_TYPE_STATUS:
		pstr = (Rstr *)data_;
		redis_reply_set_status(pstr->c_str(), pstr->size(), reply);

		break;

	case REDIS_REPLY_TYPE_ERROR:
		pstr = (Rstr *)data_;
		redis_reply_set_error(pstr->c_str(), pstr->size(), reply);

		break;

	case REDIS_REPLY_TYPE_STRING:
		pstr = (Rstr *)data_;
		redis_reply_set_string(pstr->c_str(), pstr->size(), reply);

		break;
	}

	return true;
}

std::string RedisValue::debug_string() const
{
	std::string ret;

	if (is_error())
	{
		ret += "ERROR: ";
		ret += string_view()->c_str();
	}
	else if (is_int())
	{
		std::ostringstream oss;
		oss << int_value();
		ret += oss.str();
	}
	else if (is_nil())
	{
		ret += "nil";
	}
	else if (is_string())
	{
		ret += '\"';
		ret += string_view()->c_str();
		ret += '\"';
	}
	else if (is_array())
	{
		ret += '[';
		size_t l = arr_size();
		for (size_t i = 0; i < l; i++)
		{
			if (i)
				ret += ", ";

			ret += (*this)[i].debug_string();
		}
		ret += ']';
	}

	return ret;
}

RedisValue::~RedisValue()
{
	free_data();
}

RedisMessage::RedisMessage():
	parser_(new redis_parser_t),
	stream_(new EncodeStream),
	cur_size_(0),
	asking_(false)
{
	redis_parser_init(parser_);
}

RedisMessage::~RedisMessage()
{
	if (parser_)
	{
		redis_parser_deinit(parser_);
		delete parser_;
		delete stream_;
	}
}

RedisMessage::RedisMessage(RedisMessage&& move) :
	ProtocolMessage(std::move(move))
{
	parser_ = move.parser_;
	stream_ = move.stream_;
	cur_size_ = move.cur_size_;
	asking_ = move.asking_;

	move.parser_ = NULL;
	move.stream_ = NULL;
	move.cur_size_ = 0;
	move.asking_ = false;
}

RedisMessage& RedisMessage::operator= (RedisMessage &&move)
{
	if (this != &move)
	{
		*(ProtocolMessage *)this = std::move(move);

		if (parser_)
		{
			redis_parser_deinit(parser_);
			delete parser_;
			delete stream_;
		}

		parser_ = move.parser_;
		stream_ = move.stream_;
		cur_size_ = move.cur_size_;
		asking_ = move.asking_;

		move.parser_ = NULL;
		move.stream_ = NULL;
		move.cur_size_ = 0;
		move.asking_ = false;
	}

	return *this;
}

bool RedisMessage::encode_reply(redis_reply_t *reply)
{
	EncodeStream& stream = *stream_;
	switch (reply->type)
	{
	case REDIS_REPLY_TYPE_STATUS:
		stream << "+" << std::make_pair(reply->str, reply->len) << "\r\n";
		break;

	case REDIS_REPLY_TYPE_ERROR:
		stream << "-" << std::make_pair(reply->str, reply->len) << "\r\n";
		break;

	case REDIS_REPLY_TYPE_NIL:
		stream << "$-1\r\n";
		break;

	case REDIS_REPLY_TYPE_INTEGER:
		stream << ":" << reply->integer << "\r\n";
		break;

	case REDIS_REPLY_TYPE_STRING:
		stream << "$" << reply->len << "\r\n";
		stream << std::make_pair(reply->str, reply->len) << "\r\n";
		break;

	case REDIS_REPLY_TYPE_ARRAY:
		stream << "*" << reply->elements << "\r\n";
		for (size_t i = 0; i < reply->elements; i++)
			if (!encode_reply(reply->element[i]))
				return false;

		break;

	default:
		return false;
	}

	return true;
}

int RedisMessage::encode(struct iovec vectors[], int max)
{
	stream_->reset(vectors, max);

	if (encode_reply(&parser_->reply))
		return stream_->size();

	return 0;
}

int RedisMessage::append(const void *buf, size_t *size)
{
	int ret = redis_parser_append_message(buf, size, parser_);

	if (ret >= 0)
	{
		cur_size_ += *size;
		if (cur_size_ > this->size_limit)
		{
			errno = EMSGSIZE;
			ret = -1;
		}
	}
	else if (ret == -2)
	{
		errno = EBADMSG;
		ret = -1;
	}

	return ret;
}

void RedisRequest::set_request(const std::string& command,
							   const std::vector<std::string>& params)
{
	size_t n = params.size() + 1;
	user_request_.reserve(n);
	user_request_.clear();
	user_request_.push_back(command);
	for (size_t i = 0; i < params.size(); i++)
		user_request_.push_back(params[i]);

	redis_reply_t *reply = &parser_->reply;
	redis_reply_set_array(n, reply);
	for (size_t i = 0; i < n; i++)
	{
		redis_reply_set_string(user_request_[i].c_str(),
							   user_request_[i].size(),
							   reply->element[i]);
	}
}

bool RedisRequest::get_command(std::string& command) const
{
	const redis_reply_t *reply = &parser_->reply;
	if (reply->type == REDIS_REPLY_TYPE_ARRAY && reply->elements > 0)
	{
		reply = reply->element[0];
		if (reply->type == REDIS_REPLY_TYPE_STRING)
		{
			command.assign(reply->str, reply->len);
			return true;
		}
	}

	return false;
}

bool RedisRequest::get_params(std::vector<std::string>& params) const
{
	const redis_reply_t *reply = &parser_->reply;
	if (reply->type == REDIS_REPLY_TYPE_ARRAY && reply->elements > 0)
	{
		for (size_t i = 1; i < reply->elements; i++)
		{
			if (reply->element[i]->type != REDIS_REPLY_TYPE_STRING &&
				reply->element[i]->type != REDIS_REPLY_TYPE_NIL)
			{
				return false;
			}
		}

		params.reserve(reply->elements - 1);
		params.clear();
		for (size_t i = 1; i < reply->elements; i++)
			params.emplace_back(reply->element[i]->str, reply->element[i]->len);

		return true;
	}

	return false;
}

#define REDIS_ASK_COMMAND	"ASKING"
#define REDIS_ASK_REQUEST	"*1\r\n$6\r\nASKING\r\n"
#define REDIS_OK_RESPONSE	"+OK\r\n"

int RedisRequest::encode(struct iovec vectors[], int max)
{
	stream_->reset(vectors, max);

	if (is_asking())
		(*stream_) << REDIS_ASK_REQUEST;
	if (encode_reply(&parser_->reply))
		return stream_->size();

	return 0;
}

int RedisRequest::append(const void *buf, size_t *size)
{
	int ret = RedisMessage::append(buf, size);

	if (ret > 0)
	{
		std::string command;

		if (get_command(command) &&
			strcasecmp(command.c_str(), REDIS_ASK_COMMAND) == 0)
		{
			redis_parser_deinit(parser_);
			redis_parser_init(parser_);
			set_asking(true);

			ret = this->feedback(REDIS_OK_RESPONSE, strlen(REDIS_OK_RESPONSE));
			if (ret != strlen(REDIS_OK_RESPONSE))
			{
				errno = ENOBUFS;
				ret = -1;
			}
			else
				ret = 0;
		}
	}

	return ret;
}

int RedisResponse::append(const void *buf, size_t *size)
{
	int ret = RedisMessage::append(buf, size);

	if (ret > 0 && is_asking())
	{
		redis_parser_deinit(parser_);
		redis_parser_init(parser_);
		ret = 0;
		set_asking(false);
	}

	return ret;
}

bool RedisResponse::set_result(const RedisValue& value)
{
	redis_reply_t *reply = &parser_->reply;
	redis_reply_deinit(reply);
	redis_reply_init(reply);

	value_ = value;
	return value_.transform(reply);
}

}

