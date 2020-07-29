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

#ifndef _ENCODESTREAM_H_
#define _ENCODESTREAM_H_

#include <sys/uio.h>
#include <stdint.h>
#include <string.h>
#include <utility>
#include <string>
#include "list.h"

/**
 * @file   EncodeStream.h
 * @brief  Encoder toolbox for protocol message encode
 */

// make sure max > 0
class EncodeStream
{
public:
	EncodeStream();
	EncodeStream(struct iovec *vectors, int max);
	~EncodeStream();

	void clear();
	void reset(struct iovec *vectors, int max);
	int size() const { return size_; }
	size_t bytes() const { return bytes_; }

	//nocopy, normal string
	EncodeStream& operator<< (const char *data);

	//nocopy, data string like std::pair<data_str, data_len>
	EncodeStream& operator<< (const std::pair<const char *, size_t>& data);

	//nocopy, std string
	EncodeStream& operator<< (const std::string &data);

	//plain integer, string will store in buffer_list_
	EncodeStream& operator<< (int64_t intv);

	//copy, string will store in buffer_list_
	void append_copy(const char *data);
	void append_copy(const char *data, size_t len);
	void append_copy(const std::string &data);
	//nocopy
	void append_nocopy(const char *data);
	void append_nocopy(const char *data, size_t len);
	void append_nocopy(const std::string &data);

private:
	void clear_buffer();
	void check_merge();

	struct iovec *vec_;
	size_t bytes_;
	int max_;
	int size_;
	struct list_head buffer_list_;
};

////////////////////

inline EncodeStream::EncodeStream():
	vec_(NULL),
	bytes_(0),
	max_(1),
	size_(0)
{
	INIT_LIST_HEAD(&buffer_list_);
}

inline EncodeStream::EncodeStream(struct iovec *vectors, int max):
	vec_(vectors),
	bytes_(0),
	max_(max),
	size_(0)
{
	INIT_LIST_HEAD(&buffer_list_);
}

inline EncodeStream::~EncodeStream()
{
	clear_buffer();
}

inline void EncodeStream::clear()
{
	clear_buffer();
	bytes_ = 0;
	size_ = 0;
}

inline void EncodeStream::reset(struct iovec *vectors, int max)
{
	clear();
	vec_ = vectors;
	max_ = max;
}

inline void EncodeStream::append_copy(const char *data)
{
	append_copy(data, strlen(data));
}

inline void EncodeStream::append_copy(const std::string &data)
{
	append_copy(data.c_str(), data.size());
}

inline void EncodeStream::append_nocopy(const char *data)
{
	append_nocopy(data, strlen(data));
}

inline void EncodeStream::append_nocopy(const std::string &data)
{
	append_nocopy(data.c_str(), data.size());
}

inline EncodeStream& EncodeStream::operator<< (const char *data)
{
	append_nocopy(data, strlen(data));
	return *this;
}

inline EncodeStream& EncodeStream::operator<< (const std::string &data)
{
	append_nocopy(data.c_str(), data.size());
	return *this;
}

inline EncodeStream&
EncodeStream::operator<< (const std::pair<const char *, size_t>& data)
{
	append_nocopy(data.first, data.second);
	return *this;
}

inline EncodeStream& EncodeStream::operator<< (int64_t intv)
{
	append_copy(std::to_string(intv));
	return *this;
}

#endif

