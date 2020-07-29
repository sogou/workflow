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

#ifndef _MD5UTIL_H_
#define _MD5UTIL_H_

#include <stdint.h>
#include <string>
#include <utility>

/**
 * @file   MD5Util.h
 * @brief  MD5 toolbox
 */

// static class
class MD5Util
{
public:
	//128 bit binary data
	static std::string md5_bin(const std::string& str);
	//128 bit hex string style, lower case
	static std::string md5_string_32(const std::string& str);
	//64  bit hex string style, lower case
	static std::string md5_string_16(const std::string& str);

	//128 bit integer style
	static std::pair<uint64_t, uint64_t> md5_integer_32(const std::string& str);
	//64  bit integer style
	static uint64_t md5_integer_16(const std::string& str);
};

#endif

