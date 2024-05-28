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

#ifndef _STRINGUTIL_H_
#define _STRINGUTIL_H_

#include <string>
#include <vector>

/**
 * @file   StringUtil.h
 * @brief  String toolbox
 */

// static class
class StringUtil
{
public:
	static void url_decode(std::string& str);
	static std::string url_encode(const std::string& str);
	static std::string url_encode_component(const std::string& str);
	static std::vector<std::string> split(const std::string& str, char sep);
	static std::string strip(const std::string& str);
	static bool start_with(const std::string& str, const std::string& prefix);

	//this will filter any empty result, so the result vector has no empty string
	static std::vector<std::string> split_filter_empty(const std::string& str, char sep);
};

#endif

