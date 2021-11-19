/*
  Copyright (c) 2020 Sogou, Inc.

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

#ifndef _MAPREDUCE_H_
#define _MAPREDUCE_H_

#include <utility>
#include <vector>
#include <functional>
#include "rbtree.h"

namespace algorithm
{

template<typename VAL>
class ReduceIterator
{
public:
	virtual const VAL *next() = 0;
	virtual size_t size() = 0;

protected:
	virtual ~ReduceIterator() { }
};

template<typename KEY, typename VAL>
using reduce_function_t =
	std::function<void (const KEY *, ReduceIterator<VAL> *, VAL *)>;

template<typename KEY, typename VAL>
class Reducer
{
public:
	void insert(KEY&& key, VAL&& val);

public:
	void start(reduce_function_t<KEY, VAL> reduce,
			   std::vector<std::pair<KEY, VAL>> *output);

private:
	struct rb_root key_tree;

public:
	Reducer() { this->key_tree.rb_node = NULL; }
	virtual ~Reducer();
};

}

#include "MapReduce.inl"

#endif

