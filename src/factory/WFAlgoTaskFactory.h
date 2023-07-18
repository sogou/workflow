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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _WFALGOTASKFACTORY_H_
#define _WFALGOTASKFACTORY_H_

#include <utility>
#include <string>
#include <vector>
#include "WFTask.h"
#include "MapReduce.h"

namespace algorithm
{

template<typename T>
struct SortInput
{
	T *first;
	T *last;
};

template<typename T>
struct SortOutput
{
	T *first;
	T *last;
};

template<typename T>
struct MergeInput
{
	T *first1;
	T *last1;
	T *first2;
	T *last2;
	T *d_first;
};

template<typename T>
struct MergeOutput
{
	T *first;
	T *last;
};

template<typename T>
struct ShuffleInput
{
	T *first;
	T *last;
};

template<typename T>
struct ShuffleOutput
{
	T *first;
	T *last;
};

template<typename T>
struct RemoveInput
{
	T *first;
	T *last;
	T value;
};

template<typename T>
struct RemoveOutput
{
	T *first;
	T *last;
};

template<typename T>
struct UniqueInput
{
	T *first;
	T *last;
};

template<typename T>
struct UniqueOutput
{
	T *first;
	T *last;
};

template<typename T>
struct ReverseInput
{
	T *first;
	T *last;
};

template<typename T>
struct ReverseOutput
{
	T *first;
	T *last;
};

template<typename T>
struct RotateInput
{
	T *first;
	T *middle;
	T *last;
};

template<typename T>
struct RotateOutput
{
	T *first;
	T *last;
};

template<typename KEY = std::string, typename VAL = std::string>
using ReduceInput = std::vector<std::pair<KEY, VAL>>;

template<typename KEY = std::string, typename VAL = std::string>
using ReduceOutput = std::vector<std::pair<KEY, VAL>>;

} /* namespace algorithm */

template<typename T>
using WFSortTask = WFThreadTask<algorithm::SortInput<T>,
								algorithm::SortOutput<T>>;
template<typename T>
using sort_callback_t = std::function<void (WFSortTask<T> *)>;

template<typename T>
using WFMergeTask = WFThreadTask<algorithm::MergeInput<T>,
								 algorithm::MergeOutput<T>>;
template<typename T>
using merge_callback_t = std::function<void (WFMergeTask<T> *)>;

template<typename T>
using WFShuffleTask = WFThreadTask<algorithm::ShuffleInput<T>,
								   algorithm::ShuffleOutput<T>>;
template<typename T>
using shuffle_callback_t = std::function<void (WFShuffleTask<T> *)>;

template<typename T>
using WFRemoveTask = WFThreadTask<algorithm::RemoveInput<T>,
								  algorithm::RemoveOutput<T>>;
template<typename T>
using remove_callback_t = std::function<void (WFRemoveTask<T> *)>;

template<typename T>
using WFUniqueTask = WFThreadTask<algorithm::UniqueInput<T>,
								  algorithm::UniqueOutput<T>>;
template<typename T>
using unique_callback_t = std::function<void (WFUniqueTask<T> *)>;

template<typename T>
using WFReverseTask = WFThreadTask<algorithm::ReverseInput<T>,
								   algorithm::ReverseOutput<T>>;
template<typename T>
using reverse_callback_t = std::function<void (WFReverseTask<T> *)>;

template<typename T>
using WFRotateTask = WFThreadTask<algorithm::RotateInput<T>,
								  algorithm::RotateOutput<T>>;
template<typename T>
using rotate_callback_t = std::function<void (WFRotateTask<T> *)>;

template<typename KEY = std::string, typename VAL = std::string>
using WFReduceTask = WFThreadTask<algorithm::ReduceInput<KEY, VAL>,
								  algorithm::ReduceOutput<KEY, VAL>>;
template<typename KEY = std::string, typename VAL = std::string>
using reduce_callback_t = std::function<void (WFReduceTask<KEY, VAL> *)>;

class WFAlgoTaskFactory
{
public:
	template<typename T, class CB = sort_callback_t<T>>
	static WFSortTask<T> *create_sort_task(const std::string& queue_name,
										   T *first, T *last,
										   CB callback);

	template<typename T, class CMP, class CB = sort_callback_t<T>>
	static WFSortTask<T> *create_sort_task(const std::string& queue_name,
										   T *first, T *last,
										   CMP compare,
										   CB callback);

	template<typename T, class CB = sort_callback_t<T>>
	static WFSortTask<T> *create_psort_task(const std::string& queue_name,
											T *first, T *last,
											CB callback);

	template<typename T, class CMP, class CB = sort_callback_t<T>>
	static WFSortTask<T> *create_psort_task(const std::string& queue_name,
											T *first, T *last,
											CMP compare,
											CB callback);

	template<typename T, class CB = merge_callback_t<T>>
	static WFMergeTask<T> *create_merge_task(const std::string& queue_name,
											 T *first1, T *last1,
											 T *first2, T *last2,
											 T *d_first,
											 CB callback);

	template<typename T, class CMP, class CB = merge_callback_t<T>>
	static WFMergeTask<T> *create_merge_task(const std::string& queue_name,
											 T *first1, T *last1,
											 T *first2, T *last2,
											 T *d_first,
											 CMP compare,
											 CB callback);

	template<typename T, class CB = shuffle_callback_t<T>>
	static WFShuffleTask<T> *create_shuffle_task(const std::string& queue_name,
												 T *first, T *last,
												 CB callback);

	template<typename T, class URBG, class CB = shuffle_callback_t<T>>
	static WFShuffleTask<T> *create_shuffle_task(const std::string& queue_name,
												 T *first, T *last,
												 URBG generator,
												 CB callback);

	template<typename T, class CB = remove_callback_t<T>>
	static WFRemoveTask<T> *create_remove_task(const std::string& queue_name,
											   T *first, T *last,
											   T value,
											   CB callback);

	template<typename T, class CB = unique_callback_t<T>>
	static WFUniqueTask<T> *create_unique_task(const std::string& queue_name,
											   T *first, T *last,
											   CB callback);

	template<typename T, class CB = reverse_callback_t<T>>
	static WFReverseTask<T> *create_reverse_task(const std::string& queue_name,
												 T *first, T *last,
												 CB callback);

	template<typename T, class CB = rotate_callback_t<T>>
	static WFRotateTask<T> *create_rotate_task(const std::string& queue_name,
											   T *first, T *middle, T *last,
											   CB callback);

	template<typename KEY = std::string, typename VAL = std::string,
			 class RED = algorithm::reduce_function_t<KEY, VAL>,
			 class CB = reduce_callback_t<KEY, VAL>>
	static WFReduceTask<KEY, VAL> *
	create_reduce_task(const std::string& queue_name,
					   RED reduce,
					   CB callback);

	template<typename KEY = std::string, typename VAL = std::string,
			 class RED = algorithm::reduce_function_t<KEY, VAL>,
			 class CB = reduce_callback_t<KEY, VAL>>
	static WFReduceTask<KEY, VAL> *
	create_reduce_task(const std::string& queue_name,
					   algorithm::ReduceInput<KEY, VAL> input,
					   RED reduce,
					   CB callback);
};

#include "WFAlgoTaskFactory.inl"

#endif

