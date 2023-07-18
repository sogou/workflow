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

#include <assert.h>
#include <stdlib.h>
#include <random>
#include <algorithm>
#include <vector>
#include <functional>
#include <utility>
#include "Workflow.h"
#include "WFGlobal.h"

/********** Classes without CMP **********/

template<typename T>
class __WFSortTask : public WFSortTask<T>
{
protected:
	virtual void execute()
	{
		std::sort(this->input.first, this->input.last);
		this->output.first = this->input.first;
		this->output.last = this->input.last;
	}

public:
	__WFSortTask(ExecQueue *queue, Executor *executor,
				 T *first, T *last,
				 sort_callback_t<T>&& cb) :
		WFSortTask<T>(queue, executor, std::move(cb))
	{
		this->input.first = first;
		this->input.last = last;
		this->output.first = NULL;
		this->output.last = NULL;
	}
};

template<typename T>
class __WFMergeTask : public WFMergeTask<T>
{
protected:
	virtual void execute();

public:
	__WFMergeTask(ExecQueue *queue, Executor *executor,
				  T *first1, T *last1, T *first2, T *last2, T *d_first,
				  merge_callback_t<T>&& cb) :
		WFMergeTask<T>(queue, executor, std::move(cb))
	{
		this->input.first1 = first1;
		this->input.last1 = last1;
		this->input.first2 = first2;
		this->input.last2 = last2;
		this->input.d_first = d_first;
		this->output.first = NULL;
		this->output.last = NULL;
	}
};

template<typename T>
void __WFMergeTask<T>::execute()
{
	auto *input = &this->input;
	auto *output = &this->output;

	if (input->first1 == input->d_first && input->last1 == input->first2)
	{
		std::inplace_merge(input->first1, input->first2, input->last2);
		output->last = input->last2;
	}
	else if (input->first2 == input->d_first && input->last2 == input->first1)
	{
		std::inplace_merge(input->first2, input->first1, input->last1);
		output->last = input->last1;
	}
	else
	{
		output->last = std::merge(input->first1, input->last1,
								  input->first2, input->first2,
								  input->d_first);
	}

	output->first = input->d_first;
}

template<typename T>
class __WFParSortTask : public __WFSortTask<T>
{
public:
	virtual void dispatch();

protected:
	virtual SubTask *done()
	{
		if (this->flag)
			return series_of(this)->pop();

		assert(this->state == WFT_STATE_SUCCESS);
		return this->WFSortTask<T>::done();
	}

	virtual void execute();

protected:
	int depth;
	int flag;

public:
	__WFParSortTask(ExecQueue *queue, Executor *executor,
					T *first, T *last, int depth,
					sort_callback_t<T>&& cb) :
		__WFSortTask<T>(queue, executor, first, last, std::move(cb))
	{
		this->depth = depth;
		this->flag = 0;
	}
};

template<typename T>
void __WFParSortTask<T>::dispatch()
{
	size_t n = this->input.last - this->input.first;

	if (!this->flag && this->depth < 7 && n >= 32)
	{
		SeriesWork *series = series_of(this);
		T *middle = this->input.first + n / 2;
		auto *task1 =
			new __WFParSortTask<T>(this->queue, this->executor,
								   this->input.first, middle,
								   this->depth + 1,
								   nullptr);
		auto *task2 =
			new __WFParSortTask<T>(this->queue, this->executor,
								   middle, this->input.last,
								   this->depth + 1,
								   nullptr);
		SeriesWork *sub_series[2] = {
			Workflow::create_series_work(task1, nullptr),
			Workflow::create_series_work(task2, nullptr)
		};
		ParallelWork *parallel =
			Workflow::create_parallel_work(sub_series, 2, nullptr);

		series->push_front(this);
		series->push_front(parallel);
		this->flag = 1;
		this->subtask_done();
	}
	else
		this->__WFSortTask<T>::dispatch();
}

template<typename T>
void __WFParSortTask<T>::execute()
{
	if (this->flag)
	{
		size_t n = this->input.last - this->input.first;
		T *middle = this->input.first + n / 2;

		std::inplace_merge(this->input.first, middle, this->input.last);
		this->output.first = this->input.first;
		this->output.last = this->input.last;
		this->flag = 0;
	}
	else
		this->__WFSortTask<T>::execute();
}

/********** Classes with CMP **********/

template<typename T, class CMP>
class __WFSortTaskCmp : public __WFSortTask<T>
{
protected:
	virtual void execute()
	{
		std::sort(this->input.first, this->input.last,
				  std::move(this->compare));
		this->output.first = this->input.first;
		this->output.last = this->input.last;
	}

protected:
	CMP compare;

public:
	__WFSortTaskCmp(ExecQueue *queue, Executor *executor,
					T *first, T *last, CMP&& cmp,
					sort_callback_t<T>&& cb) :
		__WFSortTask<T>(queue, executor, first, last, std::move(cb)),
		compare(std::move(cmp))
	{
	}
};

template<typename T, class CMP>
class __WFMergeTaskCmp : public __WFMergeTask<T>
{
protected:
	virtual void execute();

protected:
	CMP compare;

public:
	__WFMergeTaskCmp(ExecQueue *queue, Executor *executor,
					 T *first1, T *last1, T *first2, T *last2,
					 T *d_first, CMP&& cmp,
					 merge_callback_t<T>&& cb) :
		__WFMergeTask<T>(queue, executor, first1, last1, first2, last2, d_first,
						 std::move(cb)),
		compare(std::move(cmp))
	{
	}
};

template<typename T, class CMP>
void __WFMergeTaskCmp<T, CMP>::execute()
{
	auto *input = &this->input;
	auto *output = &this->output;

	if (input->first1 == input->d_first && input->last1 == input->first2)
	{
		std::inplace_merge(input->first1, input->first2, input->last2,
						   std::move(this->compare));
		output->last = input->last2;
	}
	else if (input->first2 == input->d_first && input->last2 == input->first1)
	{
		std::inplace_merge(input->first2, input->first1, input->last1,
						   std::move(this->compare));
		output->last = input->last1;
	}
	else
	{
		output->last = std::merge(input->first1, input->last1,
								  input->first2, input->first2,
								  input->d_first,
								  std::move(this->compare));
	}

	output->first = input->d_first;
}

template<typename T, class CMP>
class __WFParSortTaskCmp : public __WFSortTaskCmp<T, CMP>
{
public:
	virtual void dispatch();

protected:
	virtual SubTask *done()
	{
		if (this->flag)
			return series_of(this)->pop();

		assert(this->state == WFT_STATE_SUCCESS);
		return this->WFSortTask<T>::done();
	}

	virtual void execute();

protected:
	int depth;
	int flag;

public:
	__WFParSortTaskCmp(ExecQueue *queue, Executor *executor,
					   T *first, T *last, CMP cmp, int depth,
					   sort_callback_t<T>&& cb) :
		__WFSortTaskCmp<T, CMP>(queue, executor, first, last, std::move(cmp),
								std::move(cb))
	{
		this->depth = depth;
		this->flag = 0;
	}
};

template<typename T, class CMP>
void __WFParSortTaskCmp<T, CMP>::dispatch()
{
	size_t n = this->input.last - this->input.first;

	if (!this->flag && this->depth < 7 && n >= 32)
	{
		SeriesWork *series = series_of(this);
		T *middle = this->input.first + n / 2;
		auto *task1 =
			new __WFParSortTaskCmp<T, CMP>(this->queue, this->executor,
										   this->input.first, middle,
										   this->compare, this->depth + 1,
										   nullptr);
		auto *task2 =
			new __WFParSortTaskCmp<T, CMP>(this->queue, this->executor,
										   middle, this->input.last,
										   this->compare, this->depth + 1,
										   nullptr);
		SeriesWork *sub_series[2] = {
			Workflow::create_series_work(task1, nullptr),
			Workflow::create_series_work(task2, nullptr)
		};
		ParallelWork *parallel =
			Workflow::create_parallel_work(sub_series, 2, nullptr);

		series->push_front(this);
		series->push_front(parallel);
		this->flag = 1;
		this->subtask_done();
	}
	else
		this->__WFSortTaskCmp<T, CMP>::dispatch();
}

template<typename T, class CMP>
void __WFParSortTaskCmp<T, CMP>::execute()
{
	if (this->flag)
	{
		size_t n = this->input.last - this->input.first;
		T *middle = this->input.first + n / 2;

		std::inplace_merge(this->input.first, middle, this->input.last,
						   std::move(this->compare));
		this->output.first = this->input.first;
		this->output.last = this->input.last;
		this->flag = 0;
	}
	else
		this->__WFSortTaskCmp<T, CMP>::execute();
}

/********** Factory functions without CMP **********/

template<typename T, class CB>
WFSortTask<T> *WFAlgoTaskFactory::create_sort_task(const std::string& name,
												   T *first, T *last,
												   CB callback)
{
	return new __WFSortTask<T>(WFGlobal::get_exec_queue(name),
							   WFGlobal::get_compute_executor(),
							   first, last,
							   std::move(callback));
}

template<typename T, class CB>
WFMergeTask<T> *WFAlgoTaskFactory::create_merge_task(const std::string& name,
													 T *first1, T *last1,
													 T *first2, T *last2,
													 T *d_first,
													 CB callback)
{
	return new __WFMergeTask<T>(WFGlobal::get_exec_queue(name),
							    WFGlobal::get_compute_executor(),
								first1, last1, first2, last2, d_first,
								std::move(callback));
}

template<typename T, class CB>
WFSortTask<T> *WFAlgoTaskFactory::create_psort_task(const std::string& name,
													T *first, T *last,
													CB callback)
{
	return new __WFParSortTask<T>(WFGlobal::get_exec_queue(name),
								  WFGlobal::get_compute_executor(),
								  first, last, 0,
								  std::move(callback));
}

/********** Factory functions with CMP **********/

template<typename T, class CMP, class CB>
WFSortTask<T> *WFAlgoTaskFactory::create_sort_task(const std::string& name,
												   T *first, T *last,
												   CMP compare,
												   CB callback)
{
	return new __WFSortTaskCmp<T, CMP>(WFGlobal::get_exec_queue(name),
									   WFGlobal::get_compute_executor(),
									   first, last, std::move(compare),
									   std::move(callback));
}

template<typename T, class CMP, class CB>
WFMergeTask<T> *WFAlgoTaskFactory::create_merge_task(const std::string& name,
													 T *first1, T *last1,
													 T *first2, T *last2,
													 T *d_first,
													 CMP compare,
													 CB callback)
{
	return new __WFMergeTaskCmp<T, CMP>(WFGlobal::get_exec_queue(name),
										WFGlobal::get_compute_executor(),
										first1, last1, first2, last2,
										d_first, std::move(compare),
										std::move(callback));
}

template<typename T, class CMP, class CB>
WFSortTask<T> *WFAlgoTaskFactory::create_psort_task(const std::string& name,
													T *first, T *last,
													CMP compare,
													CB callback)
{
	return new __WFParSortTaskCmp<T, CMP>(WFGlobal::get_exec_queue(name),
										  WFGlobal::get_compute_executor(),
										  first, last, std::move(compare), 0,
										  std::move(callback));
}

/****************** Shuffle ******************/

template<typename T>
class __WFShuffleTask : public WFShuffleTask<T>
{
protected:
	virtual void execute()
	{
		std::shuffle(this->input.first, this->input.last,
					 std::mt19937_64(random()));
		this->output.first = this->input.first;
		this->output.last = this->input.last;
	}

public:
	__WFShuffleTask(ExecQueue *queue, Executor *executor,
					T *first, T *last,
					shuffle_callback_t<T>&& cb) :
		WFShuffleTask<T>(queue, executor, std::move(cb))
	{
		this->input.first = first;
		this->input.last = last;
		this->output.first = NULL;
		this->output.last = NULL;
	}
};

template<typename T, class URBG>
class __WFShuffleTaskGen : public __WFShuffleTask<T>
{
protected:
	virtual void execute()
	{
		std::shuffle(this->input.first, this->input.last,
					 std::move(this->generator));
		this->output.first = this->input.first;
		this->output.last = this->input.last;
	}

protected:
	URBG generator;

public:
	__WFShuffleTaskGen(ExecQueue *queue, Executor *executor,
					   T *first, T *last, URBG&& gen,
					   shuffle_callback_t<T>&& cb) :
		__WFShuffleTask<T>(queue, executor, std::move(cb)),
		generator(std::move(gen))
	{
	}
};

template<typename T, class CB>
WFShuffleTask<T> *WFAlgoTaskFactory::create_shuffle_task(const std::string& name,
														 T *first, T *last,
														 CB callback)
{
	return new __WFShuffleTask<T>(WFGlobal::get_exec_queue(name),
								  WFGlobal::get_compute_executor(),
								  first, last,
								  std::move(callback));
}

template<typename T, class URBG, class CB>
WFShuffleTask<T> *WFAlgoTaskFactory::create_shuffle_task(const std::string& name,
														 T *first, T *last,
														 URBG generator,
														 CB callback)
{
	return new __WFShuffleTaskGen<T, URBG>(WFGlobal::get_exec_queue(name),
										   WFGlobal::get_compute_executor(),
										   first, last, std::move(generator),
										   std::move(callback));
}

/****************** Remove ******************/

template<typename T>
class __WFRemoveTask : public WFRemoveTask<T>
{
protected:
	virtual void execute()
	{
		this->output.last = std::remove(this->input.first, this->input.last,
										this->input.value);
		this->output.first = this->input.first;
	}

public:
	__WFRemoveTask(ExecQueue *queue, Executor *executor,
				   T *first, T *last, T&& value,
				   remove_callback_t<T>&& cb) :
		WFRemoveTask<T>(queue, executor, std::move(cb))
	{
		this->input.first = first;
		this->input.last = last;
		this->input.value = std::move(value);
		this->output.first = NULL;
		this->output.last = NULL;
	}
};

template<typename T, class CB>
WFRemoveTask<T> *WFAlgoTaskFactory::create_remove_task(const std::string& name,
													   T *first, T *last,
													   T value,
													   CB callback)
{
	return new __WFRemoveTask<T>(WFGlobal::get_exec_queue(name),
								 WFGlobal::get_compute_executor(),
								 first, last, std::move(value),
								 std::move(callback));
}

/****************** Unique ******************/

template<typename T>
class __WFUniqueTask : public WFUniqueTask<T>
{
protected:
	virtual void execute()
	{
		this->output.last = std::unique(this->input.first, this->input.last);
		this->output.first = this->input.first;
	}

public:
	__WFUniqueTask(ExecQueue *queue, Executor *executor,
				   T *first, T *last,
				   unique_callback_t<T>&& cb) :
		WFUniqueTask<T>(queue, executor, std::move(cb))
	{
		this->input.first = first;
		this->input.last = last;
		this->output.first = NULL;
		this->output.last = NULL;
	}
};

template<typename T, class CB>
WFUniqueTask<T> *WFAlgoTaskFactory::create_unique_task(const std::string& name,
													   T *first, T *last,
													   CB callback)
{
	return new __WFUniqueTask<T>(WFGlobal::get_exec_queue(name),
								 WFGlobal::get_compute_executor(),
								 first, last,
								 std::move(callback));
}

/****************** Reverse ******************/

template<typename T>
class __WFReverseTask : public WFReverseTask<T>
{
protected:
	virtual void execute()
	{
		std::reverse(this->input.first, this->input.last);
		this->output.first = this->input.first;
		this->output.last = this->input.last;
	}

public:
	__WFReverseTask(ExecQueue *queue, Executor *executor,
					T *first, T *last,
					reverse_callback_t<T>&& cb) :
		WFReverseTask<T>(queue, executor, std::move(cb))
	{
		this->input.first = first;
		this->input.last = last;
		this->output.first = NULL;
		this->output.last = NULL;
	}
};

template<typename T, class CB>
WFReverseTask<T> *WFAlgoTaskFactory::create_reverse_task(const std::string& name,
														 T *first, T *last,
														 CB callback)
{
	return new __WFReverseTask<T>(WFGlobal::get_exec_queue(name),
								  WFGlobal::get_compute_executor(),
								  first, last,
								  std::move(callback));
}

/****************** Rotate ******************/

template<typename T>
class __WFRotateTask : public WFRotateTask<T>
{
protected:
	virtual void execute()
	{
		std::rotate(this->input.first, this->input.middle, this->input.last);
		this->output.first = this->input.first;
		this->output.last = this->input.last;
	}

public:
	__WFRotateTask(ExecQueue *queue, Executor *executor,
					T *first, T* middle, T *last,
					rotate_callback_t<T>&& cb) :
		WFRotateTask<T>(queue, executor, std::move(cb))
	{
		this->input.first = first;
		this->input.middle = middle;
		this->input.last = last;
		this->output.first = NULL;
		this->output.last = NULL;
	}
};

template<typename T, class CB>
WFRotateTask<T> *WFAlgoTaskFactory::create_rotate_task(const std::string& name,
													   T *first, T *middle, T *last,
													   CB callback)
{
	return new __WFRotateTask<T>(WFGlobal::get_exec_queue(name),
								 WFGlobal::get_compute_executor(),
								 first, middle, last,
								 std::move(callback));
}

/****************** MapReduce ******************/

template<typename KEY, typename VAL>
class __WFReduceTask : public WFReduceTask<KEY, VAL>
{
protected:
	virtual void execute();

protected:
	algorithm::reduce_function_t<KEY, VAL> reduce;

public:
	__WFReduceTask(ExecQueue *queue, Executor *executor,
				   algorithm::reduce_function_t<KEY, VAL>&& red,
				   reduce_callback_t<KEY, VAL>&& cb) :
		WFReduceTask<KEY, VAL>(queue, executor, std::move(cb)),
		reduce(std::move(red))
	{
	}

	__WFReduceTask(ExecQueue *queue, Executor *executor,
				   algorithm::ReduceInput<KEY, VAL>&& input,
				   algorithm::reduce_function_t<KEY, VAL>&& red,
				   reduce_callback_t<KEY, VAL>&& cb) :
		WFReduceTask<KEY, VAL>(queue, executor, std::move(cb)),
		reduce(std::move(red))
	{
		this->input = std::move(input);
	}
};

template<class KEY, class VAL>
void __WFReduceTask<KEY, VAL>::execute()
{
	algorithm::Reducer<KEY, VAL> reducer;
	auto iter = this->input.begin();

	while (iter != this->input.end())
	{
		reducer.insert(std::move(iter->first), std::move(iter->second));
		iter++;
	}

	this->input.clear();
	reducer.start(this->reduce, &this->output);
}

template<typename KEY, typename VAL, class RED, class CB>
WFReduceTask<KEY, VAL> *
WFAlgoTaskFactory::create_reduce_task(const std::string& name,
									  RED reduce,
									  CB callback)
{
	return new __WFReduceTask<KEY, VAL>(WFGlobal::get_exec_queue(name),
										WFGlobal::get_compute_executor(),
										std::move(reduce),
										std::move(callback));
}

template<typename KEY, typename VAL, class RED, class CB>
WFReduceTask<KEY, VAL> *
WFAlgoTaskFactory::create_reduce_task(const std::string& name,
									  algorithm::ReduceInput<KEY, VAL> input,
									  RED reduce,
									  CB callback)
{
	return new __WFReduceTask<KEY, VAL>(WFGlobal::get_exec_queue(name),
										WFGlobal::get_compute_executor(),
										std::move(input),
										std::move(reduce),
										std::move(callback));
}

