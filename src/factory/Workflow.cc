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
#include <stddef.h>
#include <string.h>
#include <utility>
#include <functional>
#include <mutex>
#include "Workflow.h"

SeriesWork::SeriesWork(SubTask *first, series_callback_t&& cb) :
	callback(std::move(cb))
{
	this->queue = new SubTask *[4];
	this->queue_size = 4;
	this->front = 0;
	this->back = 0;
	this->in_parallel = false;
	this->canceled = false;
	first->set_pointer(this);
	this->first = first;
	this->last = NULL;
	this->context = NULL;
}

void SeriesWork::dismiss_recursive()
{
	SubTask *task = first;

	this->in_parallel = false;
	this->callback = nullptr;
	do
	{
		ParallelWork *parallel = dynamic_cast<ParallelWork *>(task);

		if (parallel)
			parallel->dismiss_recursive();
		else
			delete task;

		task = this->pop_task();
	} while (task);
}

void SeriesWork::expand_queue()
{
	int size = 2 * this->queue_size;
	SubTask **queue = new SubTask *[size];
	int i, j;

	i = 0;
	j = this->front;
	do
	{
		queue[i++] = this->queue[j++];
		if (j == this->queue_size)
			j = 0;
	} while (j != this->back);

	delete []this->queue;
	this->queue = queue;
	this->queue_size = size;
	this->front = 0;
	this->back = i;
}

void SeriesWork::push_front(SubTask *task)
{
	this->mutex.lock();
	if (--this->front == -1)
		this->front = this->queue_size - 1;

	task->set_pointer(this);
	this->queue[this->front] = task;
	if (this->front == this->back)
		this->expand_queue();

	this->mutex.unlock();
}

void SeriesWork::push_back(SubTask *task)
{
	this->mutex.lock();
	task->set_pointer(this);
	this->queue[this->back] = task;
	if (++this->back == this->queue_size)
		this->back = 0;

	if (this->front == this->back)
		this->expand_queue();

	this->mutex.unlock();
}

SubTask *SeriesWork::pop()
{
	bool canceled = this->canceled;
	SubTask *task = this->pop_task();

	if (!canceled)
		return task;

	while (task)
	{
		ParallelWork *parallel = dynamic_cast<ParallelWork *>(task);

		if (parallel)
			parallel->dismiss_recursive();
		else
			delete task;

		task = this->pop_task();
	}

	return NULL;
}

SubTask *SeriesWork::pop_task()
{
	SubTask *task;

	this->mutex.lock();
	if (this->front != this->back)
	{
		task = this->queue[this->front];
		if (++this->front == this->queue_size)
			this->front = 0;
	}
	else
	{
		task = this->last;
		this->last = NULL;
	}

	this->mutex.unlock();
	if (!task)
	{
		if (this->callback)
			this->callback(this);

		if (!this->in_parallel)
			delete this;
	}

	return task;
}

ParallelWork::ParallelWork(parallel_callback_t&& cb) :
	ParallelTask(NULL, 0),
	callback(std::move(cb))
{
	this->all_series = NULL;
	this->buf_size = 0;
	this->context = NULL;
}

ParallelWork::ParallelWork(SeriesWork *const all_series[], size_t n,
						   parallel_callback_t&& cb) :
	ParallelTask(new SubTask *[2 * n], n),
	callback(std::move(cb))
{
	size_t i;

	this->all_series = (SeriesWork **)&this->subtasks[n];
	for (i = 0; i < n; i++)
	{
		assert(!all_series[i]->in_parallel);
		all_series[i]->in_parallel = true;
		this->all_series[i] = all_series[i];
		this->subtasks[i] = all_series[i]->first;
	}

	this->buf_size = n;
	this->context = NULL;
}

void ParallelWork::expand_buf()
{
	SubTask **buf;
	size_t size;

	this->buf_size *= 2;
	if (this->buf_size == 0)
		this->buf_size = 4;

	buf = new SubTask *[2 * this->buf_size];
	size = this->subtasks_nr * sizeof (void *);
	memcpy(buf, this->subtasks, size);
	memcpy(buf + this->buf_size, this->all_series, size);

	delete []this->subtasks;
	this->subtasks = buf;
	this->all_series = (SeriesWork **)&buf[this->buf_size];
}

void ParallelWork::add_series(SeriesWork *series)
{
	if (this->subtasks_nr == this->buf_size)
		this->expand_buf();

	assert(!series->in_parallel);
	series->in_parallel = true;
	this->all_series[this->subtasks_nr] = series;
	this->subtasks[this->subtasks_nr] = series->first;
	this->subtasks_nr++;
}

void ParallelWork::dismiss_recursive()
{
	size_t i;

	for (i = 0; i < this->subtasks_nr; i++)
		this->all_series[i]->dismiss_recursive();

	delete this;
}

SubTask *ParallelWork::done()
{
	SeriesWork *series = series_of(this);
	size_t i;

	if (this->callback)
		this->callback(this);

	for (i = 0; i < this->subtasks_nr; i++)
		delete this->all_series[i];

	delete this;
	return series->pop();
}

