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

#ifndef _SUBTASK_H_
#define _SUBTASK_H_

#include <stddef.h>

class ParallelTask;

class SubTask
{
public:
	virtual void dispatch() = 0;

private:
	virtual SubTask *done() = 0;

protected:
	void subtask_done();

public:
	void *get_pointer() const { return this->pointer; }
	void set_pointer(void *pointer) { this->pointer = pointer; }

private:
	ParallelTask *parent;
	void *pointer;

public:
	SubTask()
	{
		this->parent = NULL;
		this->pointer = NULL;
	}

	virtual ~SubTask() { }
	friend class ParallelTask;
};

class ParallelTask : public SubTask
{
public:
	virtual void dispatch();

protected:
	SubTask **subtasks;
	size_t subtasks_nr;

private:
	size_t nleft;

public:
	ParallelTask(SubTask **subtasks, size_t n)
	{
		this->subtasks = subtasks;
		this->subtasks_nr = n;
	}

	virtual ~ParallelTask() { }
	friend class SubTask;
};

#endif

