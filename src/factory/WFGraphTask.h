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

#ifndef _WFGRAPHTASK_H_
#define _WFGRAPHTASK_H_

#include <vector>
#include <utility>
#include <functional>
#include "Workflow.h"
#include "WFTask.h"

class WFGraphNode : protected WFCounterTask
{
public:
	void precede(WFGraphNode& node)
	{
		node.value++;
		this->successors.push_back(&node);
	}

	void succeed(WFGraphNode& node)
	{
		node.precede(*this);
	}

protected:
	virtual SubTask *done();

protected:
	std::vector<WFGraphNode *> successors;

protected:
	WFGraphNode() : WFCounterTask(0, nullptr) { }
	virtual ~WFGraphNode();
	friend class WFGraphTask;
};

static inline WFGraphNode& operator --(WFGraphNode& node, int)
{
	return node;
}

static inline WFGraphNode& operator > (WFGraphNode& prec, WFGraphNode& succ)
{
	prec.precede(succ);
	return succ;
}

static inline WFGraphNode& operator < (WFGraphNode& succ, WFGraphNode& prec)
{
	succ.succeed(prec);
	return prec;
}

static inline WFGraphNode& operator --(WFGraphNode& node)
{
	return node;
}

class WFGraphTask : public WFGenericTask
{
public:
	WFGraphNode& create_graph_node(SubTask *task);

public:
	void set_callback(std::function<void (WFGraphTask *)> cb)
	{
		this->callback = std::move(cb);
	}

protected:
	virtual void dispatch();
	virtual SubTask *done();

protected:
	ParallelWork *parallel;
	std::function<void (WFGraphTask *)> callback;

public:
	WFGraphTask(std::function<void (WFGraphTask *)>&& cb) :
		callback(std::move(cb))
	{
		this->parallel = Workflow::create_parallel_work(nullptr);
	}

protected:
	virtual ~WFGraphTask();
};

#endif

