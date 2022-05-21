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

#include <vector>
#include "Workflow.h"
#include "WFGraphTask.h"

SubTask *WFGraphNode::done()
{
	SeriesWork *series = series_of(this);

	if (!this->user_data)
	{
		this->value = 1;
		this->user_data = (void *)1;
	}
	else
		delete this;

	return series->pop();
}

WFGraphNode::~WFGraphNode()
{
	if (this->user_data)
	{
		for (WFGraphNode *node : this->successors)
			node->WFCounterTask::count();
	}
}

WFGraphNode& WFGraphTask::create_graph_node(SubTask *task)
{
	WFGraphNode *node = new WFGraphNode;
	SeriesWork *series = Workflow::create_series_work(node, node, nullptr);

	series->push_back(task);
	this->parallel->add_series(series);
	return *node;
}

void WFGraphTask::dispatch()
{
	SeriesWork *series = series_of(this);

	if (this->parallel)
	{
		series->push_front(this);
		series->push_front(this->parallel);
		this->parallel = NULL;
	}
	else
		this->state = WFT_STATE_SUCCESS;

	this->subtask_done();
}

SubTask *WFGraphTask::done()
{
	SeriesWork *series = series_of(this);

	if (this->state == WFT_STATE_SUCCESS)
	{
		if (this->callback)
			this->callback(this);

		delete this;
	}

	return series->pop();
}

WFGraphTask::~WFGraphTask()
{
	SeriesWork *series;
	size_t i;

	if (this->parallel)
	{
		for (i = 0; i < this->parallel->size(); i++)
		{
			series = this->parallel->series_at(i);
			series->unset_last_task();
		}

		this->parallel->dismiss();
	}
}

