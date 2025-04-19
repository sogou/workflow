/*
  Copyright (c) 2025 Sogou, Inc.

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

#include "HttpTaskImpl.inl"
#include "WFHttpChunkedClient.h"

void WFHttpChunkedTask::task_chunked(protocol::HttpMessageChunk *chunk,
									   WFHttpTask *task)
{
	auto *t = (WFHttpChunkedTask *)task->user_data;

	t->chunk = chunk;
	if (t->chunked)
		t->chunked(t);
}

void WFHttpChunkedTask::task_callback(WFHttpTask *task)
{
	auto *t = (WFHttpChunkedTask *)task->user_data;

	t->state = task->get_state();
	t->error = task->get_error();
	t->chunk = NULL;
	if (t->callback)
		t->callback(t);

	t->task = NULL;
	delete t;
}

WFHttpChunkedTask *
WFHttpChunkedClient::create_chunked_task(const std::string& url,
										 int redirect_max,
										 chunked_t chunked,
										 callback_t callback)
{
	WFHttpTask *task = __WFHttpTaskFactory::create_chunked_task(url,
										redirect_max,
										WFHttpChunkedTask::task_chunked,
										WFHttpChunkedTask::task_callback);
	return new WFHttpChunkedTask(task, std::move(chunked), std::move(callback));
}

WFHttpChunkedTask *
WFHttpChunkedClient::create_chunked_task(const ParsedURI& uri,
										 int redirect_max,
										 chunked_t chunked,
										 callback_t callback)
{
	WFHttpTask *task = __WFHttpTaskFactory::create_chunked_task(uri,
										redirect_max,
										WFHttpChunkedTask::task_chunked,
										WFHttpChunkedTask::task_callback);
	return new WFHttpChunkedTask(task, std::move(chunked), std::move(callback));
}

