/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

	  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com;63350856@qq.com)
*/

#include <algorithm>
#include <stdlib.h>
#include <stdio.h>
#include "workflow/WFFacilities.h"
#include "workflow/WFAlgoTaskFactory.h"

using namespace algorithm;

struct array
{
	int *a;
	int n;
	size_t size() { return n; }
};

void reduce(const int *key, ReduceIterator<array> *iter, array *res)
{
	const array *v1 = iter->next();
	const array *v2 = iter->next();

	res->a = new int[v1->n + v2->n];
	res->n = v1->n + v2->n;
	std::merge(v1->a, v1->a + v1->n, v2->a, v2->a + v2->n, res->a);
	delete []v1->a;
	delete []v2->a;
}

WFFacilities::WaitGroup wait_group(1);

void callback(WFReduceTask<int, array> *task)
{
	ReduceOutput<int, array>& output = *task->get_output();
	array& res = output[0].second;

	for (int i = 0; i < res.n; i++)
		printf("%d ", res.a[i]);

	printf("\n");
	delete []res.a;
	wait_group.done();
}

int main(int argc, char *argv[])
{
	ReduceInput<int, array> input;
	array arr;
	int i;

	if (argc != 2)
	{
		fprintf(stderr, "USAGE: %s <num>\n", argv[0]);
		exit(1);
	}

	int n = atoi(argv[1]);

	for (i = 0; i < n; i++)
	{
		arr.n = 1;
		arr.a = new int[1];
		arr.a[0] = rand() % 65536;
		input.emplace_back(0, arr);
	}

	auto *task = WFAlgoTaskFactory::create_reduce_task("sort", std::move(input),
													   reduce, callback);
	task->start();

	wait_group.wait();
	return 0;
}

