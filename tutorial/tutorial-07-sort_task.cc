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

  Author: Xie Han (xiehan@sogou-inc.com;63350856@qq.com)
*/

#include <stdlib.h>
#include <stdio.h>
#include "workflow/WFAlgoTaskFactory.h"
#include "workflow/WFFacilities.h"

using namespace algorithm;

static WFFacilities::WaitGroup wait_group(1);

bool use_parallel_sort = false;

void callback(WFSortTask<int> *task)
{
	/* Sort task's input and output are identical. */
	SortInput<int> *input = task->get_input();
	int *first = input->first;
	int *last = input->last;

	/* You may remove this output to test speed. */
	int *p = first;

	while (p < last)
		printf("%d ", *p++);

	printf("\n");
	if (task->user_data == NULL)
	{
		auto cmp = [](int a1, int a2)->bool{return a2<a1;};
		WFSortTask<int> *reverse;

		if (use_parallel_sort)
			reverse = WFAlgoTaskFactory::create_psort_task("sort", first, last,
														   cmp, callback);
		else
			reverse = WFAlgoTaskFactory::create_sort_task("sort", first, last,
														    cmp, callback);

		reverse->user_data = (void *)1;	/* as a flag */
		series_of(task)->push_back(reverse);
		printf("Sort reversely:\n");
	}
	else
		wait_group.done();
}

int main(int argc, char *argv[])
{
	size_t count;
	int *array;
	int *end;
	size_t i;

	if (argc != 2 && argc != 3)
	{
		fprintf(stderr, "USAGE: %s <count> [p]\n", argv[0]);
		exit(1);
	}

	count = atoi(argv[1]);
	array = (int *)malloc(count * sizeof (int));
	if (!array)
	{
		perror("malloc");
		exit(1);
	}

	if (argc == 3 && (*argv[2] == 'p' || *argv[2] == 'P'))
		use_parallel_sort = true;

	for (i = 0; i < count; i++)
		array[i] = rand() % 65536;
	end = &array[count];

	WFSortTask<int> *task;
	if (use_parallel_sort)
		task = WFAlgoTaskFactory::create_psort_task("sort", array, end,
													callback);
	else
		task = WFAlgoTaskFactory::create_sort_task("sort", array, end,
													callback);

	if (use_parallel_sort)
		printf("Start sorting parallelly...\n");
	else
		printf("Start sorting...\n");

	printf("Sort result:\n");
	task->start();

	wait_group.wait();
	free(array);
	return 0;
}

