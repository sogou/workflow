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

#include <stddef.h>
#include <stdlib.h>
#include "poller.h"
#include "mpoller.h"

extern poller_t *__poller_create(void **, const struct poller_params *);
extern void __poller_destroy(poller_t *);

static int __mpoller_create(const struct poller_params *params,
							mpoller_t *mpoller)
{
	void **nodes_buf = (void **)calloc(params->max_open_files, sizeof (void *));
	unsigned int i;

	if (nodes_buf)
	{
		for (i = 0; i < mpoller->nthreads; i++)
		{
			mpoller->poller[i] = __poller_create(nodes_buf, params);
			if (!mpoller->poller[i])
				break;
		}

		if (i == mpoller->nthreads)
		{
			mpoller->nodes_buf = nodes_buf;
			return 0;
		}

		while (i > 0)
			__poller_destroy(mpoller->poller[--i]);

		free(nodes_buf);
	}

	return -1;
}

mpoller_t *mpoller_create(const struct poller_params *params, size_t nthreads)
{
	mpoller_t *mpoller;
	size_t size;

	if (nthreads == 0)
		nthreads = 1;

	size = offsetof(mpoller_t, poller) + nthreads * sizeof (void *);
	mpoller = (mpoller_t *)malloc(size);
	if (mpoller)
	{
		mpoller->nthreads = (unsigned int)nthreads;
		if (__mpoller_create(params, mpoller) >= 0)
			return mpoller;

		free(mpoller);
	}

	return NULL;
}

int mpoller_start(mpoller_t *mpoller)
{
	size_t i;

	for (i = 0; i < mpoller->nthreads; i++)
	{
		if (poller_start(mpoller->poller[i]) < 0)
			break;
	}

	if (i == mpoller->nthreads)
		return 0;

	while (i > 0)
		poller_stop(mpoller->poller[--i]);

	return -1;
}

void mpoller_stop(mpoller_t *mpoller)
{
	size_t i;

	for (i = 0; i < mpoller->nthreads; i++)
		poller_stop(mpoller->poller[i]);
}

void mpoller_destroy(mpoller_t *mpoller)
{
	size_t i;

	for (i = 0; i < mpoller->nthreads; i++)
		__poller_destroy(mpoller->poller[i]);

	free(mpoller->nodes_buf);
	free(mpoller);
}

