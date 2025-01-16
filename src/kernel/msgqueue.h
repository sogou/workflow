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

#ifndef _MSGQUEUE_H_
#define _MSGQUEUE_H_

#include <stddef.h>

typedef struct __msgqueue msgqueue_t;

#ifdef __cplusplus
extern "C"
{
#endif

/* A simple implementation of message queue. The max pending messages may
 * reach two times 'maxlen' when the queue is in blocking mode, and infinite
 * in nonblocking mode. 'linkoff' is the offset from the head of each message,
 * where spaces of one pointer size should be available for internal usage.
 * 'linkoff' can be positive or negative or zero. */

msgqueue_t *msgqueue_create(size_t maxlen, int linkoff);
void *msgqueue_get(msgqueue_t *queue);
void msgqueue_put(void *msg, msgqueue_t *queue);
void msgqueue_put_head(void *msg, msgqueue_t *queue);
void msgqueue_set_nonblock(msgqueue_t *queue);
void msgqueue_set_block(msgqueue_t *queue);
void msgqueue_destroy(msgqueue_t *queue);

#ifdef __cplusplus
}
#endif

#endif

