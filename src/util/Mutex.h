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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#ifndef _MUTEX_H_
#define _MUTEX_H_

#include <pthread.h>

/**
 * @file   Mutex.h
 * @brief  RAII style pthread lock
 */

// RAII: YES
class Lock
{
public:
	Lock(pthread_mutex_t& mutex): mutex_(&mutex) { pthread_mutex_lock(mutex_); }
	Lock(pthread_mutex_t *mutex): mutex_(mutex) { pthread_mutex_lock(mutex_); }
	~Lock() { pthread_mutex_unlock(mutex_); }

private:
	pthread_mutex_t *mutex_;
};

// RAII: YES
class ReadLock
{
public:
	ReadLock(pthread_rwlock_t& rwlock): rwlock_(&rwlock) { pthread_rwlock_rdlock(rwlock_); }
	ReadLock(pthread_rwlock_t *rwlock): rwlock_(rwlock) { pthread_rwlock_rdlock(rwlock_); }
	~ReadLock() { pthread_rwlock_unlock(rwlock_); }

private:
	pthread_rwlock_t *rwlock_;
};

// RAII: YES
class WriteLock
{
public:
	WriteLock(pthread_rwlock_t& rwlock): rwlock_(&rwlock) { pthread_rwlock_wrlock(rwlock_); }
	WriteLock(pthread_rwlock_t *rwlock): rwlock_(rwlock) { pthread_rwlock_wrlock(rwlock_); }
	~WriteLock() { pthread_rwlock_unlock(rwlock_); }

private:
	pthread_rwlock_t *rwlock_;
};

#endif

