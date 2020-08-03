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

#ifndef _RWLOCK_H_
#define _RWLOCK_H_

#include <mutex>
#include <condition_variable>

class RWLock
{
public:
	RWLock() : status_(0), waiting_readers_(0), waiting_writers_(0) {}
	RWLock(const RWLock&) = delete;
	RWLock(RWLock&&) = delete;
	RWLock& operator= (const RWLock&) = delete;
	RWLock& operator= (RWLock&&) = delete;

	void rlock()
	{
		std::unique_lock<std::mutex> lock(mutex_);

		waiting_readers_++;
		//while (status_ < 0)
		while (status_ < 0 || waiting_writers_ > 0)
			read_cond_.wait(lock);

		waiting_readers_--;
		status_++;
	}

	void wlock()
	{
		std::unique_lock<std::mutex> lock(mutex_);

		waiting_writers_++;
		while (status_ != 0)
			write_cond_.wait(lock);

		waiting_writers_--;
		status_--;
	}

	void unlock()
	{
		std::lock_guard<std::mutex> lock(mutex_);

		if (status_ < 0)// status must be -1
			status_++;
		else if (status_ > 0)
			status_--;

		if (waiting_writers_ > 0)
		{
			if (status_ == 0)
				write_cond_.notify_one();
		}
		else if (waiting_readers_ > 0)
		{
			if (waiting_readers_ == 1)
				read_cond_.notify_one();
			else
				read_cond_.notify_all();
		}
	}

private:
	// -1		: one writer
	// 0		: no reader and no writer
	// n > 0	: n reader
	int32_t status_;
	int32_t waiting_readers_;
	int32_t waiting_writers_;
	std::mutex mutex_;
	std::condition_variable read_cond_;
	std::condition_variable write_cond_;
};

// RAII: YES
class ReadLock
{
public:
	ReadLock(RWLock& rwlock): rwlock_(&rwlock) { rwlock_->rlock(); }
	~ReadLock() { rwlock_->unlock(); }

private:
	RWLock *rwlock_;
};

// RAII: YES
class WriteLock
{
public:
	WriteLock(RWLock& rwlock): rwlock_(&rwlock) { rwlock_->wlock(); }
	~WriteLock() { rwlock_->unlock(); }

private:
	RWLock *rwlock_;
};

#endif

