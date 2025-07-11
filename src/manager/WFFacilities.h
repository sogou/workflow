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

  Authors: Li Yingxin (liyingxin@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
*/

#ifndef _WFFACILITIES_H_
#define _WFFACILITIES_H_

#include <assert.h>
#include "WFFuture.h"
#include "WFTaskFactory.h"

class WFFacilities
{
public:
	static void usleep(unsigned int microseconds);
	static WFFuture<void> async_usleep(unsigned int microseconds);

public:
	template<class FUNC, class... ARGS>
	static void go(const std::string& queue_name, FUNC&& func, ARGS&&... args);

public:
	template<class RESP>
	struct WFNetworkResult
	{
		RESP resp;
		long long seqid;
		int task_state;
		int task_error;
	};

	template<class REQ, class RESP>
	static WFNetworkResult<RESP> request(TransportType type, const std::string& url, REQ&& req, int retry_max);

	template<class REQ, class RESP>
	static WFFuture<WFNetworkResult<RESP>> async_request(TransportType type, const std::string& url, REQ&& req, int retry_max);

#ifndef _WIN32
public:// async fileIO
	static WFFuture<ssize_t> async_pread(int fd, void *buf, size_t count, off_t offset);
	static WFFuture<ssize_t> async_pwrite(int fd, const void *buf, size_t count, off_t offset);
	static WFFuture<ssize_t> async_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
	static WFFuture<ssize_t> async_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
	static WFFuture<int> async_fsync(int fd);
	static WFFuture<int> async_fdatasync(int fd);
#endif

public:
	class WaitGroup
	{
	public:
		WaitGroup(int n);
		~WaitGroup();

		void wait() const;
		std::future_status wait(int timeout) const;
		void add(int n);
		void done();

	private:
		static void __wait_group_callback(WFCounterTask *task);

		std::atomic<int> nleft;
		WFCounterTask *task;
		WFFuture<void> future;
	};

private:
	static void __timer_future_callback(WFTimerTask *task);
	static void __fio_future_callback(WFFileIOTask *task);
	static void __fvio_future_callback(WFFileVIOTask *task);
	static void __fsync_future_callback(WFFileSyncTask *task);
};

#include "WFFacilities.inl"

#endif

