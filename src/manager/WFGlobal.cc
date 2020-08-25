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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <string>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include "WFGlobal.h"
#include "EndpointParams.h"
#include "CommScheduler.h"
#include "DNSCache.h"
#include "RouteManager.h"
#include "Executor.h"
#include "WFTask.h"
#include "WFTaskError.h"

class __WFGlobal
{
public:
	static __WFGlobal *get_instance()
	{
		static __WFGlobal kInstance;
		return &kInstance;
	}

	const WFGlobalSettings *get_global_settings() const
	{
		return &settings_;
	}

	void set_global_settings(const WFGlobalSettings *settings)
	{
		settings_ = *settings;
	}

	const char *get_default_port(const std::string& scheme) const
	{
		const auto it = static_scheme_port_.find(scheme);

		if (it != static_scheme_port_.end())
			return it->second;

		const auto it2 = user_scheme_port_.find(scheme);

		if (it2 != user_scheme_port_.end())
			return it2->second.c_str();

		return NULL;
	}

	void register_scheme_port(const std::string& scheme, unsigned short port)
	{
		user_scheme_port_mutex_.lock();
		user_scheme_port_[scheme] = std::to_string(port);
		user_scheme_port_mutex_.unlock();
	}

	void sync_operation_begin()
	{
		bool inc;

		sync_mutex_.lock();
		inc = ++sync_count_ > sync_max_;

		if (inc)
			sync_max_ = sync_count_;
		sync_mutex_.unlock();
		if (inc)
			WFGlobal::get_scheduler()->increase_handler_thread();
	}

	void sync_operation_end()
	{
		sync_mutex_.lock();
		sync_count_--;
		sync_mutex_.unlock();
	}

private:
	__WFGlobal():
		settings_(GLOBAL_SETTINGS_DEFAULT)
	{
		static_scheme_port_["http"] = "80";
		static_scheme_port_["https"] = "443";
		static_scheme_port_["redis"] = "6379";
		static_scheme_port_["rediss"] = "6379";
		static_scheme_port_["mysql"] = "3306";
		static_scheme_port_["kafka"] = "9092";
		sync_count_ = 0;
		sync_max_ = 0;
	}

private:
	struct WFGlobalSettings settings_;
	std::unordered_map<std::string, const char *> static_scheme_port_;
	std::unordered_map<std::string, std::string> user_scheme_port_;
	std::mutex user_scheme_port_mutex_;
	std::mutex sync_mutex_;
	int sync_count_;
	int sync_max_;
};

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static std::mutex *__ssl_mutex;

static void ssl_locking_callback(int mode, int type, const char* file, int line)
{
	if (mode & CRYPTO_LOCK)
		__ssl_mutex[type].lock();
	else if (mode & CRYPTO_UNLOCK)
		__ssl_mutex[type].unlock();
}
#endif

class __SSLManager
{
public:
	static __SSLManager *get_instance()
	{
		static __SSLManager kInstance;
		return &kInstance;
	}

	SSL_CTX *get_ssl_client_ctx() { return ssl_client_ctx_; }
	SSL_CTX *get_ssl_server_ctx() { return ssl_server_ctx_; }

private:
	__SSLManager()
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		__ssl_mutex = new std::mutex[CRYPTO_num_locks()];
		CRYPTO_set_locking_callback(ssl_locking_callback);
		SSL_library_init();
		SSL_load_error_strings();
		//ERR_load_crypto_strings();
		//OpenSSL_add_all_algorithms();
#endif

		ssl_client_ctx_ = SSL_CTX_new(SSLv23_client_method());
		assert(ssl_client_ctx_ != NULL);
		ssl_server_ctx_ = SSL_CTX_new(SSLv23_server_method());
		assert(ssl_server_ctx_ != NULL);
	}

	~__SSLManager()
	{
		SSL_CTX_free(ssl_client_ctx_);
		SSL_CTX_free(ssl_server_ctx_);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
		//free ssl to avoid memory leak
		FIPS_mode_set(0);
		CRYPTO_set_locking_callback(NULL);
# ifdef CRYPTO_LOCK_ECDH
		CRYPTO_THREADID_set_callback(NULL);
# else
		CRYPTO_set_id_callback(NULL);
# endif
		ENGINE_cleanup();
		CONF_modules_unload(1);
		ERR_free_strings();
		EVP_cleanup();
# ifdef CRYPTO_LOCK_ECDH
		ERR_remove_thread_state(NULL);
# else
		ERR_remove_state(0);
# endif
		CRYPTO_cleanup_all_ex_data();
		sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
		delete []__ssl_mutex;
#endif
	}

private:
	SSL_CTX *ssl_client_ctx_;
	SSL_CTX *ssl_server_ctx_;
};

class IOServer : public IOService
{
public:
	IOServer(CommScheduler *scheduler):
		scheduler_(scheduler),
		flag_(true)
	{}

	int bind()
	{
		mutex_.lock();
		flag_ = false;

		int ret = scheduler_->io_bind(this);

		if (ret < 0)
			flag_ = true;

		mutex_.unlock();
		return ret;
	}

	void deinit()
	{
		std::unique_lock<std::mutex> lock(mutex_);
		while (!flag_)
			cond_.wait(lock);

		lock.unlock();
		IOService::deinit();
	}

private:
	virtual void handle_unbound()
	{
		mutex_.lock();
		flag_ = true;
		cond_.notify_one();
		mutex_.unlock();
	}

	virtual void handle_stop(int error)
	{
		scheduler_->io_unbind(this);
	}

	CommScheduler *scheduler_;
	std::mutex mutex_;
	std::condition_variable cond_;
	bool flag_;
};

class __DNSManager
{
public:
	ExecQueue *get_dns_queue() { return &dns_queue_; }
	Executor *get_dns_executor() { return &dns_executor_; }

	__DNSManager()
	{
		int ret;

		ret = dns_queue_.init();
		if (ret < 0)
			abort();

		ret = dns_executor_.init(__WFGlobal::get_instance()->
											 get_global_settings()->
											 dns_threads);
		if (ret < 0)
			abort();
	}

	~__DNSManager()
	{
		dns_executor_.deinit();
		dns_queue_.deinit();
	}

private:
	ExecQueue dns_queue_;
	Executor dns_executor_;
};

class __CommManager
{
public:
	static __CommManager *get_instance()
	{
		static __CommManager kInstance;
		return &kInstance;
	}

	CommScheduler *get_scheduler() { return &scheduler_; }
	RouteManager *get_route_manager() { return &route_manager_; }
	IOService *get_io_service()
	{
		if (!io_flag_)
		{
			io_mutex_.lock();
			if (!io_flag_)
			{
				io_server_ = new IOServer(&scheduler_);
				//todo EAGAIN 65536->2
				if (io_server_->init(8192) < 0)
					abort();

				if (io_server_->bind() < 0)
					abort();

				io_flag_ = true;
			}

			io_mutex_.unlock();
		}

		return io_server_;
	}

	ExecQueue *get_dns_queue()
	{
		return get_dns_manager_safe()->get_dns_queue();
	}

	Executor *get_dns_executor()
	{
		return get_dns_manager_safe()->get_dns_executor();
	}

private:
	__CommManager():
		io_server_(NULL),
		io_flag_(false),
		dns_manager_(NULL),
		dns_flag_(false)
	{
#ifdef SIGPIPE
		signal(SIGPIPE, SIG_IGN);
#endif
		const auto *settings = __WFGlobal::get_instance()->get_global_settings();
		int ret = scheduler_.init(settings->poller_threads,
								  settings->handler_threads);

		if (ret < 0)
			abort();
	}

	~__CommManager()
	{
		if (dns_manager_)
			delete dns_manager_;

		scheduler_.deinit();
		if (io_server_)
		{
			io_server_->deinit();
			delete io_server_;
		}
	}

	__DNSManager *get_dns_manager_safe()
	{
		if (!dns_flag_)
		{
			dns_mutex_.lock();
			if (!dns_flag_)
			{
				dns_manager_ = new __DNSManager();
				dns_flag_ = true;
			}

			dns_mutex_.unlock();
		}

		return dns_manager_;
	}

private:
	CommScheduler scheduler_;
	RouteManager route_manager_;
	IOServer *io_server_;
	volatile bool io_flag_;
	std::mutex io_mutex_;
	__DNSManager *dns_manager_;
	volatile bool dns_flag_;
	std::mutex dns_mutex_;
};

class __DNSCache
{
public:
	static __DNSCache *get_instance()
	{
		static __DNSCache kInstance;
		return &kInstance;
	}

	DNSCache *get_dns_cache() { return &dns_cache_; }

private:
	__DNSCache() { }

	~__DNSCache() { }

private:
	DNSCache dns_cache_;
};

class __ExecManager
{
protected:
	using ExecQueueMap = std::unordered_map<std::string, ExecQueue *>;

public:
	static __ExecManager *get_instance()
	{
		static __ExecManager kInstance;
		return &kInstance;
	}

	ExecQueue *get_exec_queue(const std::string& queue_name)
	{
		ExecQueue *queue = NULL;

		pthread_rwlock_rdlock(&rwlock_);
		const auto iter = queue_map_.find(queue_name);

		if (iter != queue_map_.cend())
			queue = iter->second;

		pthread_rwlock_unlock(&rwlock_);

		if (!queue)
		{
			queue = new ExecQueue();
			if (queue->init() < 0)
			{
				delete queue;
				queue = NULL;
			}
			else
			{
				pthread_rwlock_wrlock(&rwlock_);
				const auto ret = queue_map_.emplace(queue_name, queue);

				if (!ret.second)
				{
					queue->deinit();
					delete queue;
					queue = ret.first->second;
				}

				pthread_rwlock_unlock(&rwlock_);
			}
		}

		return queue;
	}

	Executor *get_compute_executor() { return &compute_executor_; }

private:
	__ExecManager():
		rwlock_(PTHREAD_RWLOCK_INITIALIZER)
	{
		int compute_threads = __WFGlobal::get_instance()->
										  get_global_settings()->
										  compute_threads;

		if (compute_threads <= 0)
			compute_threads = sysconf(_SC_NPROCESSORS_ONLN);

		if (compute_executor_.init(compute_threads) < 0)
			abort();
	}

	~__ExecManager()
	{
		compute_executor_.deinit();

		for (auto& kv : queue_map_)
		{
			kv.second->deinit();
			delete kv.second;
		}
	}

private:
	pthread_rwlock_t rwlock_;
	ExecQueueMap queue_map_;
	Executor compute_executor_;
};

CommScheduler *WFGlobal::get_scheduler()
{
	return __CommManager::get_instance()->get_scheduler();
}

DNSCache *WFGlobal::get_dns_cache()
{
	return __DNSCache::get_instance()->get_dns_cache();
}

RouteManager *WFGlobal::get_route_manager()
{
	return __CommManager::get_instance()->get_route_manager();
}

SSL_CTX *WFGlobal::get_ssl_client_ctx()
{
	return __SSLManager::get_instance()->get_ssl_client_ctx();
}

SSL_CTX *WFGlobal::get_ssl_server_ctx()
{
	return __SSLManager::get_instance()->get_ssl_server_ctx();
}

ExecQueue *WFGlobal::get_exec_queue(const std::string& queue_name)
{
	return __ExecManager::get_instance()->get_exec_queue(queue_name);
}

Executor *WFGlobal::get_compute_executor()
{
	return __ExecManager::get_instance()->get_compute_executor();
}

IOService *WFGlobal::get_io_service()
{
	return __CommManager::get_instance()->get_io_service();
}

ExecQueue *WFGlobal::get_dns_queue()
{
	return __CommManager::get_instance()->get_dns_queue();
}

Executor *WFGlobal::get_dns_executor()
{
	return __CommManager::get_instance()->get_dns_executor();
}

const char *WFGlobal::get_default_port(const std::string& scheme)
{
	return __WFGlobal::get_instance()->get_default_port(scheme);
}

void WFGlobal::register_scheme_port(const std::string& scheme,
									unsigned short port)
{
	__WFGlobal::get_instance()->register_scheme_port(scheme, port);
}

const WFGlobalSettings *WFGlobal::get_global_settings()
{
	return __WFGlobal::get_instance()->get_global_settings();
}

void WORKFLOW_library_init(const WFGlobalSettings *settings)
{
	__WFGlobal::get_instance()->set_global_settings(settings);
}

void WFGlobal::sync_operation_begin()
{
	__WFGlobal::get_instance()->sync_operation_begin();
}

void WFGlobal::sync_operation_end()
{
	__WFGlobal::get_instance()->sync_operation_end();
}

static inline const char *__get_ssl_error_string(int error)
{
	switch (error)
	{
	case SSL_ERROR_NONE:
		return "SSL Error None";

	case SSL_ERROR_ZERO_RETURN:
		return "SSL Error Zero Return";

	case SSL_ERROR_WANT_READ:
		return "SSL Error Want Read";

	case SSL_ERROR_WANT_WRITE:
		return "SSL Error Want Write";

	case SSL_ERROR_WANT_CONNECT:
		return "SSL Error Want Connect";

	case SSL_ERROR_WANT_ACCEPT:
		return "SSL Error Want Accept";

	case SSL_ERROR_WANT_X509_LOOKUP:
		return "SSL Error Want X509 Lookup";

#ifdef SSL_ERROR_WANT_ASYNC
	case SSL_ERROR_WANT_ASYNC:
		return "SSL Error Want Async";
#endif

#ifdef SSL_ERROR_WANT_ASYNC_JOB
	case SSL_ERROR_WANT_ASYNC_JOB:
		return "SSL Error Want Async Job";
#endif

#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
	case SSL_ERROR_WANT_CLIENT_HELLO_CB:
		return "SSL Error Want Client Hello CB";
#endif

	case SSL_ERROR_SYSCALL:
		return "SSL System Error";

	case SSL_ERROR_SSL:
		return "SSL Error SSL";

	default:
		break;
	}

	return "Unknown";
}

static inline const char *__get_task_error_string(int error)
{
	switch (error)
	{
	case WFT_ERR_URI_PARSE_FAILED:
		return "URI Parse Failed";

	case WFT_ERR_URI_SCHEME_INVALID:
		return "URI Scheme Invalid";

	case WFT_ERR_URI_PORT_INVALID:
		return "URI Port Invalid";

	case WFT_ERR_UPSTREAM_UNAVAILABLE:
		return "Upstream Unavailable";

	case WFT_ERR_HTTP_BAD_REDIRECT_HEADER:
		return "Http Bad Redirect Header";

	case WFT_ERR_REDIS_ACCESS_DENIED:
		return "Redis Access Denied";

	case WFT_ERR_REDIS_COMMAND_DISALLOWED:
		return "Redis Command Disallowed";

	case WFT_ERR_MYSQL_HOST_NOT_ALLOWED:
		return "MySQL Host Not Allowed";

	case WFT_ERR_MYSQL_ACCESS_DENIED:
		return "MySQL Access Denied";

	case WFT_ERR_MYSQL_INVALID_CHARACTER_SET:
		return "MySQL Invalid Character Set";

	case WFT_ERR_MYSQL_COMMAND_DISALLOWED:
		return "MySQL Command Disallowed";

	default:
		break;
	}

	return "Unknown";
}

const char *WFGlobal::get_error_string(int state, int error)
{
	switch (state)
	{
	case WFT_STATE_SUCCESS:
		return "Success";

	case WFT_STATE_TOREPLY:
		return "To Reply";

	case WFT_STATE_NOREPLY:
		return "No Reply";

	case WFT_STATE_SYS_ERROR:
		return strerror(error);

	case WFT_STATE_SSL_ERROR:
		return __get_ssl_error_string(error);

	case WFT_STATE_DNS_ERROR:
		return gai_strerror(error);

	case WFT_STATE_TASK_ERROR:
		return __get_task_error_string(error);

	case WFT_STATE_UNDEFINED:
		return "Undefined";

	default:
		break;
	}

	return "Unknown";
}

