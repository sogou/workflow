#ifndef _BENCHMARK_ARGS_H_
#define _BENCHMARK_ARGS_H_

#include <algorithm>
#include <numeric>
#include <string>

namespace details
{
	inline bool extract(const char * p, size_t & t)
	{
		char * e;
		long long ll = std::strtoll(p, &e, 0);
		if (*e || ll < 0)
		{
			return false;
		}
		t = static_cast<size_t>(ll);
		return true;
	}

	inline bool extract(const char * p, unsigned short & t)
	{
		char * e;
		long long ll = std::strtoll(p, &e, 0);
		if (*e
		    || ll < static_cast<long long>(std::numeric_limits<unsigned short>::min())
		    || ll > static_cast<long long>(std::numeric_limits<unsigned short>::max())
			)
		{
			return false;
		}
		t = static_cast<unsigned short>(ll);
		return true;
	}

	inline bool extract(const char * p, std::string & t)
	{
		t = p;
		return true;
	}

	inline bool extract(const char * p, const char *& t)
	{
		t = p;
		return true;
	}

	template <typename ARG>
	inline int parse_one(bool & flag, char **& p, char ** end, ARG & arg)
	{
		if (flag && (flag = p < end) && (flag = extract(*p, arg)))
		{
			p++;
		}
		return 0;
	}

	template <typename ... ARGS>
	inline size_t parse_all(char ** begin, char ** end, ARGS & ... args)
	{
		bool flag = true;
		char ** p = begin;
		static_cast<void>(std::initializer_list<int>{parse_one(flag, p, end, args) ...});
		return p - begin;
	}

	template <typename ... ARGS>
	inline size_t parse_args(int & argc, char ** argv, ARGS & ... args)
	{
		if (argc <= 1)
		{
			return 0;
		}

		size_t length = argc - 1;
		char ** begin = argv + 1;
		char ** end = begin + length;

		size_t done = parse_all(begin, end, args ...);
		std::rotate(begin, begin + done, end);
		std::reverse(end - done, end);

		argc -= done;
		return done;
	}
}

template <typename ... ARGS>
inline static size_t parse_args(int & argc, char ** argv, ARGS & ... args)
{
	return details::parse_args(argc, argv, args ...);
}

#endif //_BENCHMARK_ARGS_H_
