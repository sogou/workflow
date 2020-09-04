#ifndef _BENCHMARK_ARGS_H_
#define _BENCHMARK_ARGS_H_

#include <algorithm>
#include <numeric>
#include <string>

namespace details
{
	template <typename T>
	bool extract(const char *, T &);

	template <typename ... ARGS>
	int parse(int todo, char ** p, ARGS & ... args);

	template <>
	int parse(int todo, char ** p)
	{
		return 0;
	}

	template <typename T, typename ... ARGS>
	int parse(int todo, char ** p, T & t, ARGS & ... args)
	{
		if (todo != 0 && extract(*p, t))
		{
			return parse(todo - 1, p + 1, args ...) + 1;
		}
		return 0;
	}

	template <typename ... ARGS>
	int parse_args(int & argc, char ** argv, ARGS & ... args)
	{
		if (argc <= 1)
		{
			return 0;
		}

		int length = argc - 1;
		char ** begin = argv + 1;
		char ** end = begin + length;

		int done = parse(length, begin, args ...);
		std::rotate(begin, begin + done, end);
		std::reverse(end - done, end);

		argc -= done;
		return done;
	}

	template <>
	bool extract<size_t>(const char * p, size_t & t)
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

	template <>
	bool extract<unsigned short>(const char * p, unsigned short & t)
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

	template <>
	bool extract<std::string>(const char * p, std::string & t)
	{
		t = p;
		return true;
	}

	template <>
	bool extract<const char *>(const char * p, const char *& t)
	{
		t = p;
		return true;
	}
}

template <typename ... ARGS>
static int parse_args(int & argc, char ** argv, ARGS & ... args)
{
	return details::parse_args(argc, argv, args ...);
}

#endif //_BENCHMARK_ARGS_H_
