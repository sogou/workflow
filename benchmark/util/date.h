#ifndef _BENCHMARK_DATE_H_
#define _BENCHMARK_DATE_H_

#include <ctime>

static inline void date(char * buf, size_t n)
{
	auto tt = std::time(nullptr);
	std::tm cur{};
	// gmtime_r(&tt, &cur);
	localtime_r(&tt, &cur);
	strftime(buf, n, "%a, %d %b %Y %H:%M:%S %Z", &cur);
}

#endif //_BENCHMARK_DATE_H_
