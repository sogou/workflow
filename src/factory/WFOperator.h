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

#ifndef _WFOPERATOR_H_
#define _WFOPERATOR_H_

#include "Workflow.h"

/**
 * @file   WFOperator.h
 * @brief  Workflow Series/Parallel/Task operator
 */

/**
 * @brief      S=S>P
 * @note       Equivalent to x.push_back(&y)
*/
static inline SeriesWork& operator>(SeriesWork& x, ParallelWork& y);

/**
 * @brief      S=P>S
 * @note       Equivalent to y.push_front(&x)
*/
static inline SeriesWork& operator>(ParallelWork& x, SeriesWork& y);

/**
 * @brief      S=S>t
 * @note       Equivalent to x.push_back(&y)
*/
static inline SeriesWork& operator>(SeriesWork& x, SubTask& y);

/**
 * @brief      S=S>t
 * @note       Equivalent to x.push_back(y)
*/
static inline SeriesWork& operator>(SeriesWork& x, SubTask *y);

/**
 * @brief      S=t>S
 * @note       Equivalent to y.push_front(&x)
*/
static inline SeriesWork& operator>(SubTask& x, SeriesWork& y);

/**
 * @brief      S=t>S
 * @note       Equivalent to y.push_front(x)
*/
static inline SeriesWork& operator>(SubTask *x, SeriesWork& y);

/**
 * @brief      S=P>P
 * @note       Equivalent to Workflow::create_series_work(&x, nullptr)->push_back(&y)
*/
static inline SeriesWork& operator>(ParallelWork& x, ParallelWork& y);

/**
 * @brief      S=P>t
 * @note       Equivalent to Workflow::create_series_work(&x, nullptr)->push_back(&y)
*/
static inline SeriesWork& operator>(ParallelWork& x, SubTask& y);

/**
 * @brief      S=P>t
 * @note       Equivalent to Workflow::create_series_work(&x, nullptr)->push_back(y)
*/
static inline SeriesWork& operator>(ParallelWork& x, SubTask *y);

/**
 * @brief      S=t>P
 * @note       Equivalent to Workflow::create_series_work(&x, nullptr)->push_back(&y)
*/
static inline SeriesWork& operator>(SubTask& x, ParallelWork& y);

/**
 * @brief      S=t>P
 * @note       Equivalent to Workflow::create_series_work(x, nullptr)->push_back(&y)
*/
static inline SeriesWork& operator>(SubTask *x, ParallelWork& y);

/**
 * @brief      S=t>t
 * @note       Equivalent to Workflow::create_series_work(&x, nullptr)->push_back(&y)
*/
static inline SeriesWork& operator>(SubTask& x, SubTask& y);

/**
 * @brief      S=t>t
 * @note       Equivalent to Workflow::create_series_work(&x, nullptr)->push_back(y)
*/
static inline SeriesWork& operator>(SubTask& x, SubTask *y);

/**
 * @brief      S=t>t
 * @note       Equivalent to Workflow::create_series_work(x, nullptr)->push_back(&y)
*/
static inline SeriesWork& operator>(SubTask *x, SubTask& y);
//static inline SeriesWork& operator>(SubTask *x, SubTask *y);//compile error!

/**
 * @brief      P=P*S
 * @note       Equivalent to x.add_series(&y)
*/
static inline ParallelWork& operator*(ParallelWork& x, SeriesWork& y);

/**
 * @brief      P=S*P
 * @note       Equivalent to y.push_back(&x)
*/
static inline ParallelWork& operator*(SeriesWork& x, ParallelWork& y);

/**
 * @brief      P=P*t
 * @note       Equivalent to x.add_series(Workflow::create_series_work(&y, nullptr))
*/
static inline ParallelWork& operator*(ParallelWork& x, SubTask& y);

/**
 * @brief      P=P*t
 * @note       Equivalent to x.add_series(Workflow::create_series_work(y, nullptr))
*/
static inline ParallelWork& operator*(ParallelWork& x, SubTask *y);

/**
 * @brief      P=t*P
 * @note       Equivalent to y.add_series(Workflow::create_series_work(&x, nullptr))
*/
static inline ParallelWork& operator*(SubTask& x, ParallelWork& y);

/**
 * @brief      P=t*P
 * @note       Equivalent to y.add_series(Workflow::create_series_work(x, nullptr))
*/
static inline ParallelWork& operator*(SubTask *x, ParallelWork& y);

/**
 * @brief      P=S*S
 * @note       Equivalent to Workflow::create_parallel_work({&x, &y}, 2, nullptr)
*/
static inline ParallelWork& operator*(SeriesWork& x, SeriesWork& y);

/**
 * @brief      P=S*t
 * @note       Equivalent to Workflow::create_parallel_work({&y}, 1, nullptr)->add_series(&x)
*/
static inline ParallelWork& operator*(SeriesWork& x, SubTask& y);

/**
 * @brief      P=S*t
 * @note       Equivalent to Workflow::create_parallel_work({y}, 1, nullptr)->add_series(&x)
*/
static inline ParallelWork& operator*(SeriesWork& x, SubTask *y);

/**
 * @brief      P=t*S
 * @note       Equivalent to Workflow::create_parallel_work({&x}, 1, nullptr)->add_series(&y)
*/
static inline ParallelWork& operator*(SubTask& x, SeriesWork& y);

/**
 * @brief      P=t*S
 * @note       Equivalent to Workflow::create_parallel_work({x}, 1, nullptr)->add_series(&y)
*/
static inline ParallelWork& operator*(SubTask *x, SeriesWork& y);

/**
 * @brief      P=t*t
 * @note       Equivalent to Workflow::create_parallel_work({Workflow::create_series_work(&x, nullptr), Workflow::create_series_work(&y, nullptr)}, 2, nullptr)
*/
static inline ParallelWork& operator*(SubTask& x, SubTask& y);

/**
 * @brief      P=t*t
 * @note       Equivalent to Workflow::create_parallel_work({Workflow::create_series_work(&x, nullptr), Workflow::create_series_work(y, nullptr)}, 2, nullptr)
*/
static inline ParallelWork& operator*(SubTask& x, SubTask *y);

/**
 * @brief      P=t*t
 * @note       Equivalent to Workflow::create_parallel_work({Workflow::create_series_work(x, nullptr), Workflow::create_series_work(&y, nullptr)}, 2, nullptr)
*/
static inline ParallelWork& operator*(SubTask *x, SubTask& y);
//static inline ParallelWork& operator*(SubTask *x, SubTask *y);//compile error!


//S=S>t
static inline SeriesWork& operator>(SeriesWork& x, SubTask& y)
{
	x.push_back(&y);
	return x;
}
static inline SeriesWork& operator>(SeriesWork& x, SubTask *y)
{
	return x > *y;
}
//S=t>S
static inline SeriesWork& operator>(SubTask& x, SeriesWork& y)
{
	y.push_front(&x);
	return y;
}
static inline SeriesWork& operator>(SubTask *x, SeriesWork& y)
{
	return *x > y;
}
//S=t>t
static inline SeriesWork& operator>(SubTask& x, SubTask& y)
{
	SeriesWork *series = Workflow::create_series_work(&x, nullptr);
	series->push_back(&y);
	return *series;
}
static inline SeriesWork& operator>(SubTask& x, SubTask *y)
{
	return x > *y;
}
static inline SeriesWork& operator>(SubTask *x, SubTask& y)
{
	return *x > y;
}
//S=S>P
static inline SeriesWork& operator>(SeriesWork& x, ParallelWork& y)
{
	return x > (SubTask&)y;
}
//S=P>S
static inline SeriesWork& operator>(ParallelWork& x, SeriesWork& y)
{
	return y > (SubTask&)x;
}
//S=P>P
static inline SeriesWork& operator>(ParallelWork& x, ParallelWork& y)
{
	return (SubTask&)x > (SubTask&)y;
}
//S=P>t
static inline SeriesWork& operator>(ParallelWork& x, SubTask& y)
{
	return (SubTask&)x > y;
}
static inline SeriesWork& operator>(ParallelWork& x, SubTask *y)
{
	return x > *y;
}
//S=t>P
static inline SeriesWork& operator>(SubTask& x, ParallelWork& y)
{
	return x > (SubTask&)y;
}
static inline SeriesWork& operator>(SubTask *x, ParallelWork& y)
{
	return *x > y;
}

//P=P*S
static inline ParallelWork& operator*(ParallelWork& x, SeriesWork& y)
{
	x.add_series(&y);
	return x;
}
//P=S*P
static inline ParallelWork& operator*(SeriesWork& x, ParallelWork& y)
{
	return y * x;
}
//P=P*t
static inline ParallelWork& operator*(ParallelWork& x, SubTask& y)
{
	x.add_series(Workflow::create_series_work(&y, nullptr));
	return x;
}
static inline ParallelWork& operator*(ParallelWork& x, SubTask *y)
{
	return x * (*y);
}
//P=t*P
static inline ParallelWork& operator*(SubTask& x, ParallelWork& y)
{
	return y * x;
}
static inline ParallelWork& operator*(SubTask *x, ParallelWork& y)
{
	return (*x) * y;
}
//P=S*S
static inline ParallelWork& operator*(SeriesWork& x, SeriesWork& y)
{
	SeriesWork *arr[2] = {&x, &y};
	return *Workflow::create_parallel_work(arr, 2, nullptr);
}
//P=S*t
static inline ParallelWork& operator*(SeriesWork& x, SubTask& y)
{
	return x * (*Workflow::create_series_work(&y, nullptr));
}
static inline ParallelWork& operator*(SeriesWork& x, SubTask *y)
{
	return x * (*y);
}
//P=t*S
static inline ParallelWork& operator*(SubTask& x, SeriesWork& y)
{
	return y * x;
}
static inline ParallelWork& operator*(SubTask *x, SeriesWork& y)
{
	return (*x) * y;
}
//P=t*t
static inline ParallelWork& operator*(SubTask& x, SubTask& y)
{
	SeriesWork *arr[2] = {Workflow::create_series_work(&x, nullptr),
						  Workflow::create_series_work(&y, nullptr)};
	return *Workflow::create_parallel_work(arr, 2, nullptr);
}
static inline ParallelWork& operator*(SubTask& x, SubTask *y)
{
	return x * (*y);
}
static inline ParallelWork& operator*(SubTask *x, SubTask& y)
{
	return (*x) * y;
}


#endif

