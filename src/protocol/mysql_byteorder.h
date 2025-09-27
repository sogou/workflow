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

  Authors: Li Yingxin (liyingxin@sogou-inc.com)
*/

#ifndef _MYSQL_BYTEORDER_H_
#define _MYSQL_BYTEORDER_H_

#include <sys/types.h>
#include <string.h>
#include <stdint.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN

static inline uint16_t uint2korr(const unsigned char *A)
{
	uint16_t ret;
	memcpy(&ret, A, sizeof(ret));
	return ret;
}

static inline uint32_t uint3korr(const unsigned char *A)
{
	uint32_t ret = 0;
	memcpy(&ret, A, 3);
	return ret;
}

static inline uint32_t uint4korr(const unsigned char *A)
{
	uint32_t ret;
	memcpy(&ret, A, sizeof(ret));
	return ret;
}

static inline uint64_t uint8korr(const unsigned char *A)
{
	uint64_t ret;
	memcpy(&ret, A, sizeof(ret));
	return ret;
}

static inline void int2store(unsigned char *T, uint16_t A)
{
	memcpy(T, &A, sizeof(A));
}

static inline void int3store(unsigned char *T, uint32_t A)
{
	memcpy(T, &A, 3);
}

static inline void int4store(unsigned char *T, uint32_t A)
{
	memcpy(T, &A, sizeof(A));
}

static inline void int7store(unsigned char *T, uint64_t A)
{
	memcpy(T, &A, 7);
}

static inline void int8store(unsigned char *T, uint64_t A)
{
	memcpy(T, &A, sizeof(A));
}

#elif __BYTE_ORDER == __BIG_ENDIAN

static inline uint16_t uint2korr(const unsigned char *A)
{
	return (uint16_t)(((uint16_t)(A[0])) + ((uint16_t)(A[1]) << 8));
}

static inline uint32_t uint3korr(const unsigned char *p)
{
	return (uint32_t)(((uint32_t)(p[0])) +
		   (((uint32_t)(p[1])) << 8) +
		   (((uint32_t)(p[2])) << 16));
}

static inline uint32_t uint4korr(const unsigned char *A)
{
	return (uint32_t)(((uint32_t)(A[0])) + (((uint32_t)(A[1])) << 8) +
		   (((uint32_t)(A[2])) << 16) + (((uint32_t)(A[3])) << 24));
}

static inline uint64_t uint8korr(const unsigned char *A)
{
	return ((uint64_t)(((uint32_t)(A[0])) + (((uint32_t)(A[1])) << 8) +
		   (((uint32_t)(A[2])) << 16) + (((uint32_t)(A[3])) << 24)) +
		   (((uint64_t)(((uint32_t)(A[4])) + (((uint32_t)(A[5])) << 8) +
		   (((uint32_t)(A[6])) << 16) + (((uint32_t)(A[7])) << 24))) << 32));
}

static inline void int2store(unsigned char *T, uint16_t A)
{
	uint32_t def_temp = A;
	*(T) = (unsigned char)(def_temp);
	*(T + 1) = (unsigned char)(def_temp >> 8);
}

static inline void int3store(unsigned char *p, uint32_t x)
{
	*(p) = (unsigned char)(x);
	*(p + 1) = (unsigned char)(x >> 8);
	*(p + 2) = (unsigned char)(x >> 16);
}

static inline void int4store(unsigned char *T, uint32_t A)
{
	*(T) = (unsigned char)(A);
	*(T + 1) = (unsigned char)(A >> 8);
	*(T + 2) = (unsigned char)(A >> 16);
	*(T + 3) = (unsigned char)(A >> 24);
}

static inline void int7store(unsigned char *T, uint64_t A)
{
	*(T) = (unsigned char)(A);
	*(T + 1) = (unsigned char)(A >> 8);
	*(T + 2) = (unsigned char)(A >> 16);
	*(T + 3) = (unsigned char)(A >> 24);
	*(T + 4) = (unsigned char)(A >> 32);
	*(T + 5) = (unsigned char)(A >> 40);
	*(T + 6) = (unsigned char)(A >> 48);
}

static inline void int8store(unsigned char *T, uint64_t A)
{
	uint32_t def_temp = (uint32_t)A, def_temp2 = (uint32_t)(A >> 32);
	int4store(T, def_temp);
	int4store(T + 4, def_temp2);
}

#else
# error "unknown byte order"
#endif

// length of buffer needed to store this number [1, 3, 4, 9].
static inline unsigned int get_length_size(unsigned long long num)
{
	if (num < (unsigned long long)252LL)
		return 1;

	if (num < (unsigned long long)65536LL)
		return 3;

	if (num < (unsigned long long)16777216LL)
		return 4;

	return 9;
}

#ifdef __cplusplus
extern "C"
{
#endif

// decode encoded length integer within *end, move pos forward
int decode_length_safe(unsigned long long *res, const unsigned char **pos,
					   const unsigned char *end);

// decode encoded length string within *end, move pos forward
int decode_string(const unsigned char **str, unsigned long long *len,
				  const unsigned char **pos, const unsigned char *end);

#ifdef __cplusplus
}
#endif

#endif

