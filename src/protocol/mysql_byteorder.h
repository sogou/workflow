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

static inline int16_t sint2korr(const unsigned char *A)
{
	int16_t ret;
	memcpy(&ret, A, sizeof(ret));
	return ret;
}

static inline int32_t sint4korr(const unsigned char *A)
{
	int32_t ret;
	memcpy(&ret, A, sizeof(ret));
	return ret;
}

static inline uint16_t uint2korr(const unsigned char *A)
{
	uint16_t ret;
	memcpy(&ret, A, sizeof(ret));
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

static inline int64_t sint8korr(const unsigned char *A)
{
	int64_t ret;
	memcpy(&ret, A, sizeof(ret));
	return ret;
}

static inline void int2store(unsigned char *T, uint16_t A)
{
	memcpy(T, &A, sizeof(A));
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

static inline void float4get(float *V, const unsigned char *M)
{
	memcpy(V, (M), sizeof(float));
}

static inline void float4store(unsigned char *V, float M)
{
	memcpy(V, (&M), sizeof(float));
}

static inline void float8get(double *V, const unsigned char *M)
{
	memcpy(V, M, sizeof(double));
}

static inline void float8store(unsigned char *V, double M)
{
	memcpy(V, &M, sizeof(double));
}

static inline void floatget(float *V, const unsigned char *M)
{
	float4get(V, M);
}

static inline void floatstore(unsigned char *V, float M)
{
	float4store(V, M);
}

static inline void doublestore(unsigned char *T, double V)
{
	memcpy(T, &V, sizeof(double));
}
static inline void doubleget(double *V, const unsigned char *M)
{
	memcpy(V, M, sizeof(double));
}

static inline void ushortget(uint16_t *V, const unsigned char *pM)
{
	*V = uint2korr(pM);
}

static inline void shortget(int16_t *V, const unsigned char *pM)
{
	*V = sint2korr(pM);
}

static inline void longget(int32_t *V, const unsigned char *pM)
{
	*V = sint4korr(pM);
}

static inline void ulongget(uint32_t *V, const unsigned char *pM)
{
	*V = uint4korr(pM);
}

static inline void shortstore(unsigned char *T, int16_t V)
{
	int2store(T, V);
}

static inline void longstore(unsigned char *T, int32_t V)
{
	int4store(T, V);
}

static inline void longlongget(int64_t *V, const unsigned char *M)
{
	memcpy(V, (M), sizeof(uint64_t));
}

static inline void longlongstore(unsigned char *T, int64_t V)
{
	memcpy((T), &V, sizeof(uint64_t));
}

static inline int32_t sint3korr(const unsigned char *A)
{
	int32_t ret = 0;
	memcpy(&ret, A, 3);
	return ret;
}

static inline uint32_t uint3korr(const unsigned char *A)
{
	uint32_t ret = 0;
	memcpy(&ret, A, 3);
	return ret;
}

static inline void int3store(unsigned char *T, uint32_t A)
{
	memcpy(T, &A, 3);
}

#elif __BYTE_ORDER == __BIG_ENDIAN

static inline int16_t sint2korr(const unsigned char *A)
{
	return (int16_t)(((int16_t)(A[0])) + ((int16_t)(A[1]) << 8));
}

static inline int32_t sint4korr(const unsigned char *A)
{
	return (int32_t)(((int32_t)(A[0])) + (((int32_t)(A[1]) << 8)) +
		   (((int32_t)(A[2]) << 16)) + (((int32_t)(A[3]) << 24)));
}

static inline uint16_t uint2korr(const unsigned char *A)
{
	return (uint16_t)(((uint16_t)(A[0])) + ((uint16_t)(A[1]) << 8));
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

static inline int64_t sint8korr(const unsigned char *A)
{
	return (int64_t)uint8korr(A);
}

static inline void int2store(unsigned char *T, uint16_t A)
{
	uint def_temp = A;
	*(T) = (unsigned char)(def_temp);
	*(T + 1) = (unsigned char)(def_temp >> 8);
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
	uint def_temp = (uint)A, def_temp2 = (uint)(A >> 32);
	int4store(T, def_temp);
	int4store(T + 4, def_temp2);
}

static inline void float4store(unsigned char *T, float A)
{
	*(T) = ((unsigned char *)&A)[3];
	*((T) + 1) = (unsigned char)((unsigned char *)&A)[2];
	*((T) + 2) = (unsigned char)((unsigned char *)&A)[1];
	*((T) + 3) = (unsigned char)((unsigned char *)&A)[0];
}

static inline void float4get(float *V, const unsigned char *M)
{
	float def_temp;
	((unsigned char *)&def_temp)[0] = (M)[3];
	((unsigned char *)&def_temp)[1] = (M)[2];
	((unsigned char *)&def_temp)[2] = (M)[1];
	((unsigned char *)&def_temp)[3] = (M)[0];
	(*V) = def_temp;
}

static inline void float8store(unsigned char *T, double V) {
	*(T) = ((unsigned char *)&V)[7];
	*((T) + 1) = (unsigned char)((unsigned char *)&V)[6];
	*((T) + 2) = (unsigned char)((unsigned char *)&V)[5];
	*((T) + 3) = (unsigned char)((unsigned char *)&V)[4];
	*((T) + 4) = (unsigned char)((unsigned char *)&V)[3];
	*((T) + 5) = (unsigned char)((unsigned char *)&V)[2];
	*((T) + 6) = (unsigned char)((unsigned char *)&V)[1];
	*((T) + 7) = (unsigned char)((unsigned char *)&V)[0];
}

static inline void float8get(double *V, const unsigned char *M)
{
	double def_temp;
	((unsigned char *)&def_temp)[0] = (M)[7];
	((unsigned char *)&def_temp)[1] = (M)[6];
	((unsigned char *)&def_temp)[2] = (M)[5];
	((unsigned char *)&def_temp)[3] = (M)[4];
	((unsigned char *)&def_temp)[4] = (M)[3];
	((unsigned char *)&def_temp)[5] = (M)[2];
	((unsigned char *)&def_temp)[6] = (M)[1];
	((unsigned char *)&def_temp)[7] = (M)[0];
	(*V) = def_temp;
}

static inline void ushortget(uint16_t *V, const unsigned char *pM)
{
	*V = (uint16_t)(((uint16_t)((unsigned char)(pM)[1])) +
		 ((uint16_t)((uint16_t)(pM)[0]) << 8));
}

static inline void shortget(int16_t *V, const unsigned char *pM)
{
	*V = (short)(((short)((unsigned char)(pM)[1])) +
		 ((short)((short)(pM)[0]) << 8));
}

static inline void longget(int32_t *V, const unsigned char *pM)
{
	int32_t def_temp;
	((unsigned char *)&def_temp)[0] = (pM)[0];
	((unsigned char *)&def_temp)[1] = (pM)[1];
	((unsigned char *)&def_temp)[2] = (pM)[2];
	((unsigned char *)&def_temp)[3] = (pM)[3];
	(*V) = def_temp;
}

static inline void ulongget(uint32_t *V, const unsigned char *pM)
{
	uint32_t def_temp;
	((unsigned char *)&def_temp)[0] = (pM)[0];
	((unsigned char *)&def_temp)[1] = (pM)[1];
	((unsigned char *)&def_temp)[2] = (pM)[2];
	((unsigned char *)&def_temp)[3] = (pM)[3];
	(*V) = def_temp;
}

static inline void shortstore(unsigned char *T, int16_t A)
{
	uint def_temp = (uint)(A);
	*(((unsigned char *)T) + 1) = (unsigned char)(def_temp);
	*(((unsigned char *)T) + 0) = (unsigned char)(def_temp >> 8);
}

static inline void longstore(unsigned char *T, int32_t A)
{
	*(((unsigned char *)T) + 3) = ((A));
	*(((unsigned char *)T) + 2) = (((A) >> 8));
	*(((unsigned char *)T) + 1) = (((A) >> 16));
	*(((unsigned char *)T) + 0) = (((A) >> 24));
}

static inline void floatget(float *V, const unsigned char *M)
{
	memcpy(V, (M), sizeof(float));
}

static inline void floatstore(unsigned char *T, float V)
{
	memcpy((T), (&V), sizeof(float));
}

static inline void doubleget(double *V, const unsigned char *M)
{
	memcpy(V, (M), sizeof(double));
}

static inline void doublestore(unsigned char *T, double V)
{
	memcpy((T), &V, sizeof(double));
}

static inline void longlongget(int64_t *V, const unsigned char *M)
{
	memcpy(V, (M), sizeof(uint64_t));
}

static inline void longlongstore(unsigned char *T, int64_t V)
{
	memcpy((T), &V, sizeof(uint64_t));
}

static inline int32_t sint3korr(const unsigned char *p)
{
	return ((int32_t)(((p[2]) & 128)
			 ? (((uint32_t)255L << 24) | (((uint32_t)p[2]) << 16)
			 | (((uint32_t)p[1]) << 8) | ((uint32_t)p[0]))
			 : (((uint32_t)p[2]) << 16) | (((uint32_t)p[1]) << 8)
			 | ((uint32_t)p[0])));
}

static inline uint32_t uint3korr(const unsigned char *p)
{
	return (uint32_t)(((uint32_t)(p[0])) +
		   (((uint32_t)(p[1])) << 8) +
		   (((uint32_t)(p[2])) << 16));
}

static inline void int3store(unsigned char *p, uint32_t x)
{
	*(p) = (unsigned char)(x);
	*(p + 1) = (unsigned char)(x >> 8);
	*(p + 2) = (unsigned char)(x >> 16);
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

