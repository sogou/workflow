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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN

static inline int16_t sint2korr(const char *A) {
  int16_t ret;
  memcpy(&ret, A, sizeof(ret));
  return ret;
}

static inline int32_t sint4korr(const char *A) {
  int32_t ret;
  memcpy(&ret, A, sizeof(ret));
  return ret;
}

static inline uint16_t uint2korr(const char *A) {
  uint16_t ret;
  memcpy(&ret, A, sizeof(ret));
  return ret;
}

static inline uint32_t uint4korr(const char *A) {
  uint32_t ret;
  memcpy(&ret, A, sizeof(ret));
  return ret;
}

static inline uint64_t uint8korr(const char *A) {
  uint64_t ret;
  memcpy(&ret, A, sizeof(ret));
  return ret;
}

static inline int64_t sint8korr(const char *A) {
  int64_t ret;
  memcpy(&ret, A, sizeof(ret));
  return ret;
}

static inline void int2store(char *T, uint16_t A) { memcpy(T, &A, sizeof(A)); }

static inline void int4store(char *T, uint32_t A) { memcpy(T, &A, sizeof(A)); }

static inline void int7store(char *T, uint64_t A) { memcpy(T, &A, 7); }

static inline void int8store(char *T, uint64_t A) {
  memcpy(T, &A, sizeof(A));
}

static inline void float4get(float *V, const char *M) {
  memcpy(V, (M), sizeof(float));
}

static inline void float4store(char *V, float M) {
  memcpy(V, (&M), sizeof(float));
}

static inline void float8get(double *V, const char *M) {
  memcpy(V, M, sizeof(double));
}

static inline void float8store(char *V, double M) {
  memcpy(V, &M, sizeof(double));
}

static inline void floatget(float *V, const char *M) { float4get(V, M); }
static inline void floatstore(char *V, float M) { float4store(V, M); }

static inline void doublestore(char *T, double V) {
  memcpy(T, &V, sizeof(double));
}
static inline void doubleget(double *V, const char *M) {
  memcpy(V, M, sizeof(double));
}

static inline void ushortget(uint16_t *V, const char *pM) { *V = uint2korr(pM); }
static inline void shortget(int16_t *V, const char *pM) { *V = sint2korr(pM); }
static inline void longget(int32_t *V, const char *pM) { *V = sint4korr(pM); }
static inline void ulongget(uint32_t *V, const char *pM) { *V = uint4korr(pM); }
static inline void shortstore(char *T, int16_t V) { int2store(T, V); }
static inline void longstore(char *T, int32_t V) { int4store(T, V); }

static inline void longlongget(int64_t *V, const char *M) {
  memcpy(V, (M), sizeof(uint64_t));
}
static inline void longlongstore(char *T, int64_t V) {
  memcpy((T), &V, sizeof(uint64_t));
}

#elif __BYTE_ORDER == __BIG_ENDIAN

static inline int16_t sint2korr(const char *A) {
  return (int16_t)(((int16_t)(A[0])) + ((int16_t)(A[1]) << 8));
}

static inline int32_t sint4korr(const char *A) {
  return (int32_t)(((int32_t)(A[0])) + (((int32_t)(A[1]) << 8)) +
                 (((int32_t)(A[2]) << 16)) + (((int32_t)(A[3]) << 24)));
}

static inline uint16_t uint2korr(const char *A) {
  return (uint16_t)(((uint16_t)(A[0])) + ((uint16_t)(A[1]) << 8));
}

static inline uint32_t uint4korr(const char *A) {
  return (uint32_t)(((uint32_t)(A[0])) + (((uint32_t)(A[1])) << 8) +
                  (((uint32_t)(A[2])) << 16) + (((uint32_t)(A[3])) << 24));
}

static inline uint64_t uint8korr(const char *A) {
  return ((uint64_t)(((uint32_t)(A[0])) + (((uint32_t)(A[1])) << 8) +
                      (((uint32_t)(A[2])) << 16) + (((uint32_t)(A[3])) << 24)) +
          (((uint64_t)(((uint32_t)(A[4])) + (((uint32_t)(A[5])) << 8) +
                        (((uint32_t)(A[6])) << 16) + (((uint32_t)(A[7])) << 24)))
           << 32));
}

static inline int64_t sint8korr(const char *A) {
  return (int64_t)uint8korr(A);
}

static inline void int2store(char *T, uint16_t A) {
  uint def_temp = A;
  *(T) = (char)(def_temp);
  *(T + 1) = (char)(def_temp >> 8);
}

static inline void int4store(char *T, uint32_t A) {
  *(T) = (char)(A);
  *(T + 1) = (char)(A >> 8);
  *(T + 2) = (char)(A >> 16);
  *(T + 3) = (char)(A >> 24);
}

static inline void int7store(char *T, uint64_t A) {
  *(T) = (char)(A);
  *(T + 1) = (char)(A >> 8);
  *(T + 2) = (char)(A >> 16);
  *(T + 3) = (char)(A >> 24);
  *(T + 4) = (char)(A >> 32);
  *(T + 5) = (char)(A >> 40);
  *(T + 6) = (char)(A >> 48);
}

static inline void int8store(char *T, uint64_t A) {
  uint def_temp = (uint)A, def_temp2 = (uint)(A >> 32);
  int4store(T, def_temp);
  int4store(T + 4, def_temp2);
}

static inline void float4store(char *T, float A) {
  *(T) = ((char *)&A)[3];
  *((T) + 1) = (char)((char *)&A)[2];
  *((T) + 2) = (char)((char *)&A)[1];
  *((T) + 3) = (char)((char *)&A)[0];
}

static inline void float4get(float *V, const char *M) {
  float def_temp;
  ((char *)&def_temp)[0] = (M)[3];
  ((char *)&def_temp)[1] = (M)[2];
  ((char *)&def_temp)[2] = (M)[1];
  ((char *)&def_temp)[3] = (M)[0];
  (*V) = def_temp;
}

static inline void float8store(char *T, double V) {
  *(T) = ((char *)&V)[7];
  *((T) + 1) = (char)((char *)&V)[6];
  *((T) + 2) = (char)((char *)&V)[5];
  *((T) + 3) = (char)((char *)&V)[4];
  *((T) + 4) = (char)((char *)&V)[3];
  *((T) + 5) = (char)((char *)&V)[2];
  *((T) + 6) = (char)((char *)&V)[1];
  *((T) + 7) = (char)((char *)&V)[0];
}

static inline void float8get(double *V, const char *M) {
  double def_temp;
  ((char *)&def_temp)[0] = (M)[7];
  ((char *)&def_temp)[1] = (M)[6];
  ((char *)&def_temp)[2] = (M)[5];
  ((char *)&def_temp)[3] = (M)[4];
  ((char *)&def_temp)[4] = (M)[3];
  ((char *)&def_temp)[5] = (M)[2];
  ((char *)&def_temp)[6] = (M)[1];
  ((char *)&def_temp)[7] = (M)[0];
  (*V) = def_temp;
}

static inline void ushortget(uint16_t *V, const char *pM) {
  *V = (uint16_t)(((uint16_t)((char)(pM)[1])) + ((uint16_t)((uint16_t)(pM)[0]) << 8));
}
static inline void shortget(int16_t *V, const char *pM) {
  *V = (short)(((short)((char)(pM)[1])) + ((short)((short)(pM)[0]) << 8));
}
static inline void longget(int32_t *V, const char *pM) {
  int32_t def_temp;
  ((char *)&def_temp)[0] = (pM)[0];
  ((char *)&def_temp)[1] = (pM)[1];
  ((char *)&def_temp)[2] = (pM)[2];
  ((char *)&def_temp)[3] = (pM)[3];
  (*V) = def_temp;
}
static inline void ulongget(uint32_t *V, const char *pM) {
  uint32_t def_temp;
  ((char *)&def_temp)[0] = (pM)[0];
  ((char *)&def_temp)[1] = (pM)[1];
  ((char *)&def_temp)[2] = (pM)[2];
  ((char *)&def_temp)[3] = (pM)[3];
  (*V) = def_temp;
}
static inline void shortstore(char *T, int16_t A) {
  uint def_temp = (uint)(A);
  *(((char *)T) + 1) = (char)(def_temp);
  *(((char *)T) + 0) = (char)(def_temp >> 8);
}
static inline void longstore(char *T, int32_t A) {
  *(((char *)T) + 3) = ((A));
  *(((char *)T) + 2) = (((A) >> 8));
  *(((char *)T) + 1) = (((A) >> 16));
  *(((char *)T) + 0) = (((A) >> 24));
}

static inline void floatget(float *V, const char *M) {
  memcpy(V, (M), sizeof(float));
}

static inline void floatstore(char *T, float V) {
  memcpy((T), (&V), sizeof(float));
}

static inline void doubleget(double *V, const char *M) {
  memcpy(V, (M), sizeof(double));
}

static inline void doublestore(char *T, double V) {
  memcpy((T), &V, sizeof(double));
}

static inline void longlongget(int64_t *V, const char *M) {
  memcpy(V, (M), sizeof(uint64_t));
}
static inline void longlongstore(char *T, int64_t V) {
  memcpy((T), &V, sizeof(uint64_t));
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

static inline int32_t sint3korr(const char *p)
{
	return ((int32_t)(((p[2]) & 128)
		   ? (((uint32_t)255L << 24) | (((uint32_t)p[2]) << 16)
		   | (((uint32_t)p[1]) << 8) | ((uint32_t)p[0]))
		   : (((uint32_t)p[2]) << 16) | (((uint32_t)p[1]) << 8)
		   | ((uint32_t)p[0])));
}

static inline uint32_t uint3korr(const char *p)
{
	return (uint32_t)(((uint32_t)(p[0]))
		   + (((uint32_t)(p[1])) << 8)
		   + (((uint32_t)(p[2])) << 16));
}

static inline void int3store(char *p, uint32_t x)
{
	*(p) = (char)(x);
	*(p + 1) = (char)(x >> 8);
	*(p + 2) = (char)(x >> 16);
}

#ifdef __cplusplus
extern "C"
{
#endif

// decode encoded length integer within *end, move pos forward
int decode_length_safe(unsigned long long *res, const char **pos, const char *end);

// decode encoded length string within *end, move pos forward
int decode_string(const char **str, unsigned long long *len,
				  const char **pos, const char *end);

#ifdef __cplusplus
}
#endif

#endif

