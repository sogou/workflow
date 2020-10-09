/* Copied from http://stackoverflow.com/a/17646775/1821055
 * with the following modifications:
 *   * remove test code
 *   * global hw/sw initialization to be called once per process
 *   * HW support is determined by configure's WITH_CRC32C_HW
 *   * Windows porting (no hardware support on Windows yet)
 *
 * FIXME:
 *   * Hardware support on Windows (MSVC assembler)
 *   * Hardware support on ARM
 */

/* crc32c.c -- compute CRC-32C using the Intel crc32 instruction
 * Copyright (C) 2013 Mark Adler
 * Version 1.1  1 Aug 2013  Mark Adler
 */

/*
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler
  madler@alumni.caltech.edu
 */

/* Use hardware CRC instruction on Intel SSE 4.2 processors.  This computes a
   CRC-32C, *not* the CRC-32 used by Ethernet and zip, gzip, etc.  A software
   version is provided as a fall-back, as well as for speed comparisons. */

/* Version history:
   1.0  10 Feb 2013  First version
   1.1   1 Aug 2013  Correct comments on why three crc instructions in parallel
 */


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * Provides portable endian-swapping macros/functions.
 *
 *   be64toh()
 *   htobe64()
 *   be32toh()
 *   htobe32()
 *   be16toh()
 *   htobe16()
 *   le64toh()
 */

#ifdef __FreeBSD__
  #include <sys/endian.h>
#elif defined __GLIBC__
  #include <endian.h>
 #ifndef be64toh
   /* Support older glibc (<2.9) which lack be64toh */
  #include <byteswap.h>
  #if __BYTE_ORDER == __BIG_ENDIAN
   #define be16toh(x) (x)
   #define be32toh(x) (x)
   #define be64toh(x) (x)
   #define le64toh(x) __bswap_64 (x)
   #define le32toh(x) __bswap_32 (x)
  #else
   #define be16toh(x) __bswap_16 (x)
   #define be32toh(x) __bswap_32 (x)
   #define be64toh(x) __bswap_64 (x)
   #define le64toh(x) (x)
   #define le32toh(x) (x)
  #endif
 #endif

#elif defined __CYGWIN__
 #include <endian.h>
#elif defined __BSD__
  #include <sys/endian.h>
#elif defined __sun
  #include <sys/byteorder.h>
  #include <sys/isa_defs.h>
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#ifdef _BIG_ENDIAN
#define __BYTE_ORDER __BIG_ENDIAN
#define be64toh(x) (x)
#define be32toh(x) (x)
#define be16toh(x) (x)
#define le16toh(x) ((uint16_t)BSWAP_16(x))
#define le32toh(x) BSWAP_32(x)
#define le64toh(x) BSWAP_64(x)
# else
#define __BYTE_ORDER __LITTLE_ENDIAN
#define be64toh(x) BSWAP_64(x)
#define be32toh(x) ntohl(x)
#define be16toh(x) ntohs(x)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#define htole16(x) (x)
#define htole64(x) (x)
#endif /* __sun */

#elif defined __APPLE__
  #include <machine/endian.h>
  #include <libkern/OSByteOrder.h>
#if __DARWIN_BYTE_ORDER == __DARWIN_BIG_ENDIAN
#define be64toh(x) (x)
#define be32toh(x) (x)
#define be16toh(x) (x)
#define le16toh(x) OSSwapInt16(x)
#define le32toh(x) OSSwapInt32(x)
#define le64toh(x) OSSwapInt64(x)
#else
#define be64toh(x) OSSwapInt64(x)
#define be32toh(x) OSSwapInt32(x)
#define be16toh(x) OSSwapInt16(x)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)
#endif

#elif defined(_WIN32)
#include <intrin.h>

#define be64toh(x) _byteswap_uint64(x)
#define be32toh(x) _byteswap_ulong(x)
#define be16toh(x) _byteswap_ushort(x)
#define le16toh(x) (x)
#define le32toh(x) (x)
#define le64toh(x) (x)

#elif defined _AIX      /* AIX is always big endian */
#define be64toh(x) (x)
#define be32toh(x) (x)
#define be16toh(x) (x)
#define le32toh(x)                              \
        ((((x) & 0xff) << 24) |                 \
         (((x) & 0xff00) << 8) |                \
         (((x) & 0xff0000) >> 8) |              \
         (((x) & 0xff000000) >> 24))
#define le64toh(x)                               \
        ((((x) & 0x00000000000000ffL) << 56) |   \
         (((x) & 0x000000000000ff00L) << 40) |   \
         (((x) & 0x0000000000ff0000L) << 24) |   \
         (((x) & 0x00000000ff000000L) << 8)  |   \
         (((x) & 0x000000ff00000000L) >> 8)  |   \
         (((x) & 0x0000ff0000000000L) >> 24) |   \
         (((x) & 0x00ff000000000000L) >> 40) |   \
         (((x) & 0xff00000000000000L) >> 56))
#else
 #include <endian.h>
#endif



/*
 * On Solaris, be64toh is a function, not a macro, so there's no need to error
 * if it's not defined.
 */
#if !defined(__sun) && !defined(be64toh)
#error Missing definition for be64toh
#endif

#ifndef be32toh
#define be32toh(x) ntohl(x)
#endif

#ifndef be16toh
#define be16toh(x) ntohs(x)
#endif

#ifndef htobe64
#define htobe64(x) be64toh(x)
#endif
#ifndef htobe32
#define htobe32(x) be32toh(x)
#endif
#ifndef htobe16
#define htobe16(x) be16toh(x)
#endif

#ifndef htole32
#define htole32(x) le32toh(x)
#endif


/* CRC-32C (iSCSI) polynomial in reversed bit order. */
#define POLY 0x82f63b78

/* Table for a quadword-at-a-time software crc. */
static uint32_t crc32c_table[8][256];

/* Construct table for software CRC-32C calculation. */
static void crc32c_init_sw(void)
{
    uint32_t n, crc, k;

    for (n = 0; n < 256; n++) {
        crc = n;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc32c_table[0][n] = crc;
    }
    for (n = 0; n < 256; n++) {
        crc = crc32c_table[0][n];
        for (k = 1; k < 8; k++) {
            crc = crc32c_table[0][crc & 0xff] ^ (crc >> 8);
            crc32c_table[k][n] = crc;
        }
    }
}

/* Table-driven software version as a fall-back.  This is about 15 times slower
   than using the hardware instructions.  This assumes little-endian integers,
   as is the case on Intel processors that the assembler code here is for. */
static uint32_t crc32c_sw(uint32_t crci, const void *buf, size_t len)
{
    const unsigned char *next = buf;
    uint64_t crc;

    crc = crci ^ 0xffffffff;
    while (len && ((uintptr_t)next & 7) != 0) {
        crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    while (len >= 8) {
        /* Alignment-safe */
        uint64_t ncopy;
        memcpy(&ncopy, next, sizeof(ncopy));
        crc ^= le64toh(ncopy);
        crc = crc32c_table[7][crc & 0xff] ^
              crc32c_table[6][(crc >> 8) & 0xff] ^
              crc32c_table[5][(crc >> 16) & 0xff] ^
              crc32c_table[4][(crc >> 24) & 0xff] ^
              crc32c_table[3][(crc >> 32) & 0xff] ^
              crc32c_table[2][(crc >> 40) & 0xff] ^
              crc32c_table[1][(crc >> 48) & 0xff] ^
              crc32c_table[0][crc >> 56];
        next += 8;
        len -= 8;
    }
    while (len) {
        crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    return (uint32_t)crc ^ 0xffffffff;
}


#if WITH_CRC32C_HW
static int sse42;  /* Cached SSE42 support */

/* Multiply a matrix times a vector over the Galois field of two elements,
   GF(2).  Each element is a bit in an unsigned integer.  mat must have at
   least as many entries as the power of two for most significant one bit in
   vec. */
static RD_INLINE uint32_t gf2_matrix_times(uint32_t *mat, uint32_t vec)
{
    uint32_t sum;

    sum = 0;
    while (vec) {
        if (vec & 1)
            sum ^= *mat;
        vec >>= 1;
        mat++;
    }
    return sum;
}

/* Multiply a matrix by itself over GF(2).  Both mat and square must have 32
   rows. */
static RD_INLINE void gf2_matrix_square(uint32_t *square, uint32_t *mat)
{
    int n;

    for (n = 0; n < 32; n++)
        square[n] = gf2_matrix_times(mat, mat[n]);
}

/* Construct an operator to apply len zeros to a crc.  len must be a power of
   two.  If len is not a power of two, then the result is the same as for the
   largest power of two less than len.  The result for len == 0 is the same as
   for len == 1.  A version of this routine could be easily written for any
   len, but that is not needed for this application. */
static void crc32c_zeros_op(uint32_t *even, size_t len)
{
    int n;
    uint32_t row;
    uint32_t odd[32];       /* odd-power-of-two zeros operator */

    /* put operator for one zero bit in odd */
    odd[0] = POLY;              /* CRC-32C polynomial */
    row = 1;
    for (n = 1; n < 32; n++) {
        odd[n] = row;
        row <<= 1;
    }

    /* put operator for two zero bits in even */
    gf2_matrix_square(even, odd);

    /* put operator for four zero bits in odd */
    gf2_matrix_square(odd, even);

    /* first square will put the operator for one zero byte (eight zero bits),
       in even -- next square puts operator for two zero bytes in odd, and so
       on, until len has been rotated down to zero */
    do {
        gf2_matrix_square(even, odd);
        len >>= 1;
        if (len == 0)
            return;
        gf2_matrix_square(odd, even);
        len >>= 1;
    } while (len);

    /* answer ended up in odd -- copy to even */
    for (n = 0; n < 32; n++)
        even[n] = odd[n];
}

/* Take a length and build four lookup tables for applying the zeros operator
   for that length, byte-by-byte on the operand. */
static void crc32c_zeros(uint32_t zeros[][256], size_t len)
{
    uint32_t n;
    uint32_t op[32];

    crc32c_zeros_op(op, len);
    for (n = 0; n < 256; n++) {
        zeros[0][n] = gf2_matrix_times(op, n);
        zeros[1][n] = gf2_matrix_times(op, n << 8);
        zeros[2][n] = gf2_matrix_times(op, n << 16);
        zeros[3][n] = gf2_matrix_times(op, n << 24);
    }
}

/* Apply the zeros operator table to crc. */
static RD_INLINE uint32_t crc32c_shift(uint32_t zeros[][256], uint32_t crc)
{
    return zeros[0][crc & 0xff] ^ zeros[1][(crc >> 8) & 0xff] ^
           zeros[2][(crc >> 16) & 0xff] ^ zeros[3][crc >> 24];
}

/* Block sizes for three-way parallel crc computation.  LONG and SHORT must
   both be powers of two.  The associated string constants must be set
   accordingly, for use in constructing the assembler instructions. */
#define LONG 8192
#define LONGx1 "8192"
#define LONGx2 "16384"
#define SHORT 256
#define SHORTx1 "256"
#define SHORTx2 "512"

/* Tables for hardware crc that shift a crc by LONG and SHORT zeros. */
static uint32_t crc32c_long[4][256];
static uint32_t crc32c_short[4][256];

/* Initialize tables for shifting crcs. */
static void crc32c_init_hw(void)
{
    crc32c_zeros(crc32c_long, LONG);
    crc32c_zeros(crc32c_short, SHORT);
}

/* Compute CRC-32C using the Intel hardware instruction. */
static uint32_t crc32c_hw(uint32_t crc, const void *buf, size_t len)
{
    const unsigned char *next = buf;
    const unsigned char *end;
    uint64_t crc0, crc1, crc2;      /* need to be 64 bits for crc32q */

    /* pre-process the crc */
    crc0 = crc ^ 0xffffffff;

    /* compute the crc for up to seven leading bytes to bring the data pointer
       to an eight-byte boundary */
    while (len && ((uintptr_t)next & 7) != 0) {
        __asm__("crc32b\t" "(%1), %0"
                : "=r"(crc0)
                : "r"(next), "0"(crc0));
        next++;
        len--;
    }

    /* compute the crc on sets of LONG*3 bytes, executing three independent crc
       instructions, each on LONG bytes -- this is optimized for the Nehalem,
       Westmere, Sandy Bridge, and Ivy Bridge architectures, which have a
       throughput of one crc per cycle, but a latency of three cycles */
    while (len >= LONG*3) {
        crc1 = 0;
        crc2 = 0;
        end = next + LONG;
        do {
            __asm__("crc32q\t" "(%3), %0\n\t"
                    "crc32q\t" LONGx1 "(%3), %1\n\t"
                    "crc32q\t" LONGx2 "(%3), %2"
                    : "=r"(crc0), "=r"(crc1), "=r"(crc2)
                    : "r"(next), "0"(crc0), "1"(crc1), "2"(crc2));
            next += 8;
        } while (next < end);
        crc0 = crc32c_shift(crc32c_long, crc0) ^ crc1;
        crc0 = crc32c_shift(crc32c_long, crc0) ^ crc2;
        next += LONG*2;
        len -= LONG*3;
    }

    /* do the same thing, but now on SHORT*3 blocks for the remaining data less
       than a LONG*3 block */
    while (len >= SHORT*3) {
        crc1 = 0;
        crc2 = 0;
        end = next + SHORT;
        do {
            __asm__("crc32q\t" "(%3), %0\n\t"
                    "crc32q\t" SHORTx1 "(%3), %1\n\t"
                    "crc32q\t" SHORTx2 "(%3), %2"
                    : "=r"(crc0), "=r"(crc1), "=r"(crc2)
                    : "r"(next), "0"(crc0), "1"(crc1), "2"(crc2));
            next += 8;
        } while (next < end);
        crc0 = crc32c_shift(crc32c_short, crc0) ^ crc1;
        crc0 = crc32c_shift(crc32c_short, crc0) ^ crc2;
        next += SHORT*2;
        len -= SHORT*3;
    }

    /* compute the crc on the remaining eight-byte units less than a SHORT*3
       block */
    end = next + (len - (len & 7));
    while (next < end) {
        __asm__("crc32q\t" "(%1), %0"
                : "=r"(crc0)
                : "r"(next), "0"(crc0));
        next += 8;
    }
    len &= 7;

    /* compute the crc for up to seven trailing bytes */
    while (len) {
        __asm__("crc32b\t" "(%1), %0"
                : "=r"(crc0)
                : "r"(next), "0"(crc0));
        next++;
        len--;
    }

    /* return a post-processed crc */
    return (uint32_t)crc0 ^ 0xffffffff;
}

/* Check for SSE 4.2.  SSE 4.2 was first supported in Nehalem processors
   introduced in November, 2008.  This does not check for the existence of the
   cpuid instruction itself, which was introduced on the 486SL in 1992, so this
   will fail on earlier x86 processors.  cpuid works on all Pentium and later
   processors. */
#define SSE42(have) \
    do { \
        uint32_t eax, ecx; \
        eax = 1; \
        __asm__("cpuid" \
                : "=c"(ecx) \
                : "a"(eax) \
                : "%ebx", "%edx"); \
        (have) = (ecx >> 20) & 1; \
    } while (0)

#endif /* WITH_CRC32C_HW */

/* Compute a CRC-32C.  If the crc32 instruction is available, use the hardware
   version.  Otherwise, use the software version. */
uint32_t crc32c(uint32_t crc, const void *buf, size_t len)
{
#if WITH_CRC32C_HW
        if (sse42)
                return crc32c_hw(crc, buf, len);
        else
#endif
                return crc32c_sw(crc, buf, len);
}






/**
 * @brief Populate shift tables once
 */
void crc32c_global_init (void) {
#if WITH_CRC32C_HW
        SSE42(sse42);
        if (sse42)
                crc32c_init_hw();
        else
#endif
                crc32c_init_sw();
}
