/*
  ISC License

  Copyright (c) 2023, Antonio SJ Musumeci <trapexit@spawn.link>

  Permission to use, copy, modify, and/or distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#ifndef CRC32C_H_INCLUDED
#define CRC32C_H_INCLUDED

typedef unsigned int crc32c_t;

#ifdef __cplusplus
extern "C"
{
#endif

crc32c_t crc32c_start(void);
crc32c_t crc32c_continue(const void     *buf,
                         const crc32c_t  len,
                         const crc32c_t  crc);
crc32c_t crc32c_finish(const crc32c_t crc);

crc32c_t crc32c(const void *buf, crc32c_t len);

#ifdef __cplusplus
}
#endif

#endif
