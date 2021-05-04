/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#include <errno.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "SSLWrapper.h"

namespace protocol
{

int SSLWrapper::encode(struct iovec vectors[], int iovcnt)
{
	BIO *bio = SSL_get_wbio(this->ssl);
	struct iovec *iov;
	void *buf;
	int ret;

	ret = this->msg->encode(vectors, iovcnt);
	if ((unsigned int)ret > (unsigned int)iovcnt)
		return ret;

	for (iov = vectors; iov < vectors + ret; iov++)
	{
		if (iov->iov_len > 0)
		{
			ret = SSL_write(this->ssl, iov->iov_base, iov->iov_len);
			if (ret <= 0)
			{
				ret = SSL_get_error(this->ssl, ret);
				if (ret != SSL_ERROR_SYSCALL)
					errno = -ret;

				return -1;
			}
		}
	}

	ret = BIO_pending(bio);
	if (ret <= 0)
		return ret;

	buf = malloc(ret);
	if (buf)
	{
		ret = BIO_read(bio, buf, ret);
		if (ret > 0)
		{
			free(this->buf);
			this->buf = buf;
			vectors[0].iov_base = buf;
			vectors[0].iov_len = ret;
			return 1;
		}

		free(buf);
	}

	return -1;
}

#define BUFSIZE		8192

int SSLWrapper::append(const void *buf, size_t *size)
{
	BIO *bio = SSL_get_rbio(this->ssl);
	char rbuf[BUFSIZE];
	size_t nleft;
	size_t n;
	int ret;

	ret = BIO_write(bio, buf, *size);
	if (ret <= 0)
		return -1;

	*size = ret;
	while ((ret = SSL_read(this->ssl, rbuf, BUFSIZE)) > 0)
	{
		buf = rbuf;
		nleft = ret;
		do
		{
			n = nleft;
			ret = this->msg->append(buf, &n);
			if (ret == 0)
			{
				buf = (char *)buf + n;
				nleft -= n;
			}
			else
				return ret;

		} while (nleft > 0);
	}

	if (ret < 0)
	{
		ret = SSL_get_error(this->ssl, ret);
		if (ret != SSL_ERROR_WANT_READ)
		{
			if (ret != SSL_ERROR_SYSCALL)
				errno = -ret;

			return -1;
		}
	}

	return 0;
}

}

