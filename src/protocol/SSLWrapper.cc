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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "SSLWrapper.h"

namespace protocol
{

int SSLHandshaker::encode(struct iovec vectors[], int max)
{
	BIO *wbio = SSL_get_wbio(this->ssl);
	char *ptr;
	long len;
	int ret;

	if (BIO_reset(wbio) <= 0)
		return -1;

	ret = SSL_do_handshake(this->ssl);
	if (ret <= 0)
	{
		ret = SSL_get_error(this->ssl, ret);
		if (ret != SSL_ERROR_WANT_READ)
		{
			if (ret != SSL_ERROR_SYSCALL)
				errno = -ret;

			return -1;
		}
	}

	len = BIO_get_mem_data(wbio, &ptr);
	if (len > 0)
	{
		vectors[0].iov_base = ptr;
		vectors[0].iov_len = len;
		return 1;
	}
	else if (len == 0)
		return 0;
	else
		return -1;
}

int SSLHandshaker::append(const void *buf, size_t *size)
{
	BIO *rbio = SSL_get_rbio(this->ssl);
	BIO *wbio = SSL_get_wbio(this->ssl);
	char *ptr;
	long len;
	int ret;

	if (BIO_reset(wbio) <= 0)
		return -1;

	ret = BIO_write(rbio, buf, *size);
	if (ret <= 0)
		return -1;

	*size = ret;
	ret = SSL_do_handshake(this->ssl);
	if (ret <= 0)
	{
		ret = SSL_get_error(this->ssl, ret);
		if (ret != SSL_ERROR_WANT_READ)
		{
			if (ret != SSL_ERROR_SYSCALL)
				errno = -ret;

			return -1;
		}

		ret = 0;
	}

	len = BIO_get_mem_data(wbio, &ptr);
	if (len >= 0)
	{
		long n = this->feedback(ptr, len);

		if (n == len)
			return ret;

		if (n >= 0)
			errno = EAGAIN;
	}

	return -1;
}

int SSLWrapper::encode(struct iovec vectors[], int max)
{
	BIO *wbio = SSL_get_wbio(this->ssl);
	struct iovec *iov;
	char *ptr;
	long len;
	int ret;

	if (BIO_reset(wbio) <= 0)
		return -1;

	ret = this->msg->encode(vectors, max);
	if ((unsigned int)ret > (unsigned int)max)
		return ret;

	max = ret;
	for (iov = vectors; iov < vectors + max; iov++)
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

	len = BIO_get_mem_data(wbio, &ptr);
	if (len > 0)
	{
		vectors[0].iov_base = ptr;
		vectors[0].iov_len = len;
		return 1;
	}
	else if (len == 0)
		return 0;
	else
		return -1;
}

#define BUFSIZE		8192

int SSLWrapper::append(const void *buf, size_t *size)
{
	BIO *rbio = SSL_get_rbio(this->ssl);
	char rbuf[BUFSIZE];
	size_t nleft;
	size_t n;
	int ret;

	ret = BIO_write(rbio, buf, *size);
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

