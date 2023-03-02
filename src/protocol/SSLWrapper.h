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

#ifndef _SSLWRAPPER_H_
#define _SSLWRAPPER_H_

#include <openssl/ssl.h>
#include "ProtocolMessage.h"

namespace protocol
{

class SSLHandshaker : public ProtocolMessage
{
public:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

protected:
	SSL *ssl;

public:
	SSLHandshaker(SSL *ssl)
	{
		this->ssl = ssl;
	}

public:
	SSLHandshaker(SSLHandshaker&& handshaker) = default;
	SSLHandshaker& operator = (SSLHandshaker&& handshaker) = default;
};

class SSLWrapper : public ProtocolWrapper
{
protected:
	virtual int encode(struct iovec vectors[], int max);
	virtual int append(const void *buf, size_t *size);

protected:
	virtual int feedback(const void *buf, size_t size);

protected:
	int append_message();

protected:
	SSL *ssl;

public:
	SSLWrapper(ProtocolMessage *msg, SSL *ssl) :
		ProtocolWrapper(msg)
	{
		this->ssl = ssl;
	}

public:
	SSLWrapper(SSLWrapper&& wrapper) = default;
	SSLWrapper& operator = (SSLWrapper&& wrapper) = default;
};

class ServerSSLWrapper : public SSLWrapper
{
protected:
	virtual int append(const void *buf, size_t *size);

public:
	ServerSSLWrapper(ProtocolMessage *msg, SSL *ssl) : SSLWrapper(msg, ssl)
	{
	}

public:
	ServerSSLWrapper(ServerSSLWrapper&& wrapper) = default;
	ServerSSLWrapper& operator = (ServerSSLWrapper&& wrapper) = default;
};

}

#endif

