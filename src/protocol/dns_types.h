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

  Author: Liu Kai (liukaidx@sogou-inc.com)
*/

#ifndef _DNS_TYPES_H_
#define _DNS_TYPES_H_

enum
{
	DNS_TYPE_A = 1,
	DNS_TYPE_NS,
	DNS_TYPE_MD,
	DNS_TYPE_MF,
	DNS_TYPE_CNAME,
	DNS_TYPE_SOA = 6,
	DNS_TYPE_MB,
	DNS_TYPE_MG,
	DNS_TYPE_MR,
	DNS_TYPE_NULL,
	DNS_TYPE_WKS = 11,
	DNS_TYPE_PTR,
	DNS_TYPE_HINFO,
	DNS_TYPE_MINFO,
	DNS_TYPE_MX,
	DNS_TYPE_TXT = 16,

	DNS_TYPE_AAAA = 28,
	DNS_TYPE_SRV = 33,

	DNS_TYPE_AXFR = 252,
	DNS_TYPE_MAILB = 253,
	DNS_TYPE_MAILA = 254,
	DNS_TYPE_ALL = 255
};

enum
{
	DNS_CLASS_IN = 1,
	DNS_CLASS_CS,
	DNS_CLASS_CH,
	DNS_CLASS_HS,

	DNS_CLASS_ALL = 255
};

enum
{
	DNS_OPCODE_QUERY = 0,
	DNS_OPCODE_IQUERY,
	DNS_OPCODE_STATUS,
};

enum
{
	DNS_RCODE_NO_ERROR = 0,
	DNS_RCODE_FORMAT_ERROR,
	DNS_RCODE_SERVER_FAILURE,
	DNS_RCODE_NAME_ERROR,
	DNS_RCODE_NOT_IMPLEMENTED,
	DNS_RCODE_REFUSED
};

enum
{
	DNS_ANSWER_SECTION = 1,
	DNS_AUTHORITY_SECTION = 2,
	DNS_ADDITIONAL_SECTION = 3,
};

#endif

