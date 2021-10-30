cmake_minimum_required(VERSION 3.6)
project(protocol)

set(SRC
	dns_parser.c
	http_parser.c
	redis_parser.c
	mysql_stream.c
	mysql_parser.c
	mysql_byteorder.c
	MySQLMessage.cc
	MySQLResult.cc
	DnsMessage.cc
	DnsUtil.cc
	HttpMessage.cc
	RedisMessage.cc
	HttpUtil.cc
	SSLWrapper.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})
if (WIN32)
	target_compile_definitions(
		${PROJECT_NAME} PRIVATE
		strdup=_strdup
		strcasecmp=_stricmp
		strncasecmp=_strnicmp
	)
endif ()

