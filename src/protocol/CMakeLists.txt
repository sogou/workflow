cmake_minimum_required(VERSION 3.6)
project(protocol)

set(SRC
	http_parser.c
	redis_parser.c
	mysql_stream.c
	mysql_parser.c
	mysql_byteorder.c
	MySQLMessage.cc
	MySQLResult.cc
	HttpMessage.cc
	RedisMessage.cc
	HttpUtil.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

