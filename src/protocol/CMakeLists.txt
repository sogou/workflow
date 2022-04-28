cmake_minimum_required(VERSION 3.6)
project(protocol)

set(SRC
	PackageWrapper.cc
	SSLWrapper.cc
	dns_parser.c
	DnsMessage.cc
	DnsUtil.cc
	http_parser.c
	HttpMessage.cc
	HttpUtil.cc
)

if (NOT MYSQL STREQUAL "n")
	set(SRC
		${SRC}
		mysql_stream.c
		mysql_parser.c
		mysql_byteorder.c
		MySQLMessage.cc
		MySQLResult.cc
		MySQLUtil.cc
	)
endif ()

if (NOT REDIS STREQUAL "n")
	set(SRC
		${SRC}
		redis_parser.c
		RedisMessage.cc
	)
endif ()

add_library(${PROJECT_NAME} OBJECT ${SRC})

if (KAFKA STREQUAL "y")
	set(SRC
		kafka_parser.c
		KafkaMessage.cc
		KafkaDataTypes.cc
		KafkaResult.cc
	)
	add_library("protocol_kafka" OBJECT ${SRC})
	set_property(SOURCE KafkaMessage.cc APPEND PROPERTY COMPILE_OPTIONS "-fno-rtti")
endif ()
