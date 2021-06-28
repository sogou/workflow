cmake_minimum_required(VERSION 3.6)
project(protocol)

set(SRC
	dns_parser.c
	http_parser.c
	redis_parser.c
	mysql_stream.c
	mysql_parser.c
	mysql_byteorder.c
	websocket_parser.c
	DnsMessage.cc
	DnsUtil.cc
	MySQLMessage.cc
	MySQLResult.cc
	HttpMessage.cc
	RedisMessage.cc
	WebSocketMessage.cc
	HttpUtil.cc
	SSLWrapper.cc
)

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
	set_property(SOURCE KafkaDataTypes.cc APPEND PROPERTY COMPILE_OPTIONS "-fno-rtti")
	set_property(SOURCE KafkaResult.cc APPEND PROPERTY COMPILE_OPTIONS "-fno-rtti")
endif ()

