cmake_minimum_required(VERSION 3.6)
project(protocol)

set(SRC
	dns_parser.c
	http_parser.c
	redis_parser.c
	mysql_stream.c
	mysql_parser.c
	mysql_byteorder.c
<<<<<<< HEAD
	websocket_parser.c
=======
	DnsMessage.cc
	DnsUtil.cc
>>>>>>> 0465a939fa66b870e2fdddba73510f5d298385b4
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
endif ()

