cmake_minimum_required(VERSION 3.6)
project(client)

set(SRC
	WFDnsClient.cc
	WFMySQLConnection.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

if (KAFKA STREQUAL "y")
	set(SRC
		WFKafkaClient.cc
	)
	add_library("client_kafka" OBJECT ${SRC})
endif ()
