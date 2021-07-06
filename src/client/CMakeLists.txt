cmake_minimum_required(VERSION 3.6)
project(client)

set(SRC
	WFDnsClient.cc
)

if (NOT MYSQL STREQUAL "n")
	set(SRC
		${SRC}
		WFMySQLConnection.cc
	)
endif ()

add_library(${PROJECT_NAME} OBJECT ${SRC})

if (KAFKA STREQUAL "y")
	set(SRC
		WFKafkaClient.cc
	)
	add_library("client_kafka" OBJECT ${SRC})
	set_property(SOURCE WFKafkaClient.cc APPEND PROPERTY COMPILE_OPTIONS "-fno-rtti")
endif ()
