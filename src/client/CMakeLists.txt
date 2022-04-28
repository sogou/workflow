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

if (NOT CONSUL STREQUAL "n")
	set(SRC
		${SRC}
		WFConsulClient.cc
	)
endif ()

add_library(${PROJECT_NAME} OBJECT ${SRC})

if (KAFKA STREQUAL "y")
	set(SRC
		WFKafkaClient.cc
	)
	add_library("client_kafka" OBJECT ${SRC})
endif ()

