cmake_minimum_required(VERSION 3.6)
project(client)

set(SRC
	WFMySQLConnection.cc
)

if(KAFKA STREQUAL "y")
	set(SRC
		${SRC}
		WFKafkaClient.cc
	)
endif()

add_library(${PROJECT_NAME} OBJECT ${SRC})

