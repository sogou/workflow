cmake_minimum_required(VERSION 3.6)
project(factory)

set(SRC
	HttpTaskImpl.cc
	RedisTaskImpl.cc
	MySQLTaskImpl.cc
	WFTaskFactory.cc
	Workflow.cc
)

if(KAFKA STREQUAL "y")
	set(SRC
		${SRC}
		KafkaTaskImpl.cc
	)
endif()

add_library(${PROJECT_NAME} OBJECT ${SRC})

