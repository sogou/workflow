cmake_minimum_required(VERSION 3.6)
project(factory)

set(SRC
	WFGraphTask.cc
	DnsTaskImpl.cc
	HttpTaskImpl.cc
	RedisTaskImpl.cc
	MySQLTaskImpl.cc
	WFTaskFactory.cc
	Workflow.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

if (KAFKA STREQUAL "y")
	set(SRC
		KafkaTaskImpl.cc
	)
	add_library("factory_kafka" OBJECT ${SRC})
	set_property(SOURCE KafkaTaskImpl.cc APPEND PROPERTY COMPILE_OPTIONS "-fno-rtti")
endif ()

