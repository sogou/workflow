cmake_minimum_required(VERSION 3.6)
project(factory)

set(SRC
	WFResourcePool.cc
	WFGraphTask.cc
	HttpTaskImpl.cc
	RedisTaskImpl.cc
	MySQLTaskImpl.cc
	DnsTaskImpl.cc
	WFTaskFactory.cc
	Workflow.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})
if (WIN32)
	target_compile_definitions(
		${PROJECT_NAME} PRIVATE
		strdup=_strdup
		strcasecmp=_stricmp
		strncasecmp=_strnicmp
	)
endif ()

if (KAFKA STREQUAL "y")
	set(SRC
		KafkaTaskImpl.cc
	)
	add_library("factory_kafka" OBJECT ${SRC})
	if(WIN32)
		target_compile_definitions(
			"factory_kafka" PRIVATE
			strdup=_strdup
			strcasecmp=_stricmp
			strncasecmp=_strnicmp
		)
	else()
		set_property(SOURCE KafkaTaskImpl.cc APPEND PROPERTY COMPILE_OPTIONS "-fno-rtti")
	endif()
endif ()