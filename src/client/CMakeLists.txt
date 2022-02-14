cmake_minimum_required(VERSION 3.6)
project(client)

set(SRC
	WFMySQLConnection.cc
	WFDnsClient.cc
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
		WFKafkaClient.cc
	)
	add_library("client_kafka" OBJECT ${SRC})
	if (WIN32)
		target_compile_definitions(
			"client_kafka" PRIVATE
			strdup=_strdup
			strcasecmp=_stricmp
			strncasecmp=_strnicmp
		)
    else()
		set_property(SOURCE WFKafkaClient.cc APPEND PROPERTY COMPILE_OPTIONS "-fno-rtti")
	endif ()
endif ()