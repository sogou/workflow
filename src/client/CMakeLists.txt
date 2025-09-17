cmake_minimum_required(VERSION 3.6)
project(client)

set(SRC
	WFMySQLConnection.cc
	WFDnsClient.cc
	WFHttpChunkedClient.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})
if (WIN32)
	if (MINGW)
		target_compile_definitions(
			${PROJECT_NAME} PRIVATE
		)
	else ()
		target_compile_definitions(
			${PROJECT_NAME} PRIVATE
			strdup=_strdup
			strcasecmp=_stricmp
			strncasecmp=_strnicmp
		)
	endif ()
endif ()

if (KAFKA STREQUAL "y")
	set(SRC
		WFKafkaClient.cc
	)
	add_library("client_kafka" OBJECT ${SRC})
	if (WIN32)
		if (MINGW)
			target_compile_definitions(
				"client_kafka" PRIVATE
			)
		else ()
			target_compile_definitions(
				"client_kafka" PRIVATE
				strdup=_strdup
				strcasecmp=_stricmp
				strncasecmp=_strnicmp
			)
		endif ()
	endif ()
endif ()
