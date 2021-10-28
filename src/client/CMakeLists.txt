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

