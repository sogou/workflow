cmake_minimum_required(VERSION 3.6)
project(manager)

set(SRC
	DnsCache.cc
	UpstreamManager.cc
	RouteManager.cc
	WFGlobal.cc
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

