cmake_minimum_required(VERSION 3.6)
project(nameservice)

set(SRC
	WFNameService.cc
	WFDnsResolver.cc
	WFServiceGovernance.cc
	UpstreamPolicies.cc
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

