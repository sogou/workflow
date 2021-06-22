cmake_minimum_required(VERSION 3.6)
project(nameservice)

set(SRC
	WFNameService.cc
	WFDnsResolver.cc
)

if (UPSTREAM STREQUAL "y")
	set(SRC
		${SRC}
		WFServiceGovernance.cc
		UpstreamPolicies.cc
	)
endif ()

add_library(${PROJECT_NAME} OBJECT ${SRC})
