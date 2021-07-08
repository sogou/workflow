cmake_minimum_required(VERSION 3.6)
project(nameservice)

set(SRC
	WFNameService.cc
	WFDnsResolver.cc
)

if (NOT UPSTREAM STREQUAL "n")
	set(SRC
		${SRC}
		WFServiceGovernance.cc
		UpstreamPolicies.cc
	)
endif ()

add_library(${PROJECT_NAME} OBJECT ${SRC})
