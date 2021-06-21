cmake_minimum_required(VERSION 3.6)
project(nameservice)

set(SRC
	WFNameService.cc
	WFDnsResolver.cc
	WFServiceGovernance.cc
	UpstreamPolicies.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

