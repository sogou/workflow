cmake_minimum_required(VERSION 3.6)
project(nameservice)

set(SRC
	WFNameService.cc
	WFDNSResolver.cc
	ServiceGovernance.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

