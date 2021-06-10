cmake_minimum_required(VERSION 3.6)
project(manager)

set(SRC
	DnsCache.cc
	UpstreamManager.cc
	RouteManager.cc
	WFCondition.cc
	WFGlobal.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

