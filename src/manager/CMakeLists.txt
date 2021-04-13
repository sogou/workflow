cmake_minimum_required(VERSION 3.6)
project(manager)

set(SRC
	DNSCache.cc
	UpstreamManager.cc
	RouteManager.cc
	WFGlobal.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

