cmake_minimum_required(VERSION 3.6)
project(manager)

set(SRC
	DnsCache.cc
	UpstreamManager.cc
	RouteManager.cc
	WFSemaphore.cc
	WFGlobal.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

