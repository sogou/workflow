cmake_minimum_required(VERSION 3.6)
project(server)

set(SRC
	WFServer.cc
	WFMySQLServer.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

