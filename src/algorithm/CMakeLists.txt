cmake_minimum_required(VERSION 3.6)
project(algorithm)

set(SRC
	DnsRoutine.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

