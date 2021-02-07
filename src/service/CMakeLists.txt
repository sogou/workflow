cmake_minimum_required(VERSION 3.6)
project(service)

set(SRC
	ServiceGovernance.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

