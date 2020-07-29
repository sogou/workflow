cmake_minimum_required(VERSION 3.6)
project(algorithm)

set(SRC
	DNSRoutine.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

