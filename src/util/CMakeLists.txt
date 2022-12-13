cmake_minimum_required(VERSION 3.6)
project(util)

set(SRC
	json_parser.c
	EncodeStream.cc
	StringUtil.cc
	URIParser.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

if (KAFKA STREQUAL "y")
	set(SRC
		crc32c.c
	)
	add_library("util_kafka" OBJECT ${SRC})
endif ()
