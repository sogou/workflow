cmake_minimum_required(VERSION 3.6)
project(util)

set(SRC
	EncodeStream.cc
	StringUtil.cc
	URIParser.cc
	MD5Util.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})
if (WIN32)
	target_compile_definitions(
		${PROJECT_NAME} PRIVATE
		strdup=_strdup
	)
endif ()

if (KAFKA STREQUAL "y")
	set(SRC
		crc32c.c
	)
	add_library("util_kafka" OBJECT ${SRC})
endif ()