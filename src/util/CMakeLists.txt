cmake_minimum_required(VERSION 3.6)
project(util)

set(SRC
	EncodeStream.cc
	StringUtil.cc
	URIParser.cc
	MD5Util.cc
)

if (KAFKA STREQUAL "y")
	set(SRC
		${SRC}
		crc32c.c
	)
endif()

add_library(${PROJECT_NAME} OBJECT ${SRC})

