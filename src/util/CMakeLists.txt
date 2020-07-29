cmake_minimum_required(VERSION 3.6)
project(util)

set(SRC
	EncodeStream.cc
	StringUtil.cc
	URIParser.cc
	MD5Util.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

