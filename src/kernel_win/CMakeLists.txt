cmake_minimum_required(VERSION 3.6)
project(kernel)

set(SRC
	rbtree.c
	thrdpool.cc
	CommRequest.cc
	CommScheduler.cc
	Communicator.cc
	Executor.cc
	SubTask.cc
	WinPoller.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})
if (WIN32)
	target_compile_definitions(
		${PROJECT_NAME} PRIVATE
		strdup=_strdup
		strcasecmp=_stricmp
		strncasecmp=_strnicmp
	)
endif ()

