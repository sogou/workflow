cmake_minimum_required(VERSION 3.6)
project(kernel)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
	set(IOSERVICE_FILE IOService_linux.cc)
elseif (UNIX)
	set(IOSERVICE_FILE IOService_thread.cc)
else ()
	message(FATAL_ERROR "IOService unsupported.")
endif ()

set(SRC
	${IOSERVICE_FILE}
	mpoller.c
	poller.c
	rbtree.c
	msgqueue.c
	thrdpool.c
	CommRequest.cc
	CommScheduler.cc
	Communicator.cc
	Executor.cc
	SubTask.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})

