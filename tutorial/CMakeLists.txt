cmake_minimum_required(VERSION 3.6)

set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "build type")

project(tutorial
		LANGUAGES C CXX
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

if(ANDROID)
	link_directories(${OPENSSL_LINK_DIR})
else()
	find_library(LIBRT rt)
	find_package(OpenSSL REQUIRED)
endif()
find_package(workflow REQUIRED CONFIG HINTS ..)
include_directories(${OPENSSL_INCLUDE_DIR} ${WORKFLOW_INCLUDE_DIR})
link_directories(${WORKFLOW_LIB_DIR})

if (KAFKA STREQUAL "y")
	find_path(SNAPPY_INCLUDE_PATH NAMES snappy.h)
	include_directories(${SNAPPY_INCLUDE_PATH})
endif ()

if (WIN32)
		set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   /MP /wd4200")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /wd4200 /std:c++14")
else ()
		set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wall -fPIC -pipe -std=gnu90")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pipe -std=c++11 -fno-exceptions")
endif ()

set(TUTORIAL_LIST
	tutorial-00-helloworld
	tutorial-01-wget
	tutorial-04-http_echo_server
	tutorial-05-http_proxy
	tutorial-06-parallel_wget
	tutorial-07-sort_task
	tutorial-08-matrix_multiply
	tutorial-09-http_file_server
	tutorial-11-graph_task
	tutorial-15-name_service
	tutorial-20-reducer
)

if (APPLE)
	set(WORKFLOW_LIB workflow pthread OpenSSL::SSL OpenSSL::Crypto)
elseif (ANDROID)
	set(WORKFLOW_LIB workflow ssl crypto c)
else ()
	set(WORKFLOW_LIB workflow pthread OpenSSL::SSL OpenSSL::Crypto ${LIBRT})
endif ()

foreach(src ${TUTORIAL_LIST})
	string(REPLACE "-" ";" arr ${src})
	list(GET arr -1 bin_name)
	add_executable(${bin_name} ${src}.cc)
	target_link_libraries(${bin_name} ${WORKFLOW_LIB})
endforeach()

if (NOT REDIS STREQUAL "n")
set(TUTORIAL_LIST
	tutorial-02-redis_cli
	tutorial-03-wget_to_redis
)
foreach(src ${TUTORIAL_LIST})
	string(REPLACE "-" ";" arr ${src})
	list(GET arr -1 bin_name)
	add_executable(${bin_name} ${src}.cc)
	target_link_libraries(${bin_name} ${WORKFLOW_LIB})
endforeach()
endif()

if (NOT MYSQL STREQUAL "n")
set(TUTORIAL_LIST
	tutorial-12-mysql_cli
)
foreach(src ${TUTORIAL_LIST})
	string(REPLACE "-" ";" arr ${src})
	list(GET arr -1 bin_name)
	add_executable(${bin_name} ${src}.cc)
	target_link_libraries(${bin_name} ${WORKFLOW_LIB})
endforeach()
endif()

if (KAFKA STREQUAL "y")
	add_executable("kafka_cli" "tutorial-13-kafka_cli.cc")
	target_link_libraries("kafka_cli" wfkafka ${WORKFLOW_LIB} z snappy lz4 zstd)
endif ()

set(DIR10 tutorial-10-user_defined_protocol)
add_executable(server ${DIR10}/server.cc ${DIR10}/message.cc)
add_executable(client ${DIR10}/client.cc ${DIR10}/message.cc)
target_link_libraries(server ${WORKFLOW_LIB})
target_link_libraries(client ${WORKFLOW_LIB})

set_target_properties(server PROPERTIES
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/${DIR10})
set_target_properties(client PROPERTIES
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/${DIR10})
