cmake_minimum_required(VERSION 3.10)

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

find_library(WORKFLOW_LIB NAMES libworkflow.a workflow HINTS ${WORKFLOW_LIB_DIR})

if (KAFKA STREQUAL "y")
	find_library(WFKAFKA_LIB NAMES libwfkafka.a wfkafka HINTS ${WORKFLOW_LIB_DIR})
endif ()

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wall -fPIC -pipe -std=gnu90")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pipe -std=c++11 -fno-exceptions")
if (APPLE)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
endif()

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
	tutorial-17-dns_cli
	tutorial-19-dns_server
)

if (APPLE)
	set(LIB ${WORKFLOW_LIB} pthread OpenSSL::SSL OpenSSL::Crypto)
elseif (ANDROID)
	set(LIB ${WORKFLOW_LIB} ssl crypto c)
else ()
	set(LIB ${WORKFLOW_LIB} pthread OpenSSL::SSL OpenSSL::Crypto ${LIBRT})
endif ()

foreach(src ${TUTORIAL_LIST})
	string(REPLACE "-" ";" arr ${src})
	list(GET arr -1 bin_name)
	add_executable(${bin_name} ${src}.cc)
	target_link_libraries(${bin_name} ${LIB})
endforeach()

if (NOT REDIS STREQUAL "n")
set(TUTORIAL_LIST
	tutorial-02-redis_cli
	tutorial-03-wget_to_redis
	tutorial-18-redis_subscriber
)
foreach(src ${TUTORIAL_LIST})
	string(REPLACE "-" ";" arr ${src})
	list(GET arr -1 bin_name)
	add_executable(${bin_name} ${src}.cc)
	target_link_libraries(${bin_name} ${LIB})
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
	target_link_libraries(${bin_name} ${LIB})
endforeach()
endif()

if (NOT CONSUL STREQUAL "n")
set(TUTORIAL_LIST
	tutorial-14-consul_cli
)
foreach(src ${TUTORIAL_LIST})
	string(REPLACE "-" ";" arr ${src})
	list(GET arr -1 bin_name)
	add_executable(${bin_name} ${src}.cc)
	target_link_libraries(${bin_name} ${LIB})
endforeach()
endif()

if (KAFKA STREQUAL "y")
	add_executable("kafka_cli" "tutorial-13-kafka_cli.cc")
	find_package(ZLIB REQUIRED)
	find_path(SNAPPY_INCLUDE_PATH NAMES snappy.h)
	find_library(SNAPPY_LIB NAMES snappy)
	if ((NOT SNAPPY_INCLUDE_PATH) OR (NOT SNAPPY_LIB))
		message(FATAL_ERROR "Fail to find snappy with KAFKA=y")
	endif ()
	include_directories(${SNAPPY_INCLUDE_PATH})

	find_path(ZSTD_INCLUDE_PATH NAMES zstd.h)
	find_library(ZSTD_LIB NAMES zstd)
	if ((NOT ZSTD_INCLUDE_PATH) OR (NOT ZSTD_LIB))
		message(FATAL_ERROR "Fail to find zstd with KAFKA=y")
	endif ()
	include_directories(${ZSTD_INCLUDE_PATH})

	find_path(LZ4_INCLUDE_PATH NAMES lz4.h)
	find_library(LZ4_LIB NAMES lz4)
	if ((NOT LZ4_INCLUDE_PATH) OR (NOT LZ4_LIB))
		message(FATAL_ERROR "Fail to find lz4 with KAFKA=y")
	endif ()
	include_directories(${LZ4_INCLUDE_PATH})
	target_link_libraries("kafka_cli" ${WFKAFKA_LIB} ${LIB} ZLIB::ZLIB ${SNAPPY_LIB} ${LZ4_LIB} ${ZSTD_LIB})
endif ()

set(DIR10 tutorial-10-user_defined_protocol)
add_executable(server ${DIR10}/server.cc ${DIR10}/message.cc)
add_executable(client ${DIR10}/client.cc ${DIR10}/message.cc)
add_executable(server-uds ${DIR10}/server-uds.cc ${DIR10}/message.cc)
add_executable(client-uds ${DIR10}/client-uds.cc ${DIR10}/message.cc)
target_link_libraries(server ${LIB})
target_link_libraries(client ${LIB})
target_link_libraries(server-uds ${LIB})
target_link_libraries(client-uds ${LIB})

set_target_properties(server PROPERTIES
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/${DIR10})
set_target_properties(client PROPERTIES
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/${DIR10})
set_target_properties(server-uds PROPERTIES
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/${DIR10})
set_target_properties(client-uds PROPERTIES
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/${DIR10})

set(DIR16 tutorial-16-graceful_restart)
add_executable(bootstrap ${DIR16}/bootstrap.c)
add_executable(bootstrap_server ${DIR16}/server.cc)
target_link_libraries(bootstrap_server ${LIB})

set_target_properties(bootstrap PROPERTIES
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/${DIR16})
set_target_properties(bootstrap_server PROPERTIES OUTPUT_NAME "server"
	RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/${DIR16})
